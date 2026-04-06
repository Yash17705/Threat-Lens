/**
 * index.js — NIDS Node.js/Express Backend
 *
 * Receives packet feature data, forwards to ML service,
 * stores results (MongoDB or in-memory), serves dashboard API.
 */

require("dotenv").config();
const express  = require("express");
const cors     = require("cors");
const morgan   = require("morgan");
const axios    = require("axios");
const mongoose = require("mongoose");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const { v4: uuidv4 } = require("uuid");

// ── Config ────────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT           || 3001;
const ML_URL     = process.env.ML_SERVICE_URL || "http://localhost:8000";
const MONGO_URI  = process.env.MONGODB_URI    || "mongodb://localhost:27017/nids";

const app = express();
app.use(cors());
app.use(express.json({ limit: "5mb" }));
app.use(morgan("tiny"));

// ── Demo simulator process ───────────────────────────────────────────────────
const ROOT_DIR = path.resolve(__dirname, "..");
const demoState = {
  process: null,
  startedAt: null,
  config: null,
  lastExitCode: null,
  lastError: null,
};

function getPythonExecutable() {
  const candidates = [
    path.join(ROOT_DIR, ".venv", "bin", "python"),
    process.env.PYTHON_BIN,
    "python3",
    "python",
  ].filter(Boolean);

  const localPython = candidates.find((candidate) => candidate.includes(path.sep) && fs.existsSync(candidate));
  return localPython || candidates.find((candidate) => !candidate.includes(path.sep)) || "python3";
}

function getDemoStatus() {
  return {
    running: !!demoState.process,
    started_at: demoState.startedAt,
    config: demoState.config,
    last_exit_code: demoState.lastExitCode,
    last_error: demoState.lastError,
  };
}

function stopDemo() {
  if (!demoState.process) return false;
  demoState.process.kill("SIGTERM");
  return true;
}

function startDemo({ duration = 90, rate = 2, attacks = 0.2, clearExisting = true } = {}) {
  if (demoState.process) {
    const err = new Error("Demo is already running");
    err.status = 409;
    throw err;
  }

  if (clearExisting) {
    memStore.clear();
    Object.assign(stats, {
      total: 0, attacks: 0, normal: 0,
      byCategory: { dos:0, probe:0, r2l:0, u2r:0, anomaly:0 },
      history: [],
    });
  }

  if (usingMongo && TrafficLog) {
    TrafficLog.deleteMany({}).catch(() => {});
  }

  const pythonBin = getPythonExecutable();
  const scriptPath = path.join(ROOT_DIR, "packet-capture", "capture.py");
  const args = [
    scriptPath,
    "--simulate",
    "--duration", String(duration),
    "--rate", String(rate),
    "--attacks", String(attacks),
    "--backend", `http://localhost:${PORT}/api/analyze`,
  ];

  const child = spawn(pythonBin, args, {
    cwd: path.join(ROOT_DIR, "packet-capture"),
    stdio: ["ignore", "pipe", "pipe"],
  });

  demoState.process = child;
  demoState.startedAt = new Date().toISOString();
  demoState.config = { duration, rate, attacks, clearExisting };
  demoState.lastExitCode = null;
  demoState.lastError = null;

  child.stdout.on("data", (chunk) => process.stdout.write(`[demo] ${chunk}`));
  child.stderr.on("data", (chunk) => process.stderr.write(`[demo] ${chunk}`));
  child.on("error", (err) => {
    demoState.lastError = err.message;
  });
  child.on("close", (code) => {
    demoState.lastExitCode = code;
    demoState.process = null;
    demoState.startedAt = null;
  });
}

// ── MongoDB ───────────────────────────────────────────────────────────────────
let usingMongo = false;

const TrafficLogSchema = new mongoose.Schema({
  id:              { type: String, default: () => uuidv4() },
  timestamp:       { type: Date,   default: Date.now, index: true },
  src_ip:          String,
  dst_ip:          String,
  src_port:        Number,
  dst_port:        Number,
  protocol:        String,
  packet_length:   Number,
  prediction:      String,
  is_attack:       Boolean,
  confidence:      Number,
  attack_category: String,
  model_used:      String,
  features:        mongoose.Schema.Types.Mixed,
});

let TrafficLog;

mongoose
  .connect(MONGO_URI, { serverSelectionTimeoutMS: 3000 })
  .then(() => {
    usingMongo = true;
    TrafficLog = mongoose.model("TrafficLog", TrafficLogSchema);
    console.log("✓ MongoDB connected");
  })
  .catch(() => {
    console.log("⚠  MongoDB unavailable — using in-memory store");
  });

// ── In-memory fallback ────────────────────────────────────────────────────────
const memStore = {
  logs:    [],
  maxSize: 5000,
  push(doc) {
    this.logs.unshift(doc);
    if (this.logs.length > this.maxSize) this.logs.pop();
  },
  find({ limit = 100, attackOnly = false } = {}) {
    let result = this.logs;
    if (attackOnly) result = result.filter(l => l.is_attack);
    return result.slice(0, limit);
  },
  count()       { return this.logs.length; },
  attackCount() { return this.logs.filter(l => l.is_attack).length; },
  clear()       { this.logs = []; },
};

// ── Stats tracking ────────────────────────────────────────────────────────────
const stats = {
  total:          0,
  attacks:        0,
  normal:         0,
  startTime:      Date.now(),
  byCategory:     { dos: 0, probe: 0, r2l: 0, u2r: 0, anomaly: 0 },
  history:        [],   // {time, total, attacks} every 60s
  lastMinuteTotal: 0,
  lastMinuteAttacks: 0,
};

// Sample history every 60 seconds
setInterval(() => {
  stats.history.push({
    time:    new Date().toISOString(),
    total:   stats.total - (stats.history.length > 0 ? stats.history.reduce((a,b) => a + b.total, 0) : 0),
    attacks: stats.attacks - (stats.history.length > 0 ? stats.history.reduce((a,b) => a + b.attacks, 0) : 0),
    total_cumulative: stats.total,
    attacks_cumulative: stats.attacks,
  });
  if (stats.history.length > 30) stats.history.shift();
}, 60_000);

// ── Helper: store log ─────────────────────────────────────────────────────────
async function storeLog(doc) {
  if (usingMongo && TrafficLog) {
    try {
      await new TrafficLog(doc).save();
      return;
    } catch { /* fall through */ }
  }
  memStore.push(doc);
}

// ── ML Service proxy ──────────────────────────────────────────────────────────
async function callML(features) {
  try {
    const res = await axios.post(`${ML_URL}/predict`, features, { timeout: 5000 });
    return res.data;
  } catch (err) {
    // ML service unavailable — use simple rule fallback
    const { serror_rate = 0, srv_serror_rate = 0,
            diff_srv_rate = 0, same_srv_rate = 1,
            num_failed_logins = 0, is_guest_login = 0,
            root_shell = 0 } = features;

    let category = "normal";
    if (serror_rate > 0.8 || srv_serror_rate > 0.8)            category = "dos";
    else if (diff_srv_rate > 0.6 && same_srv_rate < 0.4)        category = "probe";
    else if (num_failed_logins > 3 || is_guest_login === 1)     category = "r2l";
    else if (root_shell === 1)                                   category = "u2r";

    const labels = { dos:"Neptune", probe:"Portsweep", r2l:"GuestPasswd", u2r:"BufferOverflow" };
    return {
      prediction:      labels[category] || "Normal",
      is_attack:       category !== "normal",
      confidence:      70,
      attack_category: category,
      model_used:      "Rule-Based (ML service offline)",
    };
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Routes
// ══════════════════════════════════════════════════════════════════════════════

// Health
app.get("/health", (_req, res) => res.json({ status: "ok", mongo: usingMongo }));

// ── POST /api/analyze — receive packet + classify ─────────────────────────────
app.post("/api/analyze", async (req, res) => {
  try {
    const packet = req.body;

    // Call ML service
    const result = await callML(packet);

    // Update stats
    stats.total++;
    if (result.is_attack) {
      stats.attacks++;
      const cat = result.attack_category;
      if (cat in stats.byCategory) stats.byCategory[cat]++;
    } else {
      stats.normal++;
    }

    // Build log document
    const log = {
      id:              uuidv4(),
      timestamp:       new Date(),
      src_ip:          packet.src_ip    || "0.0.0.0",
      dst_ip:          packet.dst_ip    || "0.0.0.0",
      src_port:        packet.src_port  || 0,
      dst_port:        packet.dst_port  || 0,
      protocol:        packet.protocol  || (packet.protocol_type === 0 ? "ICMP"
                                          : packet.protocol_type === 2 ? "UDP"
                                          : "TCP"),
      packet_length:   packet.packet_length || 0,
      prediction:      result.prediction,
      is_attack:       result.is_attack,
      confidence:      result.confidence,
      attack_category: result.attack_category,
      model_used:      result.model_used,
      features:        packet,
    };

    await storeLog(log);

    res.json({ success: true, result, log_id: log.id });
  } catch (err) {
    console.error("analyze error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/logs ─────────────────────────────────────────────────────────────
app.get("/api/logs", async (req, res) => {
  try {
    const limit      = Math.min(parseInt(req.query.limit) || 100, 500);
    const attackOnly = req.query.attack_only === "true";

    if (usingMongo && TrafficLog) {
      const query = attackOnly ? { is_attack: true } : {};
      const docs  = await TrafficLog.find(query)
        .sort({ timestamp: -1 })
        .limit(limit)
        .lean();
      return res.json({ logs: docs, total: docs.length, source: "mongodb" });
    }

    res.json({
      logs:   memStore.find({ limit, attackOnly }),
      total:  memStore.count(),
      source: "memory",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /api/logs ──────────────────────────────────────────────────────────
app.delete("/api/logs", async (req, res) => {
  try {
    if (usingMongo && TrafficLog) {
      await TrafficLog.deleteMany({});
    }
    memStore.clear();
    Object.assign(stats, {
      total: 0, attacks: 0, normal: 0,
      byCategory: { dos:0, probe:0, r2l:0, u2r:0, anomaly:0 },
      history: [],
    });
    res.json({ success: true, message: "All logs cleared" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/stats ────────────────────────────────────────────────────────────
app.get("/api/stats", (_req, res) => {
  const uptimeMs  = Date.now() - stats.startTime;
  const uptimeSec = Math.floor(uptimeMs / 1000);
  res.json({
    total_packets:  stats.total,
    attack_packets: stats.attacks,
    normal_packets: stats.normal,
    attack_rate:    stats.total > 0 ? +((stats.attacks / stats.total) * 100).toFixed(2) : 0,
    by_category:    stats.byCategory,
    uptime_seconds: uptimeSec,
    storage:        usingMongo ? "mongodb" : "memory",
  });
});

// ── GET /api/stats/history ────────────────────────────────────────────────────
app.get("/api/stats/history", (_req, res) => {
  res.json({ history: stats.history });
});

// ── Demo controls ────────────────────────────────────────────────────────────
app.get("/api/demo/status", (_req, res) => {
  res.json(getDemoStatus());
});

app.post("/api/demo/start", (req, res) => {
  try {
    const duration = Math.max(15, Math.min(Number(req.body.duration) || 90, 900));
    const rate = Math.max(0.5, Math.min(Number(req.body.rate) || 2, 20));
    const attacks = Math.max(0, Math.min(Number(req.body.attacks) || 0.2, 1));
    const clearExisting = req.body.clear_existing !== false;

    startDemo({ duration, rate, attacks, clearExisting });
    res.json({ success: true, status: getDemoStatus() });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.post("/api/demo/stop", (_req, res) => {
  const stopped = stopDemo();
  res.json({ success: stopped, status: getDemoStatus() });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🛡️  NIDS Backend running on http://localhost:${PORT}`);
  console.log(`   ML Service : ${ML_URL}`);
  console.log(`   Storage    : ${usingMongo ? "MongoDB" : "in-memory"}\n`);
});

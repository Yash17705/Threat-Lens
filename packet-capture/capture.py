"""
capture.py — NIDS Packet Capture Module

Two modes:
  --simulate  : Generate synthetic mixed normal/attack traffic (no root needed)
  (default)   : Live Scapy capture (requires root / admin)

Usage:
  python capture.py --simulate --duration 120
  sudo python capture.py --interface eth0
"""

import argparse
import random
import time
import socket
import struct
import requests
import threading
from datetime import datetime
from typing import Optional

BACKEND_URL = "http://localhost:3001/api/analyze"

# ── Common port list ──────────────────────────────────────────────────────────
COMMON_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443,
                445, 3306, 3389, 5432, 8080, 8443, 27017]

PROTOCOLS = ["TCP", "UDP", "ICMP"]

NORMAL_PROFILES = [
    {
        "name": "web",
        "protocol_type": 1,
        "service": (8, 15),
        "flag": (0, 3),
        "src_bytes": (120, 1800),
        "dst_bytes": (800, 12000),
        "count": (2, 18),
        "srv_count": (2, 18),
        "same_srv_rate": (0.88, 1.0),
        "diff_srv_rate": (0.0, 0.06),
        "dst_port": [80, 443, 8080, 8443],
    },
    {
        "name": "dns",
        "protocol_type": 2,
        "service": (1, 8),
        "flag": (0, 2),
        "src_bytes": (40, 220),
        "dst_bytes": (80, 600),
        "count": (1, 10),
        "srv_count": (1, 10),
        "same_srv_rate": (0.9, 1.0),
        "diff_srv_rate": (0.0, 0.04),
        "dst_port": [53],
    },
    {
        "name": "ssh",
        "protocol_type": 1,
        "service": (10, 20),
        "flag": (0, 4),
        "src_bytes": (80, 1200),
        "dst_bytes": (120, 3200),
        "count": (1, 8),
        "srv_count": (1, 8),
        "same_srv_rate": (0.92, 1.0),
        "diff_srv_rate": (0.0, 0.03),
        "dst_port": [22],
    },
    {
        "name": "icmp",
        "protocol_type": 0,
        "service": (0, 3),
        "flag": (0, 1),
        "src_bytes": (32, 140),
        "dst_bytes": (0, 80),
        "count": (1, 6),
        "srv_count": (1, 6),
        "same_srv_rate": (0.95, 1.0),
        "diff_srv_rate": (0.0, 0.02),
        "dst_port": [0],
    },
]

# ── Attack templates ──────────────────────────────────────────────────────────
ATTACK_TEMPLATES = {
    "neptune": {
        "category": "dos",
        "serror_rate": 0.99, "srv_serror_rate": 0.99,
        "count": 511, "same_srv_rate": 1.0, "src_bytes": 0,
        "dst_bytes": 0, "protocol_type": 1, "logged_in": 0,
        "_dst_port_choices": [80, 443],
    },
    "smurf": {
        "category": "dos",
        "serror_rate": 0.0, "count": 511, "src_bytes": 936,
        "dst_bytes": 0, "protocol_type": 0,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "_dst_port_choices": [0],
    },
    "portsweep": {
        "category": "probe",
        "diff_srv_rate": 0.81, "same_srv_rate": 0.07,
        "count": 200, "src_bytes": 0, "dst_bytes": 0,
        "protocol_type": 1, "serror_rate": 0.0,
        "srv_diff_host_rate": 0.78,
        "_dst_port_choices": [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389],
    },
    "ipsweep": {
        "category": "probe",
        "diff_srv_rate": 0.0, "same_srv_rate": 1.0,
        "count": 200, "src_bytes": 0, "dst_bytes": 0,
        "srv_diff_host_rate": 0.95, "protocol_type": 0,
        "_dst_port_choices": [0],
    },
    "guess_passwd": {
        "category": "r2l",
        "num_failed_logins": 5, "is_guest_login": 0,
        "logged_in": 0, "count": 5, "src_bytes": 200,
        "dst_bytes": 40, "protocol_type": 1,
        "service": 12, "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "_dst_port_choices": [21, 22, 23],
    },
    "buffer_overflow": {
        "category": "u2r",
        "root_shell": 1, "su_attempted": 1,
        "num_root": 1, "src_bytes": 1408, "dst_bytes": 120,
        "protocol_type": 1, "hot": 2,
        "num_compromised": 1, "num_shells": 1,
        "service": 14, "_dst_port_choices": [22, 23],
    },
}

ATTACK_CATEGORY_SEQUENCE = ["dos", "probe", "r2l", "u2r"]

# ── Random IP generators ──────────────────────────────────────────────────────
def rand_private_ip():
    prefix = random.choice(["192.168.1.", "10.0.0.", "172.16.0."])
    return prefix + str(random.randint(1, 254))

def rand_public_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

# ── Build normal packet features ──────────────────────────────────────────────
def rand_range(low: int, high: int) -> int:
    return random.randint(low, high)


def rand_float(low: float, high: float) -> float:
    return round(random.uniform(low, high), 2)


def normal_packet():
    profile = random.choices(
        NORMAL_PROFILES,
        weights=[0.55, 0.2, 0.15, 0.1],
        k=1,
    )[0]

    count = rand_range(*profile["count"])
    srv_count = min(count + random.randint(-1, 1), profile["srv_count"][1])
    srv_count = max(profile["srv_count"][0], srv_count)
    same_srv_rate = rand_float(*profile["same_srv_rate"])
    diff_srv_rate = min(rand_float(*profile["diff_srv_rate"]), round(1.0 - same_srv_rate, 2))
    dst_host_count = rand_range(max(count, 8), 64)
    dst_host_srv_count = min(dst_host_count, rand_range(max(srv_count, 6), 48))
    packet_length = rand_range(60, 900)

    return {
        "duration":                    rand_range(0, 5),
        "protocol_type":               profile["protocol_type"],
        "service":                     rand_range(*profile["service"]),
        "flag":                        rand_range(*profile["flag"]),
        "src_bytes":                   rand_range(*profile["src_bytes"]),
        "dst_bytes":                   rand_range(*profile["dst_bytes"]),
        "land":                        0,
        "wrong_fragment":              0,
        "urgent":                      0,
        "hot":                         0 if random.random() < 0.95 else 1,
        "num_failed_logins":           0,
        "logged_in":                   1 if profile["name"] in {"web", "ssh"} and random.random() < 0.65 else 0,
        "num_compromised":             0,
        "root_shell":                  0,
        "su_attempted":                0,
        "num_root":                    0,
        "num_file_creations":          0 if random.random() < 0.9 else 1,
        "num_shells":                  0,
        "num_access_files":            0,
        "num_outbound_cmds":           0,
        "is_host_login":               0,
        "is_guest_login":              0,
        "count":                       count,
        "srv_count":                   srv_count,
        "serror_rate":                 rand_float(0.0, 0.02),
        "srv_serror_rate":             rand_float(0.0, 0.02),
        "rerror_rate":                 rand_float(0.0, 0.02),
        "srv_rerror_rate":             rand_float(0.0, 0.02),
        "same_srv_rate":               same_srv_rate,
        "diff_srv_rate":               diff_srv_rate,
        "srv_diff_host_rate":          rand_float(0.0, 0.03),
        "dst_host_count":              dst_host_count,
        "dst_host_srv_count":          dst_host_srv_count,
        "dst_host_same_srv_rate":      rand_float(0.9, 1.0),
        "dst_host_diff_srv_rate":      rand_float(0.0, 0.05),
        "dst_host_same_src_port_rate": rand_float(0.0, 0.12),
        "dst_host_srv_diff_host_rate": rand_float(0.0, 0.04),
        "dst_host_serror_rate":        rand_float(0.0, 0.02),
        "dst_host_srv_serror_rate":    rand_float(0.0, 0.02),
        "dst_host_rerror_rate":        rand_float(0.0, 0.02),
        "dst_host_srv_rerror_rate":    rand_float(0.0, 0.02),
        "_dst_port_choices":           profile["dst_port"],
        "_packet_length_hint":         packet_length,
    }


def attack_packet(template_name: str):
    base = normal_packet()
    base.update(ATTACK_TEMPLATES.get(template_name, {}))
    return base


def choose_attack_template(index: int) -> str:
    """Cycle categories so short simulations show all attack types."""
    category = ATTACK_CATEGORY_SEQUENCE[index % len(ATTACK_CATEGORY_SEQUENCE)]
    matches = [
        name for name, template in ATTACK_TEMPLATES.items()
        if template.get("category") == category
    ]
    return random.choice(matches or list(ATTACK_TEMPLATES.keys()))


def add_network_meta(features: dict) -> dict:
    """Attach IP/port/size metadata for display."""
    proto_map = {0: "ICMP", 1: "TCP", 2: "UDP"}
    dst_ports = features.pop("_dst_port_choices", COMMON_PORTS)
    packet_length = features.pop("_packet_length_hint", None)
    protocol_type = features.get("protocol_type", 1)

    features["src_ip"]        = rand_private_ip()
    features["dst_ip"]        = rand_private_ip()
    features["src_port"]      = 0 if protocol_type == 0 else random.randint(1024, 65535)
    features["dst_port"]      = random.choice(dst_ports)
    features["packet_length"] = packet_length or min(
        max(int((features.get("src_bytes", 0) + features.get("dst_bytes", 0)) / 12), 60),
        1500,
    )
    features["protocol"]      = proto_map.get(protocol_type, "TCP")
    return features


# ── Send to backend ───────────────────────────────────────────────────────────
def send_packet(features: dict, verbose: bool = True):
    try:
        r = requests.post(BACKEND_URL, json=features, timeout=3)
        if r.status_code == 200:
            res = r.json()
            result = res.get("result", {})
            ts = datetime.now().strftime("%H:%M:%S")
            label = result.get("prediction", "?")
            is_atk = result.get("is_attack", False)
            conf   = result.get("confidence", 0)
            tag    = "🔴 ATTACK" if is_atk else "🟢 normal"
            if verbose:
                print(f"  [{ts}] {features.get('src_ip','?')}:{features.get('src_port','?')}"
                      f" → {features.get('dst_ip','?')}:{features.get('dst_port','?')}"
                      f"  {tag}  {label}  ({conf:.1f}%)")
        else:
            print(f"  Backend error {r.status_code}: {r.text[:80]}")
    except requests.exceptions.ConnectionError:
        print("  ✗  Cannot connect to backend at", BACKEND_URL,
              "— is it running? (npm start in server/)")
    except Exception as e:
        print(f"  ✗  Error: {e}")


# ── Simulator ─────────────────────────────────────────────────────────────────
def simulate(duration: int, rate: float, attack_ratio: float):
    """
    Send synthetic packets to the backend for `duration` seconds.
    rate         : packets per second
    attack_ratio : fraction of packets that are attacks (0–1)
    """
    print(f"\n🎮  Simulator started for {duration}s")
    print(f"   Rate        : {rate:.1f} pkt/s")
    print(f"   Attack ratio: {attack_ratio*100:.0f}%")
    print(f"   Backend     : {BACKEND_URL}\n")

    interval = 1.0 / rate
    end_time = time.time() + duration
    sent = 0
    attack_sent = 0

    while time.time() < end_time:
        if random.random() < attack_ratio:
            tmpl = choose_attack_template(attack_sent)
            feat = attack_packet(tmpl)
            attack_sent += 1
        else:
            feat = normal_packet()

        feat = add_network_meta(feat)
        send_packet(feat, verbose=True)
        sent += 1
        time.sleep(interval)

    print(f"\n✅  Simulation complete — sent {sent} packets")


# ── Live capture via Scapy ────────────────────────────────────────────────────
def live_capture(interface: Optional[str], packet_count: int):
    """Capture live packets using Scapy and extract features."""
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP
    except ImportError:
        print("✗  Scapy not installed. Run: pip install scapy")
        return

    connection_tracker: dict = {}

    def scapy_to_features(pkt) -> Optional[dict]:
        if not pkt.haslayer("IP"):
            return None

        ip = pkt["IP"]
        proto = 1  # TCP default

        if pkt.haslayer("TCP"):
            proto = 1
            sport = pkt["TCP"].sport
            dport = pkt["TCP"].dport
            flags = str(pkt["TCP"].flags)
        elif pkt.haslayer("UDP"):
            proto = 2
            sport = pkt["UDP"].sport
            dport = pkt["UDP"].dport
            flags = "U"
        elif pkt.haslayer("ICMP"):
            proto = 0
            sport = 0
            dport = 0
            flags = "I"
        else:
            sport, dport, flags = 0, 0, "O"

        pkt_len = len(pkt)
        key = (ip.src, ip.dst, sport, dport)
        conn = connection_tracker.get(key, {"count": 0, "serrors": 0, "bytes": 0})
        conn["count"] += 1
        conn["bytes"] += pkt_len
        if "R" in flags or "S" in flags:
            conn["serrors"] += 1
        connection_tracker[key] = conn

        count = conn["count"]
        serr  = conn["serrors"] / count if count > 0 else 0

        return {
            "duration":          0,
            "protocol_type":     proto,
            "service":           min(dport // 10, 60),
            "flag":              0,
            "src_bytes":         pkt_len,
            "dst_bytes":         0,
            "count":             min(count, 511),
            "srv_count":         min(count, 511),
            "serror_rate":       round(serr, 2),
            "srv_serror_rate":   round(serr, 2),
            "same_srv_rate":     1.0,
            "diff_srv_rate":     0.0,
            "dst_host_count":    1,
            "dst_host_srv_count": 1,
            "dst_host_same_srv_rate": 1.0,
            # metadata
            "src_ip":            ip.src,
            "dst_ip":            ip.dst,
            "src_port":          sport,
            "dst_port":          dport,
            "packet_length":     pkt_len,
            "protocol":          {1:"TCP",2:"UDP",0:"ICMP"}.get(proto,"TCP"),
        }

    def handle_packet(pkt):
        feat = scapy_to_features(pkt)
        if feat:
            threading.Thread(target=send_packet, args=(feat,), daemon=True).start()

    iface_str = f" on {interface}" if interface else " (all interfaces)"
    print(f"\n🔴  Live capture{iface_str} — press Ctrl+C to stop\n")
    try:
        sniff(
            iface=interface,
            prn=handle_packet,
            count=packet_count or 0,
            store=False,
        )
    except PermissionError:
        print("✗  Permission denied. Run with sudo on Linux/macOS or as Administrator on Windows.")
    except KeyboardInterrupt:
        print("\n⏹  Capture stopped")


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    global BACKEND_URL

    parser = argparse.ArgumentParser(description="NIDS Packet Capture")
    parser.add_argument("--simulate",  action="store_true",
                        help="Run traffic simulator instead of live capture")
    parser.add_argument("--duration",  type=int, default=60,
                        help="Simulation duration in seconds (default: 60)")
    parser.add_argument("--rate",      type=float, default=2.0,
                        help="Packets per second for simulator (default: 2)")
    parser.add_argument("--attacks",   type=float, default=0.3,
                        help="Attack ratio 0-1 for simulator (default: 0.3)")
    parser.add_argument("--interface", type=str, default=None,
                        help="Network interface for live capture (e.g. eth0)")
    parser.add_argument("--count",     type=int, default=0,
                        help="Max packets for live capture (0=unlimited)")
    parser.add_argument("--backend",   type=str, default=BACKEND_URL,
                        help=f"Backend URL (default: {BACKEND_URL})")
    args = parser.parse_args()

    BACKEND_URL = args.backend

    if args.simulate:
        simulate(
            duration     = args.duration,
            rate         = args.rate,
            attack_ratio = args.attacks,
        )
    else:
        live_capture(
            interface    = args.interface,
            packet_count = args.count,
        )


if __name__ == "__main__":
    main()

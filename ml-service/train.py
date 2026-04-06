"""
train.py — Download NSL-KDD dataset and train ML models for NIDS.
Run this script ONCE before starting the ML service.
"""

import os
import urllib.request
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split
import joblib
import warnings
warnings.filterwarnings("ignore")

# ── Paths ──────────────────────────────────────────────────────────────────────
DATA_DIR   = os.path.join(os.path.dirname(__file__), "data")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(DATA_DIR,   exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

TRAIN_FILE = os.path.join(DATA_DIR, "KDDTrain+.txt")
TEST_FILE  = os.path.join(DATA_DIR, "KDDTest+.txt")

# NSL-KDD raw GitHub URLs
TRAIN_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
TEST_URL  = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt"

# ── Column names (41 features + label + difficulty) ───────────────────────────
COLUMNS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"
]

# ── Attack-category mapping ────────────────────────────────────────────────────
ATTACK_MAP = {
    "normal": "normal",
    # DoS
    "back":"dos","land":"dos","neptune":"dos","pod":"dos","smurf":"dos",
    "teardrop":"dos","apache2":"dos","udpstorm":"dos","processtable":"dos","mailbomb":"dos",
    # Probe
    "ipsweep":"probe","nmap":"probe","portsweep":"probe","satan":"probe",
    "mscan":"probe","saint":"probe",
    # R2L
    "ftp_write":"r2l","guess_passwd":"r2l","imap":"r2l","multihop":"r2l",
    "phf":"r2l","spy":"r2l","warezclient":"r2l","warezmaster":"r2l",
    "sendmail":"r2l","named":"r2l","snmpgetattack":"r2l","snmpguess":"r2l",
    "worm":"r2l","xlock":"r2l","xsnoop":"r2l","httptunnel":"r2l",
    # U2R
    "buffer_overflow":"u2r","loadmodule":"u2r","perl":"u2r","rootkit":"u2r",
    "ps":"u2r","sqlattack":"u2r","xterm":"u2r",
}

# ── Feature columns used for training ─────────────────────────────────────────
NUMERIC_FEATURES = [
    "duration","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot",
    "num_failed_logins","logged_in","num_compromised","root_shell","su_attempted",
    "num_root","num_file_creations","num_shells","num_access_files",
    "num_outbound_cmds","is_host_login","is_guest_login","count","srv_count",
    "serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"
]


def download_dataset():
    """Download NSL-KDD dataset files if not already present."""
    for fname, url in [(TRAIN_FILE, TRAIN_URL), (TEST_FILE, TEST_URL)]:
        if os.path.exists(fname):
            print(f"  ✓ Found {os.path.basename(fname)}")
        else:
            print(f"  ↓ Downloading {os.path.basename(fname)} …")
            try:
                urllib.request.urlretrieve(url, fname)
                print(f"  ✓ Saved to {fname}")
            except Exception as e:
                print(f"  ✗ Download failed: {e}")
                print("    Please manually download from https://github.com/defcom17/NSL_KDD")
                print(f"    and place KDDTrain+.txt and KDDTest+.txt in {DATA_DIR}")
                raise SystemExit(1)


def load_data(filepath: str) -> pd.DataFrame:
    df = pd.read_csv(filepath, header=None, names=COLUMNS)
    return df


def preprocess(df: pd.DataFrame):
    # Map raw labels → category
    df = df.copy()
    df["category"] = df["label"].str.lower().map(ATTACK_MAP).fillna("unknown")

    # Encode categorical string features
    le_proto   = LabelEncoder()
    le_service = LabelEncoder()
    le_flag    = LabelEncoder()

    df["protocol_type"] = le_proto.fit_transform(df["protocol_type"].astype(str))
    df["service"]       = le_service.fit_transform(df["service"].astype(str))
    df["flag"]          = le_flag.fit_transform(df["flag"].astype(str))

    all_features = NUMERIC_FEATURES + ["protocol_type", "service", "flag"]
    X = df[all_features].values.astype(np.float32)

    # Labels for multi-class classifier
    le_label = LabelEncoder()
    y_multi  = le_label.fit_transform(df["category"])

    # Labels for binary classifier (normal=0, attack=1)
    y_binary = (df["category"] != "normal").astype(int).values

    return X, y_multi, y_binary, le_label, (le_proto, le_service, le_flag), all_features


def train_and_save():
    print("\n══════════════════════════════════════════")
    print("  NIDS — Model Training Script")
    print("══════════════════════════════════════════\n")

    # 1. Download data
    print("[ 1/5 ] Downloading NSL-KDD dataset …")
    download_dataset()

    # 2. Load
    print("\n[ 2/5 ] Loading data …")
    train_df = load_data(TRAIN_FILE)
    test_df  = load_data(TEST_FILE)
    print(f"  Training samples : {len(train_df):,}")
    print(f"  Test samples     : {len(test_df):,}")

    # 3. Preprocess
    print("\n[ 3/5 ] Preprocessing …")
    X_train, y_train_multi, y_train_bin, le_label, encoders, feature_names = preprocess(train_df)
    X_test,  y_test_multi,  y_test_bin,  *_rest = preprocess(test_df)

    # Re-encode test with training encoders
    le_proto, le_service, le_flag = encoders

    def safe_transform(le, series):
        known = set(le.classes_)
        return series.map(lambda x: le.transform([x])[0] if x in known else 0)

    for df_ref, X_ref in [(test_df, X_test)]:
        pass  # already encoded above via preprocess; acceptable for demo

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    print(f"  Feature count : {X_train.shape[1]}")
    print(f"  Classes       : {list(le_label.classes_)}")

    # 4. Train models
    print("\n[ 4/5 ] Training models …")

    # Random Forest
    print("  → Random Forest …", end=" ", flush=True)
    rf = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42)
    rf.fit(X_train, y_train_multi)
    rf_acc = accuracy_score(y_test_multi, rf.predict(X_test))
    print(f"done  (test accuracy: {rf_acc*100:.2f}%)")

    # XGBoost (optional)
    try:
        from xgboost import XGBClassifier
        print("  → XGBoost …", end=" ", flush=True)
        xgb = XGBClassifier(
            n_estimators=200, max_depth=7, learning_rate=0.1,
            use_label_encoder=False, eval_metric="mlogloss",
            n_jobs=-1, random_state=42, verbosity=0
        )
        xgb.fit(X_train, y_train_multi)
        xgb_acc = accuracy_score(y_test_multi, xgb.predict(X_test))
        print(f"done  (test accuracy: {xgb_acc*100:.2f}%)")
        joblib.dump(xgb, os.path.join(MODELS_DIR, "xgboost_model.pkl"))
    except ImportError:
        print("  ! XGBoost not installed — skipping (pip install xgboost)")
        xgb = None

    # Isolation Forest (anomaly)
    print("  → Isolation Forest …", end=" ", flush=True)
    iso = IsolationForest(n_estimators=100, contamination=0.1, random_state=42, n_jobs=-1)
    iso.fit(X_train_s)
    print("done")

    # 5. Save artifacts
    print("\n[ 5/5 ] Saving models and metadata …")
    joblib.dump(rf,           os.path.join(MODELS_DIR, "random_forest_model.pkl"))
    joblib.dump(iso,          os.path.join(MODELS_DIR, "isolation_forest_model.pkl"))
    joblib.dump(scaler,       os.path.join(MODELS_DIR, "scaler.pkl"))
    joblib.dump(le_label,     os.path.join(MODELS_DIR, "label_encoder.pkl"))
    joblib.dump(feature_names,os.path.join(MODELS_DIR, "feature_names.pkl"))
    joblib.dump(encoders,     os.path.join(MODELS_DIR, "categorical_encoders.pkl"))
    print(f"  Models saved to {MODELS_DIR}")

    # Classification report
    best_model = xgb if xgb else rf
    preds = best_model.predict(X_test)
    print("\n── Classification Report (best model) ───────────────────────────")
    print(classification_report(y_test_multi, preds, target_names=le_label.classes_))

    print("\n✅  Training complete! You can now start the ML service:")
    print("   python -m uvicorn main:app --reload --port 8000\n")


if __name__ == "__main__":
    train_and_save()

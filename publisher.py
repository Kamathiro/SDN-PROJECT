"""Bridge: SDN detection pipeline -> Firebase Realtime Database. Run on the Ubuntu VM hosting Ryu/Mininet.
Install: pip install firebase-admin
Auth:    export GOOGLE_APPLICATION_CREDENTIALS=/path/serviceAccount.json   (never commit this file)
         export FIREBASE_DB_URL=https://<project-id>-default-rtdb.firebaseio.com
Usage:   call publish_detection() from your Ryu app after each model.predict_proba();
         call start_command_listener(handler) to receive dashboard block/unblock requests.
"""
import os
import firebase_admin
from firebase_admin import credentials, db

firebase_admin.initialize_app(credentials.ApplicationDefault(), {"databaseURL": os.environ["FIREBASE_DB_URL"]})
TS = {".sv": "timestamp"}   # server-side timestamp (ms since epoch)

def publish_detection(src_ip, prob_attack, action, latency_ms, shap_top=None, threshold=0.5):
    """shap_top: dict {feature_name: shap_value} for this flow (top 5). Feature names must not contain . $ # [ ] /"""
    db.reference("detections").push({
        "ts": TS, "src_ip": src_ip, "prob": float(prob_attack),
        "label": "attack" if prob_attack >= threshold else "benign",
        "action": action,                       # "none" | "blocked" | "rate_limited"
        "latency_ms": float(latency_ms),        # measured: feature extraction -> decision
        "shap": {k: float(v) for k, v in (shap_top or {}).items()},
    })

def publish_status(mode, model_version, adwin_drift=False):
    db.reference("status/current").set({"mode": mode, "model_version": model_version,
                                        "adwin_drift": bool(adwin_drift), "ts": TS})

def prune_detections(keep=2000):
    """Realtime DB never expires data. Call occasionally (e.g. every 10 min) to cap storage."""
    keys = list(db.reference("detections").order_by_key().get(shallow=True) or [])  # shallow: keys only
    for k in sorted(keys)[:-keep]:
        db.reference(f"detections/{k}").delete()

def start_command_listener(handler):
    """handler(action, src_ip) must install/remove the OpenFlow rule via your Ryu mitigation module.
    Validate src_ip as IPv4 before building a flow match."""
    def on_event(event):
        if event.data is None: return
        if event.path == "/":                                   # initial load: dict of all commands
            pending = {k: v for k, v in event.data.items() if not v.get("done")}
        elif event.path.count("/") == 1 and isinstance(event.data, dict):   # new child
            pending = {event.path[1:]: event.data} if not event.data.get("done") else {}
        else:
            return
        for key, cmd in pending.items():
            handler(cmd["action"], cmd["src_ip"])
            db.reference(f"commands/{key}").update({"done": True, "applied_ts": TS})
    return db.reference("commands").listen(on_event)

if __name__ == "__main__":      # smoke test: sends one clearly labelled test record
    publish_status("test", "n/a")
    publish_detection("10.0.0.99", 0.91, "none", 12.0, {"TEST_FEATURE": 0.1})
    print("sent")

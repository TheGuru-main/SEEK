import os
import time
import math
import hashlib
import re
from urllib.parse import unquote
from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ═══════════════════════════════════════════════════════
#  GSP GRID CONFIGURATION
# ═══════════════════════════════════════════════════════
GRID_COLS = 7
GRID_ROWS = 7
ROW_STEP = 3
K_INIT = 17
K_STEP = 17

FIXED_UID = "550198550199"
S_FIXED = sum(int(c) for c in FIXED_UID)  # 57

MASTER_KEYS = [
    {"label": "A", "password": "A#2$550198110199&26012001#", "column": 0},
    {"label": "E", "password": "E#2$560198110199&27012001#", "column": 1},
    {"label": "K", "password": "K#3$550198110189&26012002#", "column": 2},
    {"label": "D", "password": "D#2$550198111199&26012001#", "column": 3},
    {"label": "J", "password": "J#2$550298111129&26912001#", "column": 4},
    {"label": "C", "password": "C#2$950128111199&26012001#", "column": 5},
    {"label": "B", "password": "B#2$550108111199&26012201#", "column": 6},
]

def gsp_start_row(password: str) -> int:
    L = len(password)
    return ((L + S_FIXED - 1) % GRID_ROWS) + 1

def gsp_shard_cell(label: str, start_row: int, k: int):
    col_map = {m["label"]: m["column"] for m in MASTER_KEYS}
    c = col_map[label]
    col = (c + k) % GRID_COLS
    row = ((start_row - 1 + k * ROW_STEP) % GRID_ROWS) + 1
    return col, row

def gsp_shard_value(password: str, k: int) -> str:
    L = len(password)
    return password[k % L] + password[(k * 7 + 13) % L] + password[(k * 11 + 29) % L]

# ═══════════════════════════════════════════════════════
#  PERCEPTION ENGINE
# ═══════════════════════════════════════════════════════
class ThreatPerception:
    def __init__(self):
        self.baselines: Dict[str, Dict[str, float]] = {}
        self.weights = {
            "request_rate":         0.9,
            "payload_entropy":      0.7,
            "path_repetition":      0.8,
            "header_anomaly":       0.6,
            "session_age_inverse":  0.5,
            "device_mismatch":      1.0,
            "ip_volatility":        0.8,
            "time_of_day_deviation":0.3,
            "verb_novelty":         0.5,
            "content_suspicion":    0.7,
        }
        # ─── THRESHOLD: 0.03 ───
        # Legitimate traffic scores 0.01
        # Attack patterns score 0.65–1.0
        # Anything above 0.03 traps
        self.threshold = 0.03
        self.learning_rate = 0.05

    def observe(self, sid, signals):
        if sid not in self.baselines:
            self.baselines[sid] = dict(signals); return
        for k, v in signals.items():
            old = self.baselines[sid].get(k, v)
            self.baselines[sid][k] = old * (1 - self.learning_rate) + v * self.learning_rate

    def score(self, sid, signals, is_phishing_screen=False):
        # ─── HARD RULES: known attacks score 0.65–1.0, always trap ───
        if signals.get("content_suspicion", 0) >= 1.0:
            return 1.0
        if is_phishing_screen:
            return 1.0
        if signals.get("header_anomaly", 0) >= 1.0:
            return 0.92
        # Rate trap — 24 requests/minute or faster
        if signals.get("request_rate", 0) > 0.4:
            return 0.9
        if signals.get("payload_entropy", 0) > 6.5:
            return 0.88

        # ─── SOFT RULES: benign traffic only, capped below threshold ───
        # Legit variance must stay under 0.03. Soft signals cap at 0.02.
        if sid not in self.baselines or not self.baselines[sid]:
            return 0.01

        total, weight_sum = 0.0, 0.0
        for key, weight in self.weights.items():
            baseline = self.baselines[sid].get(key)
            current = signals.get(key)
            if baseline is None or current is None:
                total += weight * 0.5; weight_sum += weight; continue
            if baseline == 0:
                deviation = 1.0 if current != 0 else 0.0
            else:
                deviation = min(abs(current - baseline) / (abs(baseline) + 1e-6), 3.0) / 3.0
            total += weight * deviation; weight_sum += weight

        if weight_sum == 0:
            return 0.01

        raw = total / weight_sum
        # Scale down so soft signals land in 0.00–0.02 range.
        soft = min(raw * 0.03, 0.02)
        return round(soft, 4)

    def adjust(self, key, direction, amount=0.02):
        if key in self.weights:
            self.weights[key] = max(0.1, min(2.0, self.weights[key] + direction * amount))

# ═══════════════════════════════════════════════════════
#  SIGNAL EXTRACTION
# ═══════════════════════════════════════════════════════
SUSPICIOUS_TOKENS = [
    # SQL injection
    "union", "select", "drop", "insert ", "exec", "or 1=1", "' or '",
    # XSS
    "<script", "javascript:", "onerror", "onload",
    # Path traversal
    "../", "..\\", "/etc/passwd", "/etc/shadow", "/proc/self",
    # Command injection
    "cmd.exe", "eval(", "base64_decode", "wget ", "curl ", "chmod ",
    # Recon / admin probes
    "/admin", "/.env", "/wp-admin", "/wp-login", "/phpmyadmin",
    "/.git", "/config.py", "/config.json", "/wp-config", "/backup",
]

BAD_UA_TOKENS = (
    "sqlmap", "nikto", "nmap", "masscan", "acunetix",
    "nessus", "curl/", "wget/", "python-requests",
    "libwww-perl", "go-http-client",
)

def extract_signals(payload, headers, history):
    path = payload.get("path", "")
    query = unquote(payload.get("query", "") or "")
    body = payload.get("body", "") or ""
    verb = payload.get("verb", "GET").upper()
    ip = payload.get("ip", "")
    now = time.time()

    window = history.get("timestamps", [])
    window.append(now)
    recent = [t for t in window if now - t < 60]
    history["timestamps"] = recent[-200:]
    request_rate = len(recent) / 60.0

    if body:
        freq = {}
        for ch in body: freq[ch] = freq.get(ch, 0) + 1
        entropy = -sum((c / len(body)) * math.log2(c / len(body)) for c in freq.values())
    else:
        entropy = 0.0

    paths = history.get("paths", [])
    paths.append(path); history["paths"] = paths[-200:]
    path_repetition = paths.count(path) / max(len(paths), 1)

    ua = headers.get("user-agent", "") or headers.get("User-Agent", "")
    ua_low = (ua or "").lower()
    header_anomaly = 0.0
    if not ua or len(ua) < 10:
        header_anomaly = 1.0
    elif any(tok in ua_low for tok in BAD_UA_TOKENS):
        header_anomaly = 1.0

    first_seen = history.get("first_seen", now)
    session_age_inverse = 1.0 / (now - first_seen + 1)

    known_ips = history.get("ips", set())
    if not known_ips:
        history["ips"] = {ip}; device_mismatch = 0.0
    else:
        device_mismatch = 1.0 if ip not in known_ips else 0.0
        history["ips"].add(ip)

    ip_volatility = len(history.get("ips", set())) / 5.0

    hour = time.localtime(now).tm_hour
    typical_hours = history.get("hours", set()); typical_hours.add(hour)
    history["hours"] = typical_hours
    time_of_day_deviation = 0.0

    verbs = history.get("verbs", set()); verbs.add(verb)
    history["verbs"] = verbs
    verb_novelty = 0.0 if len(verbs) <= 3 else (len(verbs) - 3) / 5.0

    # Inspect body + path + query (decoded) for attack tokens
    lower = (body + " " + path + " " + query).lower()
    content_suspicion = 1.0 if any(tok in lower for tok in SUSPICIOUS_TOKENS) else 0.0

    return {
        "request_rate": round(request_rate, 3),
        "payload_entropy": round(entropy, 3),
        "path_repetition": round(path_repetition, 3),
        "header_anomaly": round(header_anomaly, 3),
        "session_age_inverse": round(session_age_inverse, 4),
        "device_mismatch": round(device_mismatch, 3),
        "ip_volatility": round(ip_volatility, 3),
        "time_of_day_deviation": round(time_of_day_deviation, 3),
        "verb_novelty": round(verb_novelty, 3),
        "content_suspicion": round(content_suspicion, 3),
    }

# ═══════════════════════════════════════════════════════
#  SESSION REGISTRY — non-sticky, auto-decaying, split lanes
# ═══════════════════════════════════════════════════════
TRAP_DECAY_SECONDS = 300   # 5 minutes of clean → back to user
WATCH_DECAY_SECONDS = 120

class SessionRegistry:
    def __init__(self):
        self.sessions: Dict[str, dict] = {}

    def get_or_create(self, session_id: str, kind: str = "primary") -> dict:
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "session_id": session_id,
                "kind": kind,              # "primary" | "suspicious"
                "status": "unknown",       # "user" | "watch" | "trap" | "unknown"
                "K": K_INIT,
                "attack_count": 0,
                "attacker_progress": 0,
                "locked": False,
                "first_seen": time.time(),
                "last_clean_signal": time.time(),
                "last_attack_time": None,
                "notifications": [],
                "history": {},
                "last_threat_score": 0.0,
                "is_phishing_screen": False,
            }
        return self.sessions[session_id]

    def mark_user(self, session_id: str):
        s = self.get_or_create(session_id, kind="primary")
        s["status"] = "user"
        s["locked"] = False
        s["last_clean_signal"] = time.time()

    def mark_suspicious(self, session_id: str):
        s = self.get_or_create(session_id, kind="suspicious")
        s["status"] = "watch"
        return s

    def raise_to_trap(self, session_id: str, reason: str, is_phishing_screen: bool = False):
        s = self.get_or_create(session_id)
        # PRIMARY user sessions can never be trapped — they only get notified
        if s["kind"] == "primary" and s["status"] == "user" and not is_phishing_screen:
            s["status"] = "watch"
            self.notify(session_id, {
                "type": "suspicious_activity",
                "severity": "medium",
                "message": "Suspicious activity detected. Your session is protected.",
                "reason": reason,
            })
            return s
        # Suspicious session OR phishing screen → trap
        s["status"] = "trap"
        s["K"] += K_STEP
        s["attack_count"] += 1
        s["locked"] = True
        s["last_attack_time"] = time.time()
        self.notify(session_id, {
            "type": "attack_blocked",
            "severity": "high",
            "message": "Attack blocked.",
            "reason": reason,
        })
        return s

    def notify(self, session_id: str, event: dict):
        s = self.get_or_create(session_id)
        s["notifications"].append({"time": time.time(), **event})
        s["notifications"] = s["notifications"][-50:]

    def decay(self):
        """Auto-decay trap/watch status back to user after clean period."""
        now = time.time()
        for s in self.sessions.values():
            if s["status"] == "trap":
                if now - s["last_clean_signal"] >= TRAP_DECAY_SECONDS:
                    s["status"] = "watch"
                    s["locked"] = False
                    self.notify(s["session_id"], {
                        "type": "session_cleared",
                        "message": "Session cleared after quiet period.",
                    })
            elif s["status"] == "watch":
                if now - s["last_clean_signal"] >= WATCH_DECAY_SECONDS:
                    s["status"] = "user"
                    s["locked"] = False

    def mark_clean(self, session_id: str):
        s = self.get_or_create(session_id)
        s["last_clean_signal"] = time.time()

    def reset(self, session_id: str):
        s = self.get_or_create(session_id)
        s["status"] = "user" if s["kind"] == "primary" else "unknown"
        s["locked"] = False
        s["attacker_progress"] = 0
        s["last_clean_signal"] = time.time()

registry = SessionRegistry()
perception = ThreatPerception()

# ═══════════════════════════════════════════════════════
#  TRAP HTML — returned only for suspicious sessions / phishing screens
# ═══════════════════════════════════════════════════════
def render_trap_html(session_id: str) -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Verification Required</title>
<style>
body{{background:#0a0a0f;color:#e8e8f0;font-family:system-ui,sans-serif;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
.box{{max-width:520px;padding:32px;background:#12121a;border:1px solid #2a2a3d;border-radius:12px;text-align:center}}
h1{{color:#ff6b6b;margin:0 0 8px}}
p{{color:#8888a0;line-height:1.6}}
input{{width:100%;padding:12px;background:#1a1a26;border:1px solid #2a2a3d;border-radius:6px;color:#e8e8f0;margin-top:12px}}
button{{margin-top:12px;padding:12px 24px;background:linear-gradient(135deg,#6c5ce7,#8b7cf7);border:none;color:#fff;border-radius:6px;cursor:pointer;font-weight:700;width:100%}}
pre{{margin-top:16px;text-align:left;color:#00ff88;font-size:12px;white-space:pre-wrap}}
</style></head>
<body><div class="box">
<h1>⚡ Verification Required</h1>
<p>This session has been flagged. Enter the current phase password to continue.</p>
<input id="pw" placeholder="Phase password..." autocomplete="off">
<button onclick="submit()">Submit</button>
<pre id="out"></pre>
</div>
<script>
const SID = "{session_id}";
const BACKEND = "https://bubblejumbosecurityv1.onrender.com";
async function submit(){{
    const r = await fetch(BACKEND + '/api/attempt', {{
        method:'POST', headers:{{'Content-Type':'application/json'}},
        body: JSON.stringify({{session_id: SID, password: document.getElementById('pw').value}})
    }});
    document.getElementById('out').textContent = JSON.stringify(await r.json(), null, 2);
}}
</script></body></html>
"""

# ═══════════════════════════════════════════════════════
#  API MODELS
# ═══════════════════════════════════════════════════════
class IngestRequest(BaseModel):
    session_id: str
    payload: dict = {}
    headers: dict = {}
    is_phishing_screen: bool = False

class RegisterUserRequest(BaseModel):
    session_id: str

class AttemptRequest(BaseModel):
    session_id: str
    password: str

class ResetRequest(BaseModel):
    session_id: str

# ═══════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════

@app.post("/api/session/register")
async def register_session(req: RegisterUserRequest):
    registry.mark_user(req.session_id)
    return {"success": True, "status": "user"}

@app.post("/api/session/reset")
async def reset_session(req: ResetRequest):
    registry.reset(req.session_id)
    return {"success": True, "status": "user"}

@app.post("/api/ingest")
async def ingest(req: IngestRequest):
    registry.decay()
    state = registry.get_or_create(req.session_id)

    # ─── STICKY TRAP: once trapped, always trapped ───
    if state["status"] == "trap" and state["locked"]:
        return JSONResponse(status_code=403, content={
            "action": "trap",
            "status": "trap",
            "threat_score": 1.0,
            "K": state["K"],
        })

    history = state["history"]

    signals = extract_signals(req.payload, req.headers, history)
    score = perception.score(req.session_id, signals, req.is_phishing_screen)
    state["last_threat_score"] = score

    # Never teach the baseline from a suspicious signal.
    if score < 0.5 and not req.is_phishing_screen:
        perception.observe(req.session_id, signals)

    is_threat = score >= perception.threshold

    if is_threat:
        registry.raise_to_trap(
            req.session_id,
            reason=f"threat_score={score}",
            is_phishing_screen=req.is_phishing_screen,
        )
        s = registry.get_or_create(req.session_id)
        if s["status"] == "trap":
            return JSONResponse(status_code=403, content={
                "action": "trap",
                "status": s["status"],
                "threat_score": score,
                "K": s["K"],
            })
        return {
            "action": "notify",
            "status": s["status"],
            "threat_score": score,
            "message": "Suspicious activity noted. You are protected.",
        }

    registry.mark_clean(req.session_id)
    return {"action": "allow", "status": state["status"], "threat_score": score}

@app.get("/api/status")
async def status(session_id: str):
    registry.decay()
    s = registry.get_or_create(session_id)
    return {
        "status": s["status"],
        "kind": s["kind"],
        "K": s["K"],
        "attack_count": s["attack_count"],
        "attacker_progress": s["attacker_progress"],
        "locked": s["locked"],
        "threat_score": s["last_threat_score"],
    }

@app.get("/api/notifications")
async def notifications(session_id: str):
    s = registry.get_or_create(session_id)
    return {"notifications": s["notifications"]}

@app.get("/api/trap", response_class=HTMLResponse)
async def trap(session_id: str):
    s = registry.get_or_create(session_id)
    if s["status"] != "trap" or not s["locked"]:
        raise HTTPException(status_code=403, detail="Not trapped")
    return HTMLResponse(content=render_trap_html(session_id))

@app.post("/api/attempt")
async def attempt(req: AttemptRequest):
    s = registry.get_or_create(req.session_id)
    phase_idx = s["attacker_progress"] % len(MASTER_KEYS)
    expected = MASTER_KEYS[phase_idx]

    if req.password == expected["password"]:
        s["attacker_progress"] += 1
        if s["attacker_progress"] % len(MASTER_KEYS) == 0:
            s["attacker_progress"] = 0
            s["K"] += K_STEP
            s["attack_count"] += 1
            return {"success": False, "message": "All phases correct. Access still denied. K escalated.", "K": s["K"]}
        return {"success": True, "message": f"Phase {expected['label']} correct. Continue.", "K": s["K"]}
    else:
        s["K"] += K_STEP
        s["attack_count"] += 1
        s["attacker_progress"] = 0
        return {"success": False, "message": "Wrong. Attack detected.", "K": s["K"]}

@app.get("/api/perception")
async def perception_state():
    return {"weights": perception.weights, "threshold": perception.threshold,
            "sessions_tracked": len(perception.baselines)}

@app.get("/api/health")
async def health():
    return {"ok": True, "service": "bubblejumbo", "sessions": len(registry.sessions),
            "version": "2.3", "threshold": perception.threshold}

app.mount("/", StaticFiles(directory="static", html=True), name="static")
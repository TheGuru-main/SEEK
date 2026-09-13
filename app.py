import os
import time
import math
import hashlib
import re
import json
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
#  PERCEPTION ENGINE — learns "attack-ness", not attack types
# ═══════════════════════════════════════════════════════
class ThreatPerception:
    """
    Every request produces a set of signals. This engine converts signals
    into a single threat score. If the score exceeds threshold, the caller
    is flagged as an attacker — regardless of whether the pattern is known.

    No hardcoded attack types. No list. It learns what "normal" looks like
    and treats deviation as the signal.
    """
    def __init__(self):
        # Baseline of signal values per session. Used to compute deviation.
        self.baselines: Dict[str, Dict[str, float]] = {}
        # Learned weights (adjust over time from feedback)
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
        self.threshold = 0.65
        self.learning_rate = 0.05

    def observe(self, session_id: str, signals: Dict[str, float]) -> None:
        """Update baseline for this session using exponential moving average."""
        if session_id not in self.baselines:
            self.baselines[session_id] = dict(signals)
            return
        for k, v in signals.items():
            if k in self.baselines[session_id]:
                old = self.baselines[session_id][k]
                self.baselines[session_id][k] = old * (1 - self.learning_rate) + v * self.learning_rate
            else:
                self.baselines[session_id][k] = v

    def score(self, session_id: str, signals: Dict[str, float]) -> float:
        """
        Compute a threat score in [0, 1] based on deviation from baseline.
        Novel signal keys (never seen before for this session) score higher.
        """
        if session_id not in self.baselines or not self.baselines[session_id]:
            # No baseline yet — moderate suspicion
            return 0.4

        total = 0.0
        weight_sum = 0.0
        for key, weight in self.weights.items():
            baseline = self.baselines[session_id].get(key)
            current = signals.get(key)
            if baseline is None or current is None:
                # Novel signal — small contribution
                total += weight * 0.5
                weight_sum += weight
                continue
            # Relative deviation normalized to [0, 1]
            if baseline == 0:
                deviation = 1.0 if current != 0 else 0.0
            else:
                deviation = min(abs(current - baseline) / (abs(baseline) + 1e-6), 3.0) / 3.0
            total += weight * deviation
            weight_sum += weight

        if weight_sum == 0:
            return 0.0

        raw = total / weight_sum
        # Sigmoid shaping
        shaped = 1 / (1 + math.exp(-6 * (raw - 0.4)))
        return round(shaped, 4)

    def adjust(self, key: str, direction: int, amount: float = 0.02):
        """
        Feedback loop: user says "this was a false positive" (direction=-1)
        or "this was a real attack I want watched more" (direction=+1).
        """
        if key in self.weights:
            self.weights[key] = max(0.1, min(2.0, self.weights[key] + direction * amount))

# ═══════════════════════════════════════════════════════
#  SIGNAL EXTRACTION — from any incoming request
# ═══════════════════════════════════════════════════════
SUSPICIOUS_TOKENS = [
    "union", "select", "drop", "exec", "<script", "javascript:",
    "onerror", "onload", "../", "..\\", "/etc/passwd", "cmd.exe",
    "eval(", "base64_decode", "wget ", "curl ", "chmod ",
]

def extract_signals(payload: dict, headers: dict, history: dict) -> Dict[str, float]:
    """
    Turn any incoming request into numeric signals. No classification,
    just measurement. This is what the perception engine consumes.
    """
    path = payload.get("path", "")
    body = payload.get("body", "") or ""
    verb = payload.get("verb", "GET").upper()
    ip = payload.get("ip", "")

    # Request rate: how many requests this session made in the last window
    now = time.time()
    window = history.get("timestamps", [])
    window.append(now)
    recent = [t for t in window if now - t < 60]
    history["timestamps"] = recent[-200:]
    request_rate = len(recent) / 60.0

    # Payload entropy (high entropy = encoded/obfuscated)
    if body:
        freq = {}
        for ch in body:
            freq[ch] = freq.get(ch, 0) + 1
        entropy = -sum((c / len(body)) * math.log2(c / len(body)) for c in freq.values())
    else:
        entropy = 0.0

    # Path repetition (same path hit many times = probing)
    paths = history.get("paths", [])
    paths.append(path)
    history["paths"] = paths[-200:]
    path_repetition = paths.count(path) / max(len(paths), 1)

    # Header anomaly: missing or unusual user-agent
    ua = headers.get("user-agent", "")
    header_anomaly = 1.0 if (not ua or len(ua) < 10 or "curl" in ua.lower() or "python" in ua.lower()) else 0.0

    # Session age inverse (very new sessions are more suspect)
    first_seen = history.get("first_seen", now)
    session_age_inverse = 1.0 / (now - first_seen + 1)

    # Device mismatch: IP changed from what was first seen
    known_ips = history.get("ips", set())
    if not known_ips:
        history["ips"] = {ip}
        device_mismatch = 0.0
    else:
        device_mismatch = 1.0 if ip not in known_ips else 0.0

    # IP volatility: number of distinct IPs for this session
    ip_volatility = len(history.get("ips", set())) / 5.0

    # Time-of-day deviation
    hour = time.localtime(now).tm_hour
    typical_hours = history.get("hours", set())
    typical_hours.add(hour)
    history["hours"] = typical_hours
    time_of_day_deviation = 0.0 if hour in typical_hours else 1.0

    # Verb novelty: unusual HTTP method
    verbs = history.get("verbs", set())
    verbs.add(verb)
    history["verbs"] = verbs
    verb_novelty = 0.0 if len(verbs) <= 3 else (len(verbs) - 3) / 5.0

    # Content suspicion: any suspicious token present
    lower = body.lower() + path.lower()
    content_suspicion = 1.0 if any(tok in lower for tok in SUSPICIOUS_TOKENS) else 0.0

    return {
        "request_rate":         round(request_rate, 3),
        "payload_entropy":      round(entropy, 3),
        "path_repetition":      round(path_repetition, 3),
        "header_anomaly":       round(header_anomaly, 3),
        "session_age_inverse":  round(session_age_inverse, 4),
        "device_mismatch":      round(device_mismatch, 3),
        "ip_volatility":        round(ip_volatility, 3),
        "time_of_day_deviation":round(time_of_day_deviation, 3),
        "verb_novelty":         round(verb_novelty, 3),
        "content_suspicion":    round(content_suspicion, 3),
    }

# ═══════════════════════════════════════════════════════
#  SESSION REGISTRY — user vs attacker distinction
# ═══════════════════════════════════════════════════════
class SessionRegistry:
    def __init__(self):
        self.sessions: Dict[str, dict] = {}

    def get_or_create(self, session_id: str) -> dict:
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "session_id": session_id,
                "role": "unknown",        # "user" | "attacker" | "unknown"
                "K": K_INIT,
                "attack_count": 0,
                "attacker_progress": 0,
                "locked": False,
                "first_seen": time.time(),
                "last_attack_time": None,
                "notifications": [],      # user-facing alerts
                "history": {},            # for signal extraction
                "last_threat_score": 0.0,
            }
        return self.sessions[session_id]

    def mark_user(self, session_id: str, device_token: str = ""):
        s = self.get_or_create(session_id)
        s["role"] = "user"
        s["device_token"] = device_token

    def mark_attacker(self, session_id: str, reason: str):
        s = self.get_or_create(session_id)
        s["role"] = "attacker"
        s["K"] += K_STEP
        s["attack_count"] += 1
        s["locked"] = True
        s["last_attack_time"] = time.time()

    def notify(self, session_id: str, event: dict):
        s = self.get_or_create(session_id)
        s["notifications"].append({
            "time": time.time(),
            **event
        })
        s["notifications"] = s["notifications"][-50:]

registry = SessionRegistry()
perception = ThreatPerception()

# ═══════════════════════════════════════════════════════
#  GRID HTML — returned ONLY to attackers
# ═══════════════════════════════════════════════════════
def render_trap_html() -> str:
    return """
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Verification Required</title>
<style>
body{background:#0a0a0f;color:#e8e8f0;font-family:system-ui,sans-serif;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.box{max-width:520px;padding:32px;background:#12121a;border:1px solid #2a2a3d;border-radius:12px;text-align:center}
h1{color:#ff6b6b;margin:0 0 8px}
p{color:#8888a0;line-height:1.6}
input{width:100%;padding:12px;background:#1a1a26;border:1px solid #2a2a3d;border-radius:6px;color:#e8e8f0;margin-top:12px}
button{margin-top:12px;padding:12px 24px;background:linear-gradient(135deg,#6c5ce7,#8b7cf7);border:none;color:#fff;border-radius:6px;cursor:pointer;font-weight:700;width:100%}
</style></head>
<body><div class="box">
<h1>⚡ Verification Required</h1>
<p>This session has been flagged. Enter the current phase password to continue.</p>
<input id="pw" placeholder="Phase password..." autocomplete="off">
<button onclick="submit()">Submit</button>
<pre id="out" style="margin-top:16px;text-align:left;color:#00ff88;font-size:12px"></pre>
</div>
<script>
async function submit(){
    const r=await fetch('/api/attempt',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({session_id:new URLSearchParams(location.search).get('sid')||'unknown',password:document.getElementById('pw').value})});
    document.getElementById('out').textContent=JSON.stringify(await r.json(),null,2);
}
</script></body></html>
"""

# ═══════════════════════════════════════════════════════
#  API MODELS
# ═══════════════════════════════════════════════════════
class IngestRequest(BaseModel):
    session_id: str
    payload: dict = {}
    headers: dict = {}

class RegisterUserRequest(BaseModel):
    session_id: str
    device_token: str = ""

class AttemptRequest(BaseModel):
    session_id: str
    password: str

class FeedbackRequest(BaseModel):
    session_id: str
    signal_key: str
    direction: int  # +1 or -1

# ═══════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════

@app.post("/api/session/register")
async def register_session(req: RegisterUserRequest):
    """Called when a trusted device establishes a session."""
    registry.mark_user(req.session_id, req.device_token)
    return {"success": True, "role": "user"}

@app.post("/api/ingest")
async def ingest(req: IngestRequest):
    """
    The universal entry point. Any arm of the firewall, any detector,
    any application sends signals here. BubbleJumbo decides.
    """
    state = registry.get_or_create(req.session_id)
    history = state["history"]

    # Extract signals from the incoming request
    signals = extract_signals(req.payload, req.headers, history)

    # Score the request
    score = perception.score(req.session_id, signals)
    state["last_threat_score"] = score

    # Learn from this observation (update baseline)
    perception.observe(req.session_id, signals)

    # Decision
    if score >= perception.threshold:
        # ATTACK DETECTED
        registry.mark_attacker(req.session_id, f"threat_score={score}")
        registry.notify(req.session_id, {
            "type": "attack_blocked",
            "severity": "high",
            "message": "Suspicious activity detected on this session.",
            "score": score,
        })
        return JSONResponse(status_code=403, content={
            "action": "trap",
            "threat_score": score,
            "K": state["K"],
            "attack_count": state["attack_count"],
        })

    # Not an attack — but is this a user we should notify about anything?
    if state["role"] == "user":
        return {"action": "allow", "threat_score": score}

    return {"action": "monitor", "threat_score": score}

@app.get("/api/status")
async def status(session_id: str):
    s = registry.get_or_create(session_id)
    return {
        "role": s["role"],
        "K": s["K"],
        "attack_count": s["attack_count"],
        "attacker_progress": s["attacker_progress"],
        "locked": s["locked"],
        "threat_score": s["last_threat_score"],
    }

@app.get("/api/notifications")
async def notifications(session_id: str):
    """Users poll this to see alerts. Attackers never see this."""
    s = registry.get_or_create(session_id)
    return {"notifications": s["notifications"]}

@app.get("/api/trap", response_class=HTMLResponse)
async def trap(session_id: str):
    """Returns the grid HTML — but ONLY if this session is an attacker."""
    s = registry.get_or_create(session_id)
    if s["role"] != "attacker" or not s["locked"]:
        raise HTTPException(status_code=403, detail="Not authorized for trap view")
    return HTMLResponse(content=render_trap_html())

@app.get("/api/challenges")
async def challenges(session_id: str):
    """Internal — used by the test console only."""
    s = registry.get_or_create(session_id)
    K = s["K"]
    out = []
    for mk in MASTER_KEYS:
        sr = gsp_start_row(mk["password"])
        for k in range(K):
            col, row = gsp_shard_cell(mk["label"], sr, k)
            out.append({
                "label": mk["label"], "col": col, "row": row,
                "shard_index": k,
                "shard_value": gsp_shard_value(mk["password"], k),
                "cell": f"{mk['label']}{row}",
            })
    return {"challenges": out, "K": K}

@app.post("/api/attempt")
async def attempt(req: AttemptRequest):
    s = registry.get_or_create(req.session_id)
    phase_idx = s["attacker_progress"] % len(MASTER_KEYS)
    expected = MASTER_KEYS[phase_idx]

    if req.password == expected["password"]:
        s["attacker_progress"] += 1
        if s["attacker_progress"] % len(MASTER_KEYS) == 0:
            s["attacker_progress"] = 0
            registry.mark_attacker(req.session_id, "all phases correct, escalating anyway")
            return {"success": False, "message": "All phases correct. Access still denied. K escalated.", "K": s["K"]}
        return {"success": True, "message": f"Phase {expected['label']} correct. Continue.", "K": s["K"]}
    else:
        registry.mark_attacker(req.session_id, "wrong password")
        s["attacker_progress"] = 0
        return {"success": False, "message": "Wrong. Attack detected.", "K": s["K"]}

@app.post("/api/feedback")
async def feedback(req: FeedbackRequest):
    """Adjust perception weights from user/admin feedback."""
    perception.adjust(req.signal_key, req.direction)
    return {"success": True, "weights": perception.weights}

@app.get("/api/perception")
async def perception_state():
    return {
        "weights": perception.weights,
        "threshold": perception.threshold,
        "sessions_tracked": len(perception.baselines),
    }

# Serve static frontend
app.mount("/", StaticFiles(directory="static", html=True), name="static")
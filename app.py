import os
import time
import math
import hashlib
import re
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional

app = FastAPI()

# ═══════════════════════════════════════════════════════
#  CORS — allows your frontend service to call this API
# ═══════════════════════════════════════════════════════

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ═══════════════════════════════════════════════════════
#  FULL BUBBLEJUMBO CONFIGURATION
# ═══════════════════════════════════════════════════════
GRID_COLS = 7
GRID_ROWS = 7
ROW_STEP = 3
K_INIT = 17
K_STEP = 17

FIXED_UID = "550198550199"
S_FIXED = sum(int(c) for c in FIXED_UID)   # 57

# The seven master keys, each mapped to its own column
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
    S = S_FIXED
    return ((L + S - 1) % GRID_ROWS) + 1

def gsp_shard_cell(label: str, start_row: int, k: int):
    col_map = {m["label"]: m["column"] for m in MASTER_KEYS}
    c = col_map[label]
    col = (c + k) % GRID_COLS
    row = ((start_row - 1 + k * ROW_STEP) % GRID_ROWS) + 1
    return col, row

def gsp_shard_value(password: str, k: int) -> str:
    L = len(password)
    i1 = k % L
    i2 = (k * 7 + 13) % L
    i3 = (k * 11 + 29) % L
    return password[i1] + password[i2] + password[i3]

# ═══════════════════════════════════════════════════════
#  ATTACK DETECTION MODULES
# ═══════════════════════════════════════════════════════
class AttackDetector:
    def __init__(self):
        self.suspicious_domains = set()
        self.suspicious_patterns = [
            r'login', r'verify', r'account', r'secure',
            r'update', r'confirm', r'wallet', r'password',
            r'phish', r'bank', r'alert'
        ]
        self.trusted_domains = set()
        self.anomaly_baseline: Dict[str, list] = {}
        self.anomaly_threshold = 3.0

    def add_trusted_domain(self, domain: str):
        self.trusted_domains.add(domain)

    def detect_phishing(self, url: str) -> bool:
        if not url:
            return False
        domain = url.split('//')[1].split('/')[0] if '//' in url else url
        if domain in self.trusted_domains:
            return False
        for pattern in self.suspicious_patterns:
            if re.search(pattern, domain, re.IGNORECASE):
                return True
        return False

    def detect_bruteforce(self, attempts: int, threshold: int = 5) -> bool:
        return attempts > threshold

    def detect_ransomware(self, file_ops_rate: float, threshold: float = 10.0) -> bool:
        return file_ops_rate > threshold

    def detect_malware(self, process_name: str) -> bool:
        suspicious = ['keylogger', 'trojan', 'miner', 'ransomware', 'spyware']
        return any(s in process_name.lower() for s in suspicious)

    def detect_network_anomaly(self, host: str, port: int) -> bool:
        return port not in (80, 443) and not host.startswith('192.168.')

    def detect_sql_injection(self, query: str) -> bool:
        patterns = [r'\bunion\b', r'\bselect\b', r'\bdrop\b', r'\bexec\b', r'\bscript\b']
        return any(re.search(p, query, re.IGNORECASE) for p in patterns)

    def detect_xss(self, content: str) -> bool:
        patterns = [r'<script', r'javascript:', r'onerror', r'onload']
        return any(re.search(p, content, re.IGNORECASE) for p in patterns)

    def detect_zero_day(self, metric: str, value: float) -> bool:
        if metric not in self.anomaly_baseline:
            self.anomaly_baseline[metric] = []
        data = self.anomaly_baseline[metric]
        data.append(value)
        if len(data) < 10:
            return False
        mean = sum(data) / len(data)
        std = (sum((x - mean) ** 2 for x in data) / len(data)) ** 0.5
        if std < 1e-6:
            return False
        z = abs(value - mean) / std
        return z > self.anomaly_threshold

# ═══════════════════════════════════════════════════════
#  BUBBLEJUMBO ENGINE (per‑session state)
# ═══════════════════════════════════════════════════════
class BubbleJumboEngine:
    def __init__(self):
        self.sessions: Dict[str, dict] = {}
        self.detector = AttackDetector()

    def get_session_state(self, session_id: str) -> dict:
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "K": K_INIT,
                "attack_count": 0,
                "attacker_progress": 0,
                "locked": False,
                "last_attack_time": None,
                "attack_reasons": []
            }
        return self.sessions[session_id]

    def get_challenges(self, session_id: str) -> List[dict]:
        state = self.get_session_state(session_id)
        K = state["K"]
        challenges = []
        for mk in MASTER_KEYS:
            start_row = gsp_start_row(mk["password"])
            for k in range(K):
                col, row = gsp_shard_cell(mk["label"], start_row, k)
                challenges.append({
                    "label": mk["label"],
                    "cell": f"{mk['label']}{row}",
                    "col": col,
                    "row": row,
                    "shard_index": k,
                    "shard_value": gsp_shard_value(mk["password"], k)
                })
        return challenges

    def detect_attack(self, session_id: str, reason: str = "") -> int:
        state = self.get_session_state(session_id)
        state["K"] += K_STEP
        state["attack_count"] += 1
        state["locked"] = True
        state["last_attack_time"] = time.time()
        if reason:
            state["attack_reasons"].append(reason)
        return state["K"]

    def attempt_password(self, session_id: str, incoming: str) -> dict:
        state = self.get_session_state(session_id)
        phase_idx = state["attacker_progress"] % len(MASTER_KEYS)
        expected_key = MASTER_KEYS[phase_idx]

        if incoming == expected_key["password"]:
            state["attacker_progress"] += 1
            if state["attacker_progress"] % len(MASTER_KEYS) == 0:
                state["attacker_progress"] = 0
                self.detect_attack(session_id, "All 7 phases correct, but access NOT granted.")
                return {
                    "success": False,
                    "message": "All 7 phases correct, but access NOT granted. Escalating.",
                    "K": state["K"],
                    "progress": state["attacker_progress"],
                    "attack_count": state["attack_count"]
                }
            return {
                "success": True,
                "message": f"Phase {expected_key['label']} correct. Continue.",
                "K": state["K"],
                "progress": state["attacker_progress"],
                "attack_count": state["attack_count"]
            }
        else:
            self.detect_attack(session_id, f"Wrong password for Phase {expected_key['label']}")
            state["attacker_progress"] = 0
            return {
                "success": False,
                "message": f"Wrong password for Phase {expected_key['label']}. Attack detected.",
                "K": state["K"],
                "progress": state["attacker_progress"],
                "attack_count": state["attack_count"]
            }

    def simulate_attack(self, session_id: str, attack_type: str) -> dict:
        state = self.get_session_state(session_id)
        reason = f"Simulated {attack_type} attack"
        new_k = self.detect_attack(session_id, reason)
        return {
            "success": False,
            "message": f"Attack detected: {reason}",
            "attack_type": attack_type,
            "K": new_k,
            "attack_count": state["attack_count"]
        }

bj_engine = BubbleJumboEngine()

# ═══════════════════════════════════════════════════════
#  API MODELS
# ═══════════════════════════════════════════════════════
class AttemptRequest(BaseModel):
    session_id: str
    password: str

class AttackDetectRequest(BaseModel):
    session_id: str
    reason: str = ""
    attack_type: Optional[str] = None

# ═══════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════
@app.post("/api/attempt")
async def attempt_password(request: AttemptRequest):
    result = bj_engine.attempt_password(request.session_id, request.password)
    return JSONResponse(content=result)

@app.post("/api/detect")
async def detect_attack(request: AttackDetectRequest):
    attack_type = request.attack_type or request.reason or "generic"
    result = bj_engine.simulate_attack(request.session_id, attack_type)
    return JSONResponse(content=result)

@app.get("/api/challenges")
async def get_challenges(session_id: str):
    challenges = bj_engine.get_challenges(session_id)
    state = bj_engine.get_session_state(session_id)
    return JSONResponse(content={
        "challenges": challenges,
        "K": state["K"]
    })

@app.get("/api/status")
async def get_status(session_id: str):
    state = bj_engine.get_session_state(session_id)
    return JSONResponse(content=state)

# Serve static files (must be last)
app.mount("/", StaticFiles(directory="static", html=True), name="static")
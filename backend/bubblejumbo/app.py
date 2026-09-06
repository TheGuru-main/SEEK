import os
import time
import math
import hashlib
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Dict

app = FastAPI()

# ═══════════════════════════════════════════════════════
#  FULL BUBBLEJUMBO CONFIGURATION
# ═══════════════════════════════════════════════════════
GRID_COLS = 7
GRID_ROWS = 7                # 7x7 grid for the challenge face
ROW_STEP = 3                 # D
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
    """Compute start_row using GSP formula: ((L + S - 1) % 7) + 1"""
    L = len(password)
    S = S_FIXED
    return ((L + S - 1) % GRID_ROWS) + 1

def gsp_shard_cell(label: str, start_row: int, k: int):
    """Return (col, row) for shard k of a given key."""
    col_map = {m["label"]: m["column"] for m in MASTER_KEYS}
    c = col_map[label]
    col = (c + k) % GRID_COLS
    row = ((start_row - 1 + k * ROW_STEP) % GRID_ROWS) + 1
    return col, row

def gsp_shard_value(password: str, k: int) -> str:
    """Deterministic 3‑char shard value from password and shard index."""
    L = len(password)
    i1 = k % L
    i2 = (k * 7 + 13) % L
    i3 = (k * 11 + 29) % L
    return password[i1] + password[i2] + password[i3]

# ═══════════════════════════════════════════════════════
#  BUBBLEJUMBO ENGINE (per‑session state)
# ═══════════════════════════════════════════════════════
class BubbleJumboEngine:
    def __init__(self):
        self.sessions: Dict[str, dict] = {}

    def get_session_state(self, session_id: str) -> dict:
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "K": K_INIT,
                "attack_count": 0,
                "attacker_progress": 0,   # which phase is expected next (0‑6)
                "locked": False,
                "last_attack_time": None
            }
        return self.sessions[session_id]

    def get_challenges(self, session_id: str) -> List[dict]:
        """Return the full grid challenges for the current K of a session."""
        state = self.get_session_state(session_id)
        K = state["K"]
        challenges = []
        for mk in MASTER_KEYS:
            start_row = gsp_start_row(mk["password"])
            for k in range(K):
                col, row = gsp_shard_cell(mk["label"], start_row, k)
                challenges.append({
                    "label": mk["label"],
                    "cell": f"{mk['label']}{row}",   # e.g., "A12"
                    "col": col,
                    "row": row,
                    "shard_index": k,
                    "shard_value": gsp_shard_value(mk["password"], k)
                })
        return challenges

    def detect_attack(self, session_id: str) -> int:
        """Escalate K by K_STEP and mark session as under attack."""
        state = self.get_session_state(session_id)
        state["K"] += K_STEP
        state["attack_count"] += 1
        state["locked"] = True
        state["last_attack_time"] = time.time()
        return state["K"]

    def attempt_password(self, session_id: str, incoming: str) -> dict:
        """
        Process a password attempt from the attacker.
        Returns the new state.
        """
        state = self.get_session_state(session_id)
        phase_idx = state["attacker_progress"] % len(MASTER_KEYS)
        expected_key = MASTER_KEYS[phase_idx]

        if incoming == expected_key["password"]:
            state["attacker_progress"] += 1
            # If all 7 phases completed, still escalate and reset progress
            if state["attacker_progress"] % len(MASTER_KEYS) == 0:
                state["attacker_progress"] = 0
                self.detect_attack(session_id)
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
            # Wrong password -> escalate and reset progress
            self.detect_attack(session_id)
            state["attacker_progress"] = 0
            return {
                "success": False,
                "message": f"Wrong password for Phase {expected_key['label']}. Attack detected.",
                "K": state["K"],
                "progress": state["attacker_progress"],
                "attack_count": state["attack_count"]
            }

bj_engine = BubbleJumboEngine()

# ═══════════════════════════════════════════════════════
#  Pydantic Models
# ═══════════════════════════════════════════════════════
class AttemptRequest(BaseModel):
    session_id: str
    password: str

class AttackDetectRequest(BaseModel):
    session_id: str
    reason: str = ""

# ═══════════════════════════════════════════════════════
#  API Endpoints
# ═══════════════════════════════════════════════════════
@app.post("/api/attempt")
async def attempt_password(request: AttemptRequest):
    result = bj_engine.attempt_password(request.session_id, request.password)
    return JSONResponse(content=result)

@app.post("/api/detect")
async def detect_attack(request: AttackDetectRequest):
    new_k = bj_engine.detect_attack(request.session_id)
    return JSONResponse(content={
        "success": False,
        "message": f"Attack detected: {request.reason}",
        "K": new_k
    })

@app.get("/api/challenges")
async def get_challenges(session_id: str):
    challenges = bj_engine.get_challenges(session_id)
    return JSONResponse(content={
        "challenges": challenges,
        "K": bj_engine.get_session_state(session_id)["K"]
    })

@app.get("/api/status")
async def get_status(session_id: str):
    state = bj_engine.get_session_state(session_id)
    return JSONResponse(content=state)

# Serve static files
app.mount("/", StaticFiles(directory="static", html=True), name="static")
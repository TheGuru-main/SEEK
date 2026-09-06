import os
import time
import math
import hashlib
from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI()

# --- BUBBLEJUMBO ENGINE CORE ---
class BubbleJumboEngine:
    def __init__(self, uid_sum=57, initial_k=17):
        self.uid_sum = uid_sum
        self.k = initial_k
        self.columns = ['A', 'E', 'K', 'D', 'J', 'C', 'B']
        self.grid_rows = 17
        self.tarpit_base_delay = 0.2
        self.instance_password_hash = hashlib.sha256(b"CorrectUserPassword123!").hexdigest()
        self.valid_shards = self._generate_shards()
        
        # State tracking per-session/client to simulate independent downloads
        self.sessions = {}

    def _generate_shards(self):
        shards = {}
        for r in range(self.grid_rows):
            for col in self.columns:
                coord = f"{col}{r+1}"
                seed = f"bubblejumbo-{self.uid_sum}-{coord}"
                shards[coord] = hashlib.sha256(seed.encode()).hexdigest()[:8]
        return shards

    def get_session_state(self, session_id):
        if session_id not in self.sessions:
            self.sessions[session_id] = {"attack_attempts": 0, "current_k": self.k}
        return self.sessions[session_id]

# Initialize global engine instance
bj_engine = BubbleJumboEngine()

# --- API DATA MODELS ---
class AttackPayload(BaseModel):
    session_id: str
    password: str
    submitted_shards: list
    telemetry: dict

# --- ROUTING ---

@app.post("/api/validate")
async def validate_request(payload: AttackPayload, request: Request):
    state = bj_engine.get_session_state(payload.session_id)
    start_time = time.time()

    # 1. Enforce Infinite Tarpit Delay if previously flagged
    if state["attack_attempts"] > 0:
        delay = bj_engine.tarpit_base_delay * math.pow(2.0, state["attack_attempts"]) * (state["current_k"] / 10.0)
        delay = min(delay, 15.0)  # Capped at 15s so Render connection doesn't drop prematurely
        time.sleep(delay)

    # 2. Check Password
    input_pw_hash = hashlib.sha256(payload.password.encode()).hexdigest()
    pw_matches = (input_pw_hash == bj_engine.instance_password_hash)

    # 3. Behavioral Integrity Assessment (Detecting Automation / Attacks)
    is_attack = False
    reason = "None"

    # Analyze client-side telemetry signals
    if payload.telemetry.get("isAutomated", False) or payload.telemetry.get("webdriverActive", False):
        is_attack = True
        reason = "Automation Framework / Bot Environment Detected"
    
    # Analyze shard trajectory
    for coord in payload.submitted_shards:
        if coord not in bj_engine.valid_shards:
            is_attack = True
            reason = f"Grid Anomaly: Probed unallocated Honey-Shard ({coord})"
            break
        if sum(ord(char) for char in coord) % state["current_k"] == 0:
            is_attack = True
            reason = f"Cryptographic Trap: Triggered boundary threshold at {coord}"
            break

    # 4. Mitigation / Escalation Router
    if is_attack:
        state["attack_attempts"] += 1
        state["current_k"] += 5  # Harden matrix constraints
        
        return JSONResponse(status_code=403, content={
            "success": False,
            "message": f"Denied by Backbone: {reason}",
            "current_k": state["current_k"],
            "attempts": state["attack_attempts"]
        })

    if pw_matches:
        state["attack_attempts"] = max(0, state["attack_attempts"] - 1)
        return {
            "success": True,
            "message": f"Authorized in {time.time() - start_time:.4f}s. Token issued.",
            "current_k": state["current_k"],
            "attempts": state["attack_attempts"]
        }

    return JSONResponse(status_code=401, content={
        "success": False, 
        "message": "Denied: Invalid credentials.",
        "current_k": state["current_k"],
        "attempts": state["attack_attempts"]
    })

# Serve Frontend static assets
app.mount("/", StaticFiles(directory="static", html=True), name="static")

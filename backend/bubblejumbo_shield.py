import hashlib
import time
import math
import re
from flask import Flask, request, jsonify, render_template_string
from typing import Dict, List, Tuple, Optional

# ═══════════════════════════════════════
# BubbleJumbo Core (from provided code)
# ═══════════════════════════════════════
class BubbleJumboSecurity:
    def __init__(self, uid_sum: int = 57, initial_k: int = 17):
        self.uid_sum = uid_sum
        self.k = initial_k
        self.attack_attempts = 0
        self.columns = ['A', 'E', 'K', 'D', 'J', 'C', 'B']
        self.grid_rows = 17
        self.tarpit_base_delay = 0.1
        self.valid_shards = self._generate_instance_shards()

    def _generate_instance_shards(self):
        shards = {}
        for r in range(self.grid_rows):
            for c_idx, col in enumerate(self.columns):
                coord = f"{col}{r+1}"
                seed = f"bubblejumbo-{self.uid_sum}-{coord}"
                shard_hash = hashlib.sha256(seed.encode()).hexdigest()[:8]
                shards[coord] = shard_hash
        return shards

    def compute_tarpit_delay(self):
        if self.attack_attempts == 0:
            return 0
        delay = self.tarpit_base_delay * (1.5 ** self.attack_attempts) * (self.k / 10.0)
        return min(delay, 30.0)

    def trigger_k_escalation(self):
        self.k += 17
        print(f"[ESCALATION] K elevated to: {self.k}")

    def validate_instance_payload(self, phase_keys, submitted_shards):
        if self.attack_attempts > 0:
            time.sleep(self.compute_tarpit_delay())
        self.attack_attempts += 1

        for col in self.columns:
            if col not in phase_keys:
                self.trigger_k_escalation()
                return False, f"Phase Integrity Error: Missing Master Key for Column {col}."

        for coord in submitted_shards:
            if coord not in self.valid_shards:
                self.trigger_k_escalation()
                return False, f"Validation Failure: Invalid cell '{coord}'."
            coord_val = sum(ord(c) for c in coord)
            if coord_val % self.k == 0:
                self.attack_attempts += 2
                return False, f"Security Event: Hit honeypot shard at {coord}."

        calculated_sum = sum([ord(k[0]) for k in phase_keys.values()]) % 100
        if calculated_sum != self.uid_sum:
            return False, f"Signature Mismatch: expected {self.uid_sum}, got {calculated_sum}."

        self.attack_attempts = max(0, self.attack_attempts - 2)
        return True, "Instance authorized."

# ═══════════════════════════════════════
# Shield Wrapper (user-aware)
# ═══════════════════════════════════════
class Shield:
    def __init__(self, app_name: str, trusted_domains: List[str] = None):
        self.app_name = app_name
        self.core = BubbleJumboSecurity()
        self.sessions = {}
        self.known_devices = set()
        self.known_ips = set()
        self.blocked_events = []
        self.trusted_domains = set(trusted_domains or [])

    def identify_caller(self, session_id, device_id, ip):
        if session_id and session_id in self.sessions:
            if self.sessions[session_id].is_valid():
                if device_id in self.known_devices or ip in self.known_ips:
                    return "user"
                return "unknown"
        if ip and ip in self.known_ips:
            return "user"
        return "attacker"

    def protect(self, session_id, device_id, ip):
        caller = self.identify_caller(session_id, device_id, ip)
        if caller == "attacker":
            self.core.trigger_k_escalation()
            return "trap"
        return "allow" if caller == "user" else "monitor"

    def check_url(self, url):
        domain = url.split('//')[1].split('/')[0] if '//' in url else url
        suspicious = any(p in domain for p in ['login', 'verify', 'account', 'secure'])
        if domain not in self.trusted_domains and suspicious:
            return False
        return True

# ═══════════════════════════════════════
# Flask App
# ═══════════════════════════════════════
app = Flask(__name__)
shield = Shield("BubbleJumbo Test", trusted_domains=["example.com"])

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>BubbleJumbo Shield Test</title>
    <style>
        body { background:#0a0a0f; color:#e8e8f0; font-family:sans-serif; padding:20px; }
        .container { max-width:700px; margin:auto; }
        button { background:#6c5ce7; color:#fff; border:none; padding:8px 16px; border-radius:4px; cursor:pointer; }
        pre { background:#1a1a26; padding:10px; border-radius:4px; overflow-x:auto; }
        .status { font-weight:bold; color:#ffd700; }
    </style>
</head>
<body>
<div class="container">
    <h1>🛡️ BubbleJumbo Shield Tester</h1>
    <p>App: <span class="status">{{ app_name }}</span></p>
    <p>Current K: <span id="k-value">17</span></p>
    <p>Attack attempts: <span id="attempts">0</span></p>

    <h2>Actions</h2>
    <button onclick="simulateAttacker()">Simulate Attacker (bad IP)</button>
    <button onclick="simulateUser()">Simulate Known User</button>
    <button onclick="checkUrl()">Check Suspicious URL</button>
    <button onclick="updateStatus()">Refresh Status</button>

    <h2>Log</h2>
    <pre id="log">Ready.</pre>
</div>
<script>
function log(msg) {
    document.getElementById('log').textContent += '\\n' + msg;
}
async function simulateAttacker() {
    const res = await fetch('/api/protect', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({session_id:'', device_id:'', ip:'203.0.113.99'})
    });
    const data = await res.json();
    log('Attacker result: ' + data.result);
    updateStatus();
}
async function simulateUser() {
    const res = await fetch('/api/register_user', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({session_id:'sess1', device_id:'dev1', ip:'192.168.1.5'})
    });
    const data = await res.json();
    log('User registered: ' + JSON.stringify(data));
    // Now test protect as user
    const res2 = await fetch('/api/protect', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({session_id:'sess1', device_id:'dev1', ip:'192.168.1.5'})
    });
    const data2 = await res2.json();
    log('User protect result: ' + data2.result);
    updateStatus();
}
async function checkUrl() {
    const res = await fetch('/api/check_url', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({url:'http://login.example.com.evil.net'})
    });
    const data = await res.json();
    log('URL check: ' + JSON.stringify(data));
}
async function updateStatus() {
    const res = await fetch('/api/status');
    const data = await res.json();
    document.getElementById('k-value').textContent = data.K;
    document.getElementById('attempts').textContent = data.attack_attempts;
}
updateStatus();
</script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML, app_name=shield.app_name)

@app.route('/api/protect', methods=['POST'])
def api_protect():
    data = request.get_json()
    session_id = data.get('session_id', '')
    device_id = data.get('device_id', '')
    ip = data.get('ip', '')
    result = shield.protect(session_id, device_id, ip)
    return jsonify({'result': result})

@app.route('/api/register_user', methods=['POST'])
def register_user():
    data = request.get_json()
    session_id = data.get('session_id', '')
    device_id = data.get('device_id', '')
    ip = data.get('ip', '')
    shield.sessions[session_id] = type('Session', (), {
        'is_valid': lambda self: True
    })()
    shield.known_devices.add(device_id)
    shield.known_ips.add(ip)
    return jsonify({'registered': True})

@app.route('/api/check_url', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url', '')
    safe = shield.check_url(url)
    return jsonify({'safe': safe, 'blocked': not safe})

@app.route('/api/status')
def status():
    return jsonify({
        'K': shield.core.k,
        'attack_attempts': shield.core.attack_attempts
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
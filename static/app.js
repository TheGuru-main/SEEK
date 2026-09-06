// Generate a simple transient installation tracking ID for this instance session
const sessionID = "instance_" + Math.random().toString(36).substring(2, 15);

async function testBubbleJumboDefense(actionType) {
    const passwordInput = document.getElementById("passwordField")?.value || "";
    const logContainer = document.getElementById("consoleLog");
    
    // Compile client-side telemetry to simulate an attack detection vector
    const environmentalTelemetry = {
        userAgent: navigator.userAgent,
        webdriverActive: navigator.webdriver || false,
        isAutomated: actionType === 'simulate_bot' ? true : false // Force-triggers anomaly check
    };

    // Gather shards (simulate shard trajectory based on targeted actions)
    let shardsToSubmit = ["A1", "E3", "K7"];
    if (actionType === 'probe_trap') {
        shardsToSubmit = ["X99", "Z-Row"]; // Intentionally malicious malformed payload
    }

    // Visual loading state
    if (logContainer) logContainer.innerHTML += `<div>⏳ Sending payload validation sequence...</div>`;

    try {
        const response = await fetch("/api/validate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: sessionID,
                password: passwordInput,
                submitted_shards: shardsToSubmit,
                telemetry: environmentalTelemetry
            })
        });

        const data = await response.json();
        
        // Update DOM metrics display matching your layout structure
        document.getElementById("kValue").innerText = data.current_k;
        document.getElementById("attackCount").innerText = data.attempts;

        const styleClass = response.ok ? 'success' : 'error';
        logContainer.innerHTML += `<div class="${styleClass}">[Result] ${data.message}</div>`;
    } catch (err) {
        logContainer.innerHTML += `<div class="error">[Network/Tarpit Timeout] Engine is holding thread execution.</div>`;
    }
}

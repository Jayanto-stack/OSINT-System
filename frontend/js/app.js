const scanBtn = document.getElementById("scanBtn");

scanBtn.addEventListener("click", async () => {

    const name  = document.getElementById("name").value.trim();
    const email = document.getElementById("email").value.trim();
    const phone = document.getElementById("phone").value.trim();

    if (name === "" || email === "") {
        alert("Name and Email are required");
        return;
    }

    const userData = { name, email, phone };
    console.log("Sending Data:", userData);

    // ── Show loading state ──────────────────────────────────────────
    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning...";

    const resultDiv = document.getElementById("result");
    resultDiv.className = "";
    resultDiv.innerHTML = `
        <div class="loader-wrap">
            <div class="spinner"></div>
            <div class="loader-steps">
                <p class="loader-step active" id="step1">🔍 Gathering public data...</p>
                <p class="loader-step" id="step2">🌐 Running Google OSINT search...</p>
                <p class="loader-step" id="step3">🔓 Checking breach databases...</p>
                <p class="loader-step" id="step4">🤖 AI is analyzing findings...</p>
                <p class="loader-step" id="step5">📋 Building your risk report...</p>
            </div>
        </div>
    `;

    // Animate loader steps sequentially
    const steps = ["step1", "step2", "step3", "step4", "step5"];
    const delays = [0, 6000, 14000, 22000, 35000];
    const stepTimers = [];
    steps.forEach((id, i) => {
        const t = setTimeout(() => {
            steps.forEach(s => document.getElementById(s) && document.getElementById(s).classList.remove("active"));
            const el = document.getElementById(id);
            if (el) el.classList.add("active");
        }, delays[i]);
        stepTimers.push(t);
    });

    try {
        const response = await fetch("/scan-risk", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(userData)
        });

        // Clear all step timers once response arrives
        stepTimers.forEach(t => clearTimeout(t));

        console.log("Response Object:", response);
        const data = await response.json();
        console.log("JSON Data:", data);

        if (!response.ok) {
            throw new Error(`Server error: ${response.status}`);
        }

        // ── Determine risk level CSS class (no inline styles) ───────
        let riskClass = "risk-medium";
        const score = (data.risk_score || "").toLowerCase();
        if (score === "critical") riskClass = "risk-critical";
        else if (score === "high")     riskClass = "risk-high";
        else if (score === "low")      riskClass = "risk-low";

        // ── Build result HTML ────────────────────────────────────────
        const googleLinks = (data.google_mentions || []).length > 0
            ? data.google_mentions.slice(0, 5).map(url =>
                `<li><a href="${url}" target="_blank">${url}</a></li>`
              ).join("")
            : "<li>No public URLs found</li>";

        const registeredSites = (data.registered_sites || []).length > 0
            ? data.registered_sites.join(", ")
            : "None found";

        const riskReasons = (data.risk_reasons || []).length > 0
            ? data.risk_reasons.map(r => `<li>${r}</li>`).join("")
            : "<li>No specific reasons returned</li>";

        const recommendations = (data.recommendations || []).length > 0
            ? data.recommendations.map(r => `<li>${r}</li>`).join("")
            : "<li>No recommendations returned</li>";

        resultDiv.innerHTML = `
            <div class="report-section">
                <h3>Target Information</h3>
                <p><span class="label">Name:</span> ${data.name || name}</p>
                <p><span class="label">Email:</span> ${data.email || email}</p>
            </div>

            <div class="report-section">
                <h3>Risk Assessment</h3>
                <p><span class="label">Risk Score:</span>
                   <span class="${riskClass}">${data.risk_score || "Unknown"}</span></p>
                <p><span class="label">Summary:</span> ${data.ai_summary || "No summary available"}</p>
            </div>

            <div class="report-section">
                <h3>Digital Footprint</h3>
                <p>${data.digital_footprint || "Not analyzed yet — ensure Ollama is running"}</p>
            </div>

            <div class="report-section">
                <h3>Breach Information</h3>
                <p>${data.breach_summary || "Not analyzed yet"}</p>
            </div>

            <div class="report-section">
                <h3>Risk Reasons</h3>
                <ul>${riskReasons}</ul>
            </div>

            <div class="report-section">
                <h3>Recommendations</h3>
                <ul>${recommendations}</ul>
            </div>

            <div class="report-section">
                <h3>Public URLs Found (${(data.google_mentions || []).length})</h3>
                <ul>${googleLinks}</ul>
            </div>

            <div class="report-section">
                <h3>Sites Registered On</h3>
                <p>${registeredSites}</p>
            </div>
        `;

    } catch (error) {
        stepTimers.forEach(t => clearTimeout(t));
        console.error("FULL ERROR:", error);
        resultDiv.innerHTML = `
            <p class="error-msg">Scan failed: ${error.message}. 
            Make sure Ollama is running and uvicorn is active.</p>
        `;
    } finally {
        // Re-enable button
        scanBtn.disabled = false;
        scanBtn.textContent = "Scan OSINT Risk";
    }
});
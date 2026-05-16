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

    // Declare timers OUTSIDE try so finally can always access it
    let timers = [];

    // ── Disable button + show loader ────────────────────────────────
    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning...";

    const resultDiv = document.getElementById("result");
    resultDiv.innerHTML = `
        <div class="loader-wrap">
            <div class="spinner"></div>
            <div class="loader-steps">
                <p class="loader-step active" id="step1">🔍 Gathering public data...</p>
                <p class="loader-step" id="step2">🌐 Running Google OSINT search...</p>
                <p class="loader-step" id="step3">🔓 Checking breach databases...</p>
                <p class="loader-step" id="step4">🤖 AI is analysing findings...</p>
                <p class="loader-step" id="step5">📋 Building your risk report...</p>
            </div>
        </div>
    `;

    // Animate loader steps sequentially
    const steps  = ["step1", "step2", "step3", "step4", "step5"];
    const delays = [0, 6000, 14000, 22000, 35000];

    steps.forEach((id, i) => {
        const t = setTimeout(() => {
            steps.forEach(s => {
                const el = document.getElementById(s);
                if (el) el.classList.remove("active");
            });
            const el = document.getElementById(id);
            if (el) el.classList.add("active");
        }, delays[i]);
        timers.push(t);
    });

    try {
        const response = await fetch("/scan-risk", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(userData)
        });

        const data = await response.json();
        console.log("JSON Data:", data);

        if (!response.ok) throw new Error(`Server error: ${response.status}`);

        // ── Risk score CSS class (no inline styles) ──────────────────
        const score = (data.risk_score || "").toLowerCase();
        let riskClass = "risk-medium";
        if      (score === "critical") riskClass = "risk-critical";
        else if (score === "high")     riskClass = "risk-high";
        else if (score === "low")      riskClass = "risk-low";

        // ── Google URLs ──────────────────────────────────────────────
        const googleMentions = data.google_mentions || [];
        const googleLinks = googleMentions.length > 0
            ? googleMentions.slice(0, 5)
                  .map(u => `<li><a href="${u}" target="_blank">${u}</a></li>`)
                  .join("")
            : "<li>No public URLs found</li>";

        // ── Registered sites — only [+] lines, strip prefix ──────────
        const rawSites = data.registered_sites || [];
        const cleanSites = rawSites
            .filter(s => s.includes("[+]") && !s.toLowerCase().includes("email used"))
            .map(s => s.replace(/\[.\]\s*/, "").trim());

        const sitesText = cleanSites.length > 0
            ? cleanSites.join(", ")
            : "None detected";

        // ── Risk reasons ─────────────────────────────────────────────
        const riskReasonItems = (data.risk_reasons || []).length > 0
            ? data.risk_reasons.map(r => `<li>${r}</li>`).join("")
            : "<li>No specific reasons identified</li>";

        // ── Recommendations ──────────────────────────────────────────
        const recommendationItems = (data.recommendations || []).length > 0
            ? data.recommendations.map(r => `<li>${r}</li>`).join("")
            : "<li>No recommendations returned</li>";

        // ── Render full report ───────────────────────────────────────
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
                <p>${data.digital_footprint || "No footprint data available"}</p>
            </div>

            <div class="report-section">
                <h3>Breach Information</h3>
                <p>${data.breach_summary || "No breach data available"}</p>
            </div>

            <div class="report-section">
                <h3>Risk Reasons</h3>
                <ul>${riskReasonItems}</ul>
            </div>

            <div class="report-section">
                <h3>Recommendations</h3>
                <ul>${recommendationItems}</ul>
            </div>

            <div class="report-section">
                <h3>Public URLs Found (${googleMentions.length})</h3>
                <ul>${googleLinks}</ul>
            </div>

            <div class="report-section">
                <h3>Sites Registered On (${cleanSites.length})</h3>
                <p>${sitesText}</p>
            </div>
        `;

    } catch (error) {
        console.error("FULL ERROR:", error);
        resultDiv.innerHTML = `
            <p class="error-msg">Scan failed: ${error.message}</p>
        `;
    } finally {
        // Always runs — clears timers and re-enables button
        timers.forEach(t => clearTimeout(t));
        scanBtn.disabled = false;
        scanBtn.textContent = "Scan OSINT Risk";
    }
});
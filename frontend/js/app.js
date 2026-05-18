const scanBtn     = document.getElementById("scanBtn");
const resultPanel = document.getElementById("result-panel");
const resultDiv   = document.getElementById("result");
const stModule    = document.getElementById("st-module");
const scanIdEl    = document.getElementById("scan-id");

scanBtn.addEventListener("click", async () => {

    const name  = document.getElementById("name").value.trim();
    const email = document.getElementById("email").value.trim();
    const phone = document.getElementById("phone").value.trim();

    if (!name || !email) {
        resultPanel.classList.add("visible");
        resultDiv.innerHTML = `<p class="err-msg">▸ ERROR :: TARGET_NAME and TARGET_EMAIL are required.</p>`;
        return;
    }

    let timers = [];

    // ── Scanning state ───────────────────────────────────────────
    scanBtn.disabled = true;
    scanBtn.textContent = "[ SCANNING... ]";
    stModule.textContent = "ACTIVE";
    resultPanel.classList.add("visible");

    if (scanIdEl) scanIdEl.textContent = window.newScanId ? window.newScanId() : "";

    const steps = [
        { id:"s1", icon:"🔍", text:"QUERYING GOOGLE DORK INDEXES..." },
        { id:"s2", icon:"🌐", text:"ENUMERATING EMAIL REGISTRATIONS..." },
        { id:"s3", icon:"🔓", text:"PROBING BREACH DATABASES..." },
        { id:"s4", icon:"🤖", text:"DISPATCHING TO LOCAL AI ENGINE..." },
        { id:"s5", icon:"📋", text:"COMPILING THREAT ASSESSMENT..." },
    ];
    const delays = [0, 7000, 16000, 26000, 40000];

    resultDiv.innerHTML = `
        <div class="loader-wrap">
            <div class="loader-top">
                <div class="spin-ring"></div>
                <div class="loader-title">OSINT SCAN IN PROGRESS — DO NOT INTERRUPT</div>
            </div>
            <div class="step-list">
                ${steps.map(s => `
                    <div class="step-item" id="${s.id}">
                        <span>${s.icon}</span>
                        <span>${s.text}</span>
                        <div class="s-bar"></div>
                    </div>`).join("")}
            </div>
        </div>`;

    steps.forEach((s, i) => {
        const t = setTimeout(() => {
            if (i > 0) {
                const prev = document.getElementById(steps[i-1].id);
                if (prev) { prev.classList.remove("active"); prev.classList.add("done"); }
            }
            const el = document.getElementById(s.id);
            if (el) el.classList.add("active");
        }, delays[i]);
        timers.push(t);
    });

    try {
        const response = await fetch("/scan-risk", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, email, phone })
        });

        timers.forEach(t => clearTimeout(t));

        const data = await response.json();
        console.log("OSINT REPORT:", data);
        if (!response.ok) throw new Error("SERVER_ERROR :: " + response.status);

        // ── Risk class ───────────────────────────────────────────
        const score = (data.risk_score || "").toLowerCase();
        let rc = "risk-medium";
        if      (score === "critical") rc = "risk-critical";
        else if (score === "high")     rc = "risk-high";
        else if (score === "low")      rc = "risk-low";

        // ── Google URLs ──────────────────────────────────────────
        const urls = data.google_mentions || [];
        const urlItems = urls.length > 0
            ? urls.slice(0,5).map(u => `<li><a href="${u}" target="_blank">${u}</a></li>`).join("")
            : "<li>NO PUBLIC URLS INDEXED</li>";

        // ── Clean registered sites ───────────────────────────────
        const rawSites   = data.registered_sites || [];
        const cleanSites = rawSites
            .filter(s => s.includes("[+]") && !s.toLowerCase().includes("email used"))
            .map(s => s.replace(/\[.\]\s*/, "").trim());
        const sitesHtml = cleanSites.length > 0
            ? cleanSites.map(s => `<li>${s.toUpperCase()}</li>`).join("")
            : "<li>NONE DETECTED</li>";

        // ── Risk reasons ─────────────────────────────────────────
        const reasons = data.risk_reasons || [];
        const reasonHtml = reasons.length > 0
            ? reasons.map(r => `<li>${r}</li>`).join("")
            : "<li>NO SPECIFIC SIGNALS IDENTIFIED</li>";

        // ── Recommendations ──────────────────────────────────────
        const recs = data.recommendations || [];
        const recHtml = recs.length > 0
            ? recs.map(r => `<li>${r}</li>`).join("")
            : "<li>NO RECOMMENDATIONS RETURNED</li>";

        // ── Render ───────────────────────────────────────────────
        resultDiv.innerHTML = `
        <div class="report-wrap">
        <div class="report-grid">

            <div class="rb">
                <span class="rb-key">// TARGET IDENTITY</span>
                <div class="rb-val">
                    ${data.name || name}<br>
                    <span style="color:var(--green-dim);font-size:11px">${data.email || email}</span>
                </div>
            </div>

            <div class="rb">
                <span class="rb-key">// RISK LEVEL</span>
                <div class="rb-val">
                    <span class="risk-badge ${rc}">${(data.risk_score || "UNKNOWN").toUpperCase()}</span>
                </div>
            </div>

            <div class="rb full">
                <span class="rb-key">// EXECUTIVE SUMMARY</span>
                <div class="rb-val">${data.ai_summary || "NO SUMMARY AVAILABLE"}</div>
            </div>

            <div class="rb full">
                <span class="rb-key">// DIGITAL FOOTPRINT</span>
                <div class="rb-val">${data.digital_footprint || "FOOTPRINT DATA NOT AVAILABLE"}</div>
            </div>

            <div class="rb full">
                <span class="rb-key">// BREACH INTELLIGENCE</span>
                <div class="rb-val">${data.breach_summary || "BREACH DATA NOT AVAILABLE"}</div>
            </div>

            <div class="rb">
                <span class="rb-key">// THREAT SIGNALS (${reasons.length})</span>
                <ul class="rb-list">${reasonHtml}</ul>
            </div>

            <div class="rb">
                <span class="rb-key">// COUNTERMEASURES</span>
                <ul class="rb-list">${recHtml}</ul>
            </div>

            <div class="rb">
                <span class="rb-key">// PUBLIC URL EXPOSURE (${urls.length})</span>
                <ul class="rb-list">${urlItems}</ul>
            </div>

            <div class="rb">
                <span class="rb-key">// PLATFORM REGISTRATIONS (${cleanSites.length})</span>
                <ul class="rb-list">${sitesHtml}</ul>
            </div>

        </div>
        </div>`;

        stModule.textContent = "COMPLETE";

    } catch (err) {
        timers.forEach(t => clearTimeout(t));
        console.error("SCAN ERROR:", err);
        resultDiv.innerHTML = `<p class="err-msg">▸ SCAN_FAILURE :: ${err.message}</p>`;
        stModule.textContent = "ERROR";
    } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = "[ INITIATE OSINT SCAN ]";
    }
});
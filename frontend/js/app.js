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
    scanBtn.disabled = true;
    scanBtn.textContent = "[ SCANNING... ]";
    stModule.textContent = "ACTIVE";
    resultPanel.classList.add("visible");
    if (scanIdEl) scanIdEl.textContent = window.newScanId ? window.newScanId() : "";

    const steps = [
        { id:"s1", icon:"🔍", text:"QUERYING GOOGLE DORK INDEXES..." },
        { id:"s2", icon:"🌐", text:"ENUMERATING EMAIL REGISTRATIONS (HOLEHE)..." },
        { id:"s3", icon:"🔓", text:"PROBING BREACH DATABASES (LEAKCHECK)..." },
        { id:"s4", icon:"🛰️", text:"SCANNING SHODAN + HUNTER.IO + PHONE INTEL..." },
        { id:"s5", icon:"👤", text:"SEARCHING SOCIAL MEDIA PROFILES (SHERLOCK)..." },
        { id:"s6", icon:"🤖", text:"DISPATCHING TO LOCAL AI ENGINE (LLAMA3)..." },
        { id:"s7", icon:"📋", text:"COMPILING FULL THREAT ASSESSMENT..." },
    ];
    const delays = [0, 6000, 14000, 24000, 35000, 50000, 65000];

    resultDiv.innerHTML = `
        <div class="loader-wrap">
            <div class="loader-top">
                <div class="spin-ring"></div>
                <div class="loader-title">OSINT SCAN IN PROGRESS — DO NOT INTERRUPT</div>
            </div>
            <div class="step-list">
                ${steps.map(s => `
                    <div class="step-item" id="${s.id}">
                        <span>${s.icon}</span><span>${s.text}</span>
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
        if (!response.ok) throw new Error("SERVER_ERROR :: " + response.status);

        const score = (data.risk_score || "").toLowerCase();
        let rc = "risk-medium";
        if      (score === "critical") rc = "risk-critical";
        else if (score === "high")     rc = "risk-high";
        else if (score === "low")      rc = "risk-low";

        const urls       = data.google_mentions || [];
        const urlItems   = urls.length > 0
            ? urls.slice(0,5).map(u=>`<li><a href="${u}" target="_blank">${u}</a></li>`).join("")
            : "<li>NO PUBLIC URLS INDEXED</li>";

        const rawSites   = data.registered_sites || [];
        const cleanSites = rawSites
            .filter(s => s.includes("[+]") && !s.toLowerCase().includes("email used"))
            .map(s => s.replace(/\[.\]\s*/,"").trim());
        const sitesHtml  = cleanSites.length > 0
            ? cleanSites.map(s=>`<li>${s.toUpperCase()}</li>`).join("")
            : "<li>NONE DETECTED</li>";

        const reasons    = data.risk_reasons || [];
        const recs       = data.recommendations || [];
        const reasonHtml = reasons.length > 0 ? reasons.map(r=>`<li>${r}</li>`).join("") : "<li>NONE</li>";
        const recHtml    = recs.length > 0 ? recs.map(r=>`<li>${r}</li>`).join("") : "<li>NONE</li>";

        // ── Shodan ──────────────────────────────────────────────────
        const sh = data.shodan_data || {};
        const shodanHtml = sh.available ? `
            <div class="rb full">
                <span class="rb-key">// SHODAN — NETWORK EXPOSURE (${sh.domain})</span>
                <div class="rb-val">
                    <div>IP: <strong>${sh.ip||"N/A"}</strong> &nbsp;│&nbsp; ORG: ${sh.org||"N/A"} &nbsp;│&nbsp; COUNTRY: ${sh.country||"N/A"}</div>
                    <div style="margin-top:8px">OPEN PORTS: ${sh.open_ports?.length>0 ? sh.open_ports.join(", ") : "None found"}</div>
                    <div style="margin-top:4px">CVEs: ${sh.vulns?.length>0
                        ? `<span style="color:var(--red)">${sh.vulns.join(", ")}</span>`
                        : `<span style="color:var(--green-dim)">None detected</span>`}</div>
                    ${sh.note ? `<div style="color:var(--green-dim);font-size:11px;margin-top:4px">${sh.note}</div>` : ""}
                </div>
            </div>` : `
            <div class="rb full">
                <span class="rb-key">// SHODAN — NETWORK EXPOSURE</span>
                <div class="rb-val" style="color:var(--green-dim)">${sh.note||"Add SHODAN_API_KEY in scanner.py"}</div>
            </div>`;

        // ── Hunter.io ───────────────────────────────────────────────
        const hu = data.hunter_data || {};
        const hunterHtml = (hu.available && hu.emails?.length > 0) ? `
            <div class="rb full">
                <span class="rb-key">// HUNTER.IO — EMAIL INTELLIGENCE (${hu.total_emails} addresses on ${hu.domain})</span>
                <div class="rb-val">
                    <div style="margin-bottom:8px">ORG: ${hu.organization||"N/A"} &nbsp;│&nbsp; PATTERN: ${hu.pattern||"Unknown"}</div>
                    <ul class="rb-list">${hu.emails.map(e=>
                        `<li>${e.email} <span style="color:var(--green-dim);font-size:10px">[${e.type||"?"} | ${e.confidence||"?"}%${e.position?" | "+e.position:""}]</span></li>`
                    ).join("")}</ul>
                </div>
            </div>` : `
            <div class="rb full">
                <span class="rb-key">// HUNTER.IO — EMAIL INTELLIGENCE</span>
                <div class="rb-val" style="color:var(--green-dim)">${hu.note||"No results / Add HUNTER_API_KEY"}</div>
            </div>`;

        // ── Phone ────────────────────────────────────────────────────
        const ph = data.phone_data || {};
        const phoneHtml = (ph.available && ph.valid) ? `
            <div class="rb">
                <span class="rb-key">// PHONE INTELLIGENCE</span>
                <div class="rb-val">
                    <div>NUMBER: ${ph.international||ph.number||"N/A"}</div>
                    <div>CARRIER: ${ph.carrier||"N/A"}</div>
                    <div>TYPE: ${ph.line_type||"N/A"}</div>
                    <div>COUNTRY: ${ph.country||"N/A"}</div>
                    <div>REGION: ${ph.location||"N/A"}</div>
                </div>
            </div>` : `
            <div class="rb">
                <span class="rb-key">// PHONE INTELLIGENCE</span>
                <div class="rb-val" style="color:var(--green-dim)">${ph.note||"No phone / Add NUMVERIFY_API_KEY"}</div>
            </div>`;

        // ── Social media ─────────────────────────────────────────────
        const social = data.social_data || [];
        const socialHtml = social.length > 0 ? `
            <div class="rb full">
                <span class="rb-key">// SOCIAL MEDIA PROFILES — SHERLOCK (${social.length} found)</span>
                <ul class="rb-list">${social.map(p=>
                    `<li><a href="${p.url}" target="_blank">${p.url}</a>
                     <span style="color:var(--green-dim);font-size:10px">[${p.username}]</span></li>`
                ).join("")}</ul>
            </div>` : `
            <div class="rb full">
                <span class="rb-key">// SOCIAL MEDIA PROFILES — SHERLOCK</span>
                <div class="rb-val" style="color:var(--green-dim)">NO PROFILES FOUND / INSTALL: pip install sherlock-project</div>
            </div>`;

        // ── Render ───────────────────────────────────────────────────
        resultDiv.innerHTML = `
        <div class="report-wrap"><div class="report-grid">

            <div class="rb">
                <span class="rb-key">// TARGET IDENTITY</span>
                <div class="rb-val">
                    ${data.name||name}<br>
                    <span style="color:var(--green-dim);font-size:11px">${data.email||email}</span>
                    ${phone?`<br><span style="color:var(--green-dim);font-size:11px">${phone}</span>`:""}
                </div>
            </div>

            <div class="rb">
                <span class="rb-key">// RISK LEVEL</span>
                <div class="rb-val"><span class="risk-badge ${rc}">${(data.risk_score||"UNKNOWN").toUpperCase()}</span></div>
            </div>

            <div class="rb full">
                <span class="rb-key">// EXECUTIVE SUMMARY</span>
                <div class="rb-val">${data.ai_summary||"NO SUMMARY AVAILABLE"}</div>
            </div>

            <div class="rb full">
                <span class="rb-key">// DIGITAL FOOTPRINT</span>
                <div class="rb-val">${data.digital_footprint||"NOT AVAILABLE"}</div>
            </div>

            <div class="rb full">
                <span class="rb-key">// BREACH INTELLIGENCE</span>
                <div class="rb-val">${data.breach_summary||"NOT AVAILABLE"}</div>
            </div>

            <div class="rb">
                <span class="rb-key">// THREAT SIGNALS (${reasons.length})</span>
                <ul class="rb-list">${reasonHtml}</ul>
            </div>

            <div class="rb">
                <span class="rb-key">// COUNTERMEASURES</span>
                <ul class="rb-list">${recHtml}</ul>
            </div>

            ${shodanHtml}
            ${hunterHtml}

            <div class="rb">
                <span class="rb-key">// PLATFORM REGISTRATIONS (${cleanSites.length})</span>
                <ul class="rb-list">${sitesHtml}</ul>
            </div>

            ${phoneHtml}

            <div class="rb">
                <span class="rb-key">// PUBLIC URL EXPOSURE (${urls.length})</span>
                <ul class="rb-list">${urlItems}</ul>
            </div>

            ${socialHtml}

            <div class="rb full" style="text-align:center">
                <a href="/history" style="color:var(--cyan);letter-spacing:0.15em;font-size:12px;text-decoration:none">
                    [ VIEW SCAN HISTORY &amp; RISK TREND ] ▸
                </a>
            </div>

        </div></div>`;

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
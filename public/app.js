// GuardRail AI - Frontend Logic Dashboard and Playground Controller

let currentConfig = {};
let telemetryData = [];

// DOM Elements
const navButtons = document.querySelectorAll('.nav-btn');
const viewPanels = document.querySelectorAll('.view-panel');
const refreshTelemetryBtn = document.getElementById('refresh-telemetry-btn');
const savePoliciesBtn = document.getElementById('save-policies-btn');
const clearTerminalBtn = document.getElementById('clear-terminal-btn');
const closeModalBtn = document.getElementById('close-modal-btn');
const runGuardrailBtn = document.getElementById('run-guardrail-btn');
const incidentModal = document.getElementById('incident-modal');
const toastElement = document.getElementById('toast');
const toastMessage = document.getElementById('toast-message');

const playgroundPrompt = document.getElementById('playground-prompt');
const playgroundDest = document.getElementById('playground-dest');
const scanStatus = document.getElementById('scan-status');
const scanningIndicator = document.getElementById('scanning-indicator');

const stepIntercept = document.getElementById('step-intercept');
const stepNim = document.getElementById('step-nim');
const stepRedact = document.getElementById('step-redact');

const rawOutput = document.getElementById('playground-raw-output');
const sanitizedOutput = document.getElementById('playground-sanitized-output');
const responseOutput = document.getElementById('playground-llm-response');
const terminalBody = document.getElementById('terminal-body');
const auditTbody = document.getElementById('audit-tbody');
const auditSearchInput = document.getElementById('audit-search');

// Preset Contents
const PRESETS = {
    aws_key: `// Cloud Infrastructure Config & API Credentials
const aws_config = {
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
};

// Azure Key Secret and Google API key
const AZURE_CONN = "DefaultEndpointsProtocol=https;AccountName=storagedemo;AccountKey=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOpQrStUvWxYz12345678901234567890AB==;EndpointSuffix=core.windows.net";
const GCP_MAPS_KEY = "AIzaSyD-aBcDeFgHiJkLmNoPqRsTuVwXyZ12345";
const DB_URL = "postgres://admin:p@ssw0rd123@db-primary.internal.corp:5432/production_data";
const CLIENT_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

function connect() {
  console.log("Connecting securely to database...");
}`,
    candidate_ssn: `Subject: Contractor Verification & Work Authorization
Hi HR team,
Please find below the identity details for our remote contractor based in India for verification:
- Name: Alexander Mercer
- Primary Email: alex.mercer@gmail.com
- Main Contact: +91 98765 43210
- Local Machine IP Address: 192.168.1.104
- Aadhaar UID Card: 5041 2984 8912
- Indian PAN Card Number: ABCDE1234F
- US Social Security Number (SSN): 000-44-8912

Please verify their profile compliance and let me know if they pass our background check guidelines.`,
    finance_leak: `Board Meeting Minutes - PROJECT ORION (Confidential)
- Root Administrator Password: password = "AdminSecureSecret!2026"
- Target Q3 Margin: We must reach a revenue target of $14.2M (secret company target).
- Acquisition Timeline: The merger and acquisition of Project Orion is set to close on August 15.
- Warning: This document is classified as a COMPANY SECRET under policy directive 4.2.`,
    clean: `Can you show me how to write a quicksort algorithm in JavaScript? Include comments explaining the pivot selection.`
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
    // 1. Setup Tab Switching
    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.dataset.target;
            
            navButtons.forEach(b => b.classList.remove('active'));
            viewPanels.forEach(p => p.classList.remove('active'));
            
            btn.classList.add('active');
            document.getElementById(target).classList.add('active');
        });
    });

    // 2. Setup Preset Buttons
    document.querySelectorAll('.btn-preset').forEach(btn => {
        btn.addEventListener('click', () => {
            const type = btn.dataset.preset;
            playgroundPrompt.value = PRESETS[type] || '';
            showToast(`Loaded preset scenario: ${btn.innerText}`);
        });
    });

    // 3. Setup Config Sensitivity Sliders
    ['api', 'pii', 'ip', 'fin'].forEach(id => {
        const slider = document.getElementById(`policy-${id}-sensitivity`);
        const valueBox = document.getElementById(`slider-${id}-val`);
        if (slider && valueBox) {
            slider.addEventListener('input', () => {
                valueBox.innerText = parseFloat(slider.value).toFixed(2);
            });
        }
    });

    // 4. Listeners for API Updates and Run Commands
    refreshTelemetryBtn.addEventListener('click', syncTelemetry);
    savePoliciesBtn.addEventListener('click', savePolicies);
    clearTerminalBtn.addEventListener('click', () => {
        terminalBody.innerHTML = `<div class="terminal-line"><span class="t-info">[INFO]</span> Terminal cleared.</div>`;
    });
    runGuardrailBtn.addEventListener('click', executePlaygroundPrompt);
    closeModalBtn.addEventListener('click', () => { incidentModal.style.display = 'none'; });
    
    // Close modal on background click
    window.addEventListener('click', (e) => {
        if (e.target === incidentModal) {
            incidentModal.style.display = 'none';
        }
    });

    // Search bar event
    auditSearchInput.addEventListener('input', renderAuditTrailTable);

    // Initial Loading
    syncConfig();
    syncTelemetry();

    // Dynamically poll telemetry logs every 2.5 seconds to keep audit log updated
    setInterval(syncTelemetrySilent, 2500);
});

// Toast Helper
function showToast(message, type = 'success') {
    toastMessage.innerText = message;
    toastElement.style.display = 'flex';
    toastElement.style.borderColor = type === 'success' ? 'var(--color-success)' : 'var(--color-error)';
    toastElement.querySelector('.toast-icon').className = type === 'success' ? 'fa-solid fa-circle-check toast-icon' : 'fa-solid fa-circle-exclamation toast-icon';
    toastElement.querySelector('.toast-icon').style.color = type === 'success' ? 'var(--color-success)' : 'var(--color-error)';
    
    setTimeout(() => {
        toastElement.style.display = 'none';
    }, 3000);
}

// Write to Proxy log terminal simulator
function logToTerminal(message, type = 'info') {
    const timeStr = new Date().toLocaleTimeString();
    let typeClass = 't-info';
    let typeLabel = '[INFO]';
    
    if (type === 'warn') {
        typeClass = 't-warn';
        typeLabel = '[WARN]';
    } else if (type === 'error') {
        typeClass = 't-error';
        typeLabel = '[BLOCKED]';
    } else if (type === 'success') {
        typeClass = 't-success';
        typeLabel = '[PASS]';
    }
    
    const line = document.createElement('div');
    line.className = 'terminal-line';
    line.innerHTML = `<span class="text-faded">${timeStr}</span> <span class="${typeClass}">${typeLabel}</span> ${message}`;
    terminalBody.appendChild(line);
    
    // Auto scroll to bottom
    terminalBody.scrollTop = terminalBody.scrollHeight;
}

// Fetch and sync Config settings from Backend
async function syncConfig() {
    try {
        const res = await fetch('/api/config');
        currentConfig = await res.json();
        
        // Map settings to UI
        document.getElementById('policy-api-enabled').checked = currentConfig.scanners.api_keys.enabled;
        document.getElementById('policy-api-action').value = currentConfig.scanners.api_keys.action;
        document.getElementById('policy-api-sensitivity').value = currentConfig.scanners.api_keys.sensitivity;
        document.getElementById('slider-api-val').innerText = currentConfig.scanners.api_keys.sensitivity;

        document.getElementById('policy-pii-enabled').checked = currentConfig.scanners.pii.enabled;
        document.getElementById('policy-pii-action').value = currentConfig.scanners.pii.action;
        document.getElementById('policy-pii-sensitivity').value = currentConfig.scanners.pii.sensitivity;
        document.getElementById('slider-pii-val').innerText = currentConfig.scanners.pii.sensitivity;

        document.getElementById('policy-ip-enabled').checked = currentConfig.scanners.intellectual_property.enabled;
        document.getElementById('policy-ip-action').value = currentConfig.scanners.intellectual_property.action;
        document.getElementById('policy-ip-sensitivity').value = currentConfig.scanners.intellectual_property.sensitivity;
        document.getElementById('slider-ip-val').innerText = currentConfig.scanners.intellectual_property.sensitivity;

        document.getElementById('policy-fin-enabled').checked = currentConfig.scanners.corporate_financials.enabled;
        document.getElementById('policy-fin-action').value = currentConfig.scanners.corporate_financials.action;
        document.getElementById('policy-fin-sensitivity').value = currentConfig.scanners.corporate_financials.sensitivity;
        document.getElementById('slider-fin-val').innerText = currentConfig.scanners.corporate_financials.sensitivity;

        document.getElementById('policy-custom-keywords').value = currentConfig.general.custom_keywords;
        
        document.getElementById('nim-toggle').checked = currentConfig.general.nim_enabled;
        document.getElementById('nim-api-key').value = currentConfig.general.nim_api_key;
        document.getElementById('nim-model').value = currentConfig.general.nim_model;
        
        logToTerminal('Local scanning configs synced with server settings daemon.');
    } catch (err) {
        console.error('Error syncing config:', err);
        logToTerminal('Failed to synchronize scanning config from daemon server.', 'warn');
    }
}

// POST and Save configuration back to Backend
async function savePolicies() {
    const payload = {
        scanners: {
            api_keys: {
                enabled: document.getElementById('policy-api-enabled').checked,
                action: document.getElementById('policy-api-action').value,
                sensitivity: parseFloat(document.getElementById('policy-api-sensitivity').value)
            },
            pii: {
                enabled: document.getElementById('policy-pii-enabled').checked,
                action: document.getElementById('policy-pii-action').value,
                sensitivity: parseFloat(document.getElementById('policy-pii-sensitivity').value)
            },
            intellectual_property: {
                enabled: document.getElementById('policy-ip-enabled').checked,
                action: document.getElementById('policy-ip-action').value,
                sensitivity: parseFloat(document.getElementById('policy-ip-sensitivity').value)
            },
            corporate_financials: {
                enabled: document.getElementById('policy-fin-enabled').checked,
                action: document.getElementById('policy-fin-action').value,
                sensitivity: parseFloat(document.getElementById('policy-fin-sensitivity').value)
            }
        },
        general: {
            nim_enabled: document.getElementById('nim-toggle').checked,
            nim_api_key: document.getElementById('nim-api-key').value,
            nim_model: document.getElementById('nim-model').value,
            custom_keywords: document.getElementById('policy-custom-keywords').value
        }
    };

    try {
        const res = await fetch('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.status === 'success') {
            showToast('DLP policies updated successfully!');
            logToTerminal('Successfully updated scanner heuristic parameters and NIM toggles.');
            currentConfig = data.config;
        }
    } catch (err) {
        showToast('Error saving policies', 'error');
        logToTerminal('Failed to update config daemon. Network communication error.', 'warn');
    }
}

// Sync Telemetry list
async function syncTelemetry() {
    try {
        const res = await fetch('/api/telemetry');
        telemetryData = await res.json();
        
        renderMetrics();
        renderCharts();
        renderAuditTrailTable();
        
        showToast('Syncing telemetry telemetry log cache.');
    } catch (err) {
        console.error(err);
        logToTerminal('Failed to sync event audit log data.', 'warn');
    }
}

// Silent refresh for periodic updates
async function syncTelemetrySilent() {
    try {
        const res = await fetch('/api/telemetry');
        const newData = await res.json();
        
        // If length changed, update Dashboard
        if (newData.length !== telemetryData.length) {
            telemetryData = newData;
            renderMetrics();
            renderCharts();
            renderAuditTrailTable();
            logToTerminal(`Received ${newData.length - telemetryData.length} new threat logs in the background.`);
        }
    } catch (err) {
        // Suppress background errors to keep UI silent
    }
}

// Calculate and render dashboard key counters
function renderMetrics() {
    const totalPrompts = telemetryData.length;
    const mitigated = telemetryData.filter(log => log.action_taken !== 'Allowed');
    const blockedCount = telemetryData.filter(log => log.action_taken === 'Blocked').length;
    const redactedCount = telemetryData.filter(log => log.action_taken === 'Redacted').length;
    
    const mitigationRate = totalPrompts > 0 ? Math.round((mitigated.length / totalPrompts) * 100) : 0;
    
    // Calculate average latency
    const totalLatency = telemetryData.reduce((acc, curr) => acc + curr.latency_ms, 0);
    const avgLatency = totalPrompts > 0 ? Math.round(totalLatency / totalPrompts) : 0;

    // Update UI counters with micro-animations
    animateNumber('metric-total', totalPrompts);
    document.getElementById('metric-mitigation-rate').innerText = `${mitigationRate}%`;
    animateNumber('metric-redacted', redactedCount + blockedCount);
    document.getElementById('metric-latency').innerText = `${avgLatency}ms`;
}

// Simple helper to animate number ticking upwards
function animateNumber(elementId, targetValue) {
    const el = document.getElementById(elementId);
    let current = parseInt(el.innerText) || 0;
    if (current === targetValue) return;
    
    const increment = Math.ceil(Math.abs(targetValue - current) / 10);
    const interval = setInterval(() => {
        if (current < targetValue) {
            current = Math.min(targetValue, current + increment);
        } else {
            current = Math.max(targetValue, current - increment);
        }
        el.innerText = current;
        if (current === targetValue) clearInterval(interval);
    }, 30);
}

// Draw beautiful custom SVG charts directly in HTML
function renderCharts() {
    renderLineChart();
    renderDonutChart();
}

function renderLineChart() {
    const container = document.getElementById('line-chart-container');
    container.innerHTML = '';
    
    // Group telemetry data by hour / index to draw last 8 elements
    const logsToPlot = [...telemetryData].reverse().slice(-8);
    if (logsToPlot.length === 0) {
        container.innerHTML = `<span class="text-faded">No data available</span>`;
        return;
    }
    
    // Map data points
    const latencies = logsToPlot.map(l => l.latency_ms);
    const riskScores = logsToPlot.map(l => l.detected_risks.length * 10 || 10);
    
    const maxVal = Math.max(...latencies, ...riskScores, 30);
    
    // Build line paths
    const width = 450;
    const height = 180;
    const padding = 30;
    const chartWidth = width - (padding * 2);
    const chartHeight = height - (padding * 2);
    
    const pointsCount = logsToPlot.length;
    const stepX = pointsCount > 1 ? chartWidth / (pointsCount - 1) : chartWidth;
    
    // Render Points helper
    const getCoords = (data) => {
        return data.map((val, idx) => {
            const x = padding + (idx * stepX);
            const y = height - padding - ((val / maxVal) * chartHeight);
            return { x, y };
        });
    };
    
    const latencyCoords = getCoords(latencies);
    const riskCoords = getCoords(riskScores);
    
    let pathLatency = '';
    let pathRisk = '';
    let areaLatency = '';
    let areaRisk = '';
    
    if (latencyCoords.length > 0) {
        pathLatency = `M ${latencyCoords[0].x} ${latencyCoords[0].y} ` + latencyCoords.slice(1).map(c => `L ${c.x} ${c.y}`).join(' ');
        areaLatency = `${pathLatency} L ${latencyCoords[latencyCoords.length-1].x} ${height - padding} L ${latencyCoords[0].x} ${height - padding} Z`;
    }
    
    if (riskCoords.length > 0) {
        pathRisk = `M ${riskCoords[0].x} ${riskCoords[0].y} ` + riskCoords.slice(1).map(c => `L ${c.x} ${c.y}`).join(' ');
        areaRisk = `${pathRisk} L ${riskCoords[riskCoords.length-1].x} ${height - padding} L ${riskCoords[0].x} ${height - padding} Z`;
    }
    
    // Build Grid SVGs
    let gridLines = '';
    const gridCount = 4;
    for (let i = 0; i <= gridCount; i++) {
        const y = padding + (i * (chartHeight / gridCount));
        const valLabel = Math.round(maxVal - (i * (maxVal / gridCount)));
        gridLines += `
            <line x1="${padding}" y1="${y}" x2="${width - padding}" y2="${y}" stroke="rgba(255,255,255,0.05)" stroke-width="1"/>
            <text x="${padding - 5}" y="${y + 4}" fill="var(--text-faded)" font-size="9" text-anchor="end">${valLabel}</text>
        `;
    }
    
    // Build labels
    let textLabels = '';
    logsToPlot.forEach((log, idx) => {
        const x = padding + (idx * stepX);
        const label = log.timestamp.split('T')[1].substring(0, 5); // HH:MM
        textLabels += `
            <text x="${x}" y="${height - padding + 18}" fill="var(--text-faded)" font-size="9" text-anchor="middle">${label}</text>
            <line x1="${x}" y1="${padding}" x2="${x}" y2="${height - padding}" stroke="rgba(255,255,255,0.02)" stroke-width="1"/>
        `;
    });
    
    const svgHTML = `
        <svg viewBox="0 0 ${width} ${height}" class="w-full h-full">
            <defs>
                <linearGradient id="grad-latency" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="var(--color-info)" stop-opacity="0.3"/>
                    <stop offset="100%" stop-color="var(--color-info)" stop-opacity="0.0"/>
                </linearGradient>
                <linearGradient id="grad-risk" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="var(--color-primary)" stop-opacity="0.3"/>
                    <stop offset="100%" stop-color="var(--color-primary)" stop-opacity="0.0"/>
                </linearGradient>
            </defs>
            
            <!-- Grid and helper axis lines -->
            ${gridLines}
            ${textLabels}
            
            <!-- Area Fills -->
            ${areaLatency ? `<path d="${areaLatency}" fill="url(#grad-latency)"/>` : ''}
            ${areaRisk ? `<path d="${areaRisk}" fill="url(#grad-risk)"/>` : ''}
            
            <!-- Path Lines -->
            ${pathLatency ? `<path d="${pathLatency}" fill="none" stroke="var(--color-info)" stroke-width="2.5" stroke-linecap="round"/>` : ''}
            ${pathRisk ? `<path d="${pathRisk}" fill="none" stroke="var(--color-primary)" stroke-width="2.5" stroke-linecap="round"/>` : ''}
            
            <!-- Nodes Circle elements -->
            ${latencyCoords.map((c, i) => `<circle cx="${c.x}" cy="${c.y}" r="4" fill="var(--color-info)" stroke="#0b0d13" stroke-width="1"/>`).join('')}
            ${riskCoords.map((c, i) => `<circle cx="${c.x}" cy="${c.y}" r="4" fill="var(--color-primary)" stroke="#0b0d13" stroke-width="1"/>`).join('')}
        </svg>
        <div class="chart-legend" style="margin-top: 5px;">
            <div class="legend-item"><span class="legend-color" style="background-color: var(--color-info);"></span><span class="legend-text">Proxy Latency (ms)</span></div>
            <div class="legend-item"><span class="legend-color" style="background-color: var(--color-primary);"></span><span class="legend-text">Mitigated Threat Index</span></div>
        </div>
    `;
    
    container.innerHTML = svgHTML;
}

function renderDonutChart() {
    const container = document.getElementById('donut-chart-container');
    container.innerHTML = '';
    
    // Group risk counts
    const counts = { "API Keys": 0, "PII": 0, "Intel Property": 0, "Financials": 0 };
    
    telemetryData.forEach(log => {
        log.detected_risks.forEach(risk => {
            if (risk.category === 'API Keys') counts['API Keys']++;
            else if (risk.category === 'PII') counts['PII']++;
            else if (risk.category === 'Intellectual Property') counts['Intel Property']++;
            else if (risk.category === 'Corporate Financials') counts['Financials']++;
        });
    });
    
    const totalRisks = Object.values(counts).reduce((a, b) => a + b, 0);
    
    if (totalRisks === 0) {
        container.innerHTML = `<span class="text-faded">No data available</span>`;
        return;
    }
    
    // Math configuration for SVG circle stroke dash offsets
    const radius = 50;
    const circumference = 2 * Math.PI * radius; // 314.16
    
    const categories = [
        { label: 'API Keys', count: counts['API Keys'], color: 'var(--color-primary)' },
        { label: 'PII Data', count: counts['PII'], color: 'var(--color-success)' },
        { label: 'Intel Property', count: counts['Intel Property'], color: 'var(--color-info)' },
        { label: 'Corp Secrets', count: counts['Financials'], color: 'var(--color-warn)' }
    ];
    
    let currentOffset = 0;
    let circleSVGs = '';
    
    categories.forEach(cat => {
        if (cat.count === 0) return;
        const share = cat.count / totalRisks;
        const dashArray = share * circumference;
        const dashOffset = currentOffset;
        
        circleSVGs += `
            <circle cx="60" cy="60" r="${radius}" 
                fill="transparent" 
                stroke="${cat.color}" 
                stroke-width="12" 
                stroke-dasharray="${dashArray} ${circumference - dashArray}" 
                stroke-dashoffset="-${dashOffset}" 
                class="donut-segment"
            />
        `;
        currentOffset += dashArray;
    });
    
    const svgHTML = `
        <div style="position: relative; width: 120px; height: 120px; margin: 0 auto;">
            <svg viewBox="0 0 120 120" class="donut-chart-svg" width="120" height="120">
                <circle cx="60" cy="60" r="${radius}" fill="transparent" stroke="rgba(255,255,255,0.03)" stroke-width="12"/>
                ${circleSVGs}
            </svg>
            <div style="position: absolute; top: 0; left: 0; width:100%; height:100%; display:flex; flex-direction:column; align-items:center; justify-content:center; text-align:center;">
                <span style="font-size: 1.15rem; font-weight:700;">${totalRisks}</span>
                <span style="font-size:0.68rem; color:var(--text-secondary); text-transform:uppercase;">Threats</span>
            </div>
        </div>
        <div class="chart-legend">
            ${categories.map(c => `
                <div class="legend-item">
                    <span class="legend-color" style="background-color: ${c.color};"></span>
                    <span class="legend-text">${c.label}</span>
                    <span class="legend-val">${c.count}</span>
                </div>
            `).join('')}
        </div>
    `;
    
    container.innerHTML = svgHTML;
}

// Render dynamic elements to Audit Trail table
function renderAuditTrailTable() {
    auditTbody.innerHTML = '';
    const query = auditSearchInput.value.toLowerCase().strip();
    
    // Filter telemetry
    const filtered = telemetryData.filter(log => {
        if (!query) return true;
        return log.id.toLowerCase().includes(query) ||
               log.source.toLowerCase().includes(query) ||
               log.destination.toLowerCase().includes(query) ||
               log.action_taken.toLowerCase().includes(query) ||
               log.detected_risks.some(r => r.type.toLowerCase().includes(query) || r.category.toLowerCase().includes(query));
    });
    
    if (filtered.length === 0) {
        auditTbody.innerHTML = `<tr><td colspan="7" style="text-align: center;" class="text-faded">No compliance alerts matched filter query.</td></tr>`;
        return;
    }
    
    filtered.forEach(log => {
        const row = document.createElement('tr');
        
        // Match appropriate action badge
        let badgeClass = 'badge-success';
        if (log.action_taken === 'Blocked') badgeClass = 'badge-error';
        else if (log.action_taken === 'Redacted') badgeClass = 'badge-warning';
        
        // Parse time format
        const date = new Date(log.timestamp);
        const timeFormatted = date.toLocaleTimeString() + ' (' + date.toLocaleDateString(undefined, {month:'short', day:'numeric'}) + ')';
        
        // Summarize match risk types
        const riskSummary = log.detected_risks.length > 0 
            ? log.detected_risks.map(r => r.type).join(', ') 
            : 'None (Safe Data)';
            
        row.innerHTML = `
            <td class="code-font">${timeFormatted}</td>
            <td>${log.source}</td>
            <td>${log.destination}</td>
            <td><span class="font-bold">${riskSummary}</span></td>
            <td><span class="badge ${badgeClass}">${log.action_taken}</span></td>
            <td class="code-font text-highlight">${log.latency_ms}ms</td>
            <td>
                <button class="btn btn-secondary btn-inspect" style="padding: 4px 10px; font-size: 0.75rem;" data-id="${log.id}">
                    <i class="fa-solid fa-expand"></i> Inspect
                </button>
            </td>
        `;
        
        // row click bindings to open detail modals
        row.addEventListener('click', (e) => {
            if (!e.target.closest('.btn-inspect')) {
                openIncidentModal(log.id);
            }
        });
        
        row.querySelector('.btn-inspect').addEventListener('click', (e) => {
            e.stopPropagation();
            openIncidentModal(log.id);
        });

        auditTbody.appendChild(row);
    });
}

// Modal inspection detailed window
function openIncidentModal(logId) {
    const log = telemetryData.find(l => l.id === logId);
    if (!log) return;
    
    document.getElementById('modal-id').innerText = log.id;
    document.getElementById('modal-time').innerText = new Date(log.timestamp).toLocaleString();
    document.getElementById('modal-source').innerText = log.source;
    document.getElementById('modal-latency').innerText = `${log.latency_ms}ms`;
    
    // Render threat list badges
    const badgesContainer = document.getElementById('modal-threats-container');
    badgesContainer.innerHTML = '';
    
    if (log.detected_risks.length === 0) {
        badgesContainer.innerHTML = `<span class="badge badge-success">Clean outbound request</span>`;
    } else {
        log.detected_risks.forEach(r => {
            const badge = document.createElement('span');
            badge.className = `badge ${r.action === 'Blocked' ? 'badge-error' : 'badge-warning'}`;
            badge.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> ${r.category} : ${r.type} (${r.action})`;
            badgesContainer.appendChild(badge);
        });
    }

    // Modal Diff Renderings
    // 1. Highlight Raw Prompt
    let highlightedRaw = escapeHTML(log.prompt_raw);
    log.detected_risks.forEach(r => {
        // Find evidence and highlight it
        const escapedEvidence = escapeHTML(r.evidence);
        highlightedRaw = highlightedRaw.replaceAll(escapedEvidence, `<span class="threat-highlight">${escapedEvidence}</span>`);
    });
    
    document.getElementById('modal-raw-prompt').innerHTML = highlightedRaw;

    // 2. Redacted prompt
    let formattedRedacted = escapeHTML(log.prompt_redacted);
    // Replace all redacted tags like [REDACTED_...] with neon orange labels
    formattedRedacted = formattedRedacted.replace(/(\[REDACTED_[A-Z_]+\])/g, '<span class="redact-highlight">$1</span>');
    formattedRedacted = formattedRedacted.replace(/(\[BLOCKED\])/g, '<span class="t-error font-bold">$1</span>');
    document.getElementById('modal-redacted-prompt').innerHTML = formattedRedacted;
    
    // Action Badge status
    const actionBadge = document.getElementById('modal-action-badge');
    actionBadge.innerText = log.action_taken;
    actionBadge.className = 'badge ' + (log.action_taken === 'Blocked' ? 'badge-error' : (log.action_taken === 'Redacted' ? 'badge-warning' : 'badge-success'));

    // LLM Response
    document.getElementById('modal-llm-response').innerText = log.llm_response;

    // Open Modal
    incidentModal.style.display = 'flex';
}

// Utility function to escape HTML
function escapeHTML(str) {
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#039;');
}

// Main Playground submission controller
async function executePlaygroundPrompt() {
    const text = playgroundPrompt.value.strip();
    if (!text) {
        showToast('Please type or select a prompt first!', 'error');
        return;
    }

    // Toggle scanning animation status
    runGuardrailBtn.disabled = true;
    scanStatus.innerText = 'Analyzing Outbound Prompt...';
    scanStatus.className = 'scan-status-active';
    scanningIndicator.style.display = 'inline-block';
    
    // Reset output viewers
    rawOutput.innerText = 'Proxy intercepts packet, analyzing buffer data...';
    sanitizedOutput.innerText = 'Waiting for proxy to scan contents...';
    responseOutput.innerText = 'Waiting for proxy routing...';

    // Step-by-step pipeline highlights
    try {
        logToTerminal(`Outbound packet intercepted from local sandbox context.`);
        stepIntercept.className = 'pipeline-step active';
        
        await sleep(500);
        stepIntercept.className = 'pipeline-step success';
        stepNim.className = 'pipeline-step active';
        logToTerminal(`Scanning buffer with NVIDIA NIM safety guardrails.`);
        
        await sleep(800);
        stepNim.className = 'pipeline-step success';
        stepRedact.className = 'pipeline-step active';
        logToTerminal(`Parsing matching token rules and applying replacement matrices.`);
        
        await sleep(500);
        
        // POST to Proxy Endpoint
        const res = await fetch('/api/playground/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                messages: [{ role: 'user', content: text }]
            })
        });
        
        const data = await res.json();
        const log = data.guardrail_telemetry;
        
        stepRedact.className = 'pipeline-step success';
        scanStatus.innerText = 'Scan Completed';
        scanStatus.className = 'scan-status-idle';
        scanningIndicator.style.display = 'none';
        
        // Display results in Playground UI
        // 1. Highlight Raw Prompt
        let highlightedRaw = escapeHTML(log.prompt_raw);
        log.detected_risks.forEach(r => {
            const escapedEvidence = escapeHTML(r.evidence);
            highlightedRaw = highlightedRaw.replaceAll(escapedEvidence, `<span class="threat-highlight">${escapedEvidence}</span>`);
        });
        rawOutput.innerHTML = highlightedRaw;
        
        const rawBadge = document.getElementById('raw-badge');
        if (log.detected_risks.length > 0) {
            rawBadge.style.display = 'inline-block';
            rawBadge.innerText = `${log.detected_risks.length} Risk(s)`;
        } else {
            rawBadge.style.display = 'none';
        }
        
        // 2. Redacted prompt output
        let formattedRedacted = escapeHTML(log.prompt_redacted);
        formattedRedacted = formattedRedacted.replace(/(\[REDACTED_[A-Z_]+\])/g, '<span class="redact-highlight">$1</span>');
        formattedRedacted = formattedRedacted.replace(/(\[BLOCKED\])/g, '<span class="t-error font-bold">$1</span>');
        sanitizedOutput.innerHTML = formattedRedacted;
        document.getElementById('sanitized-badge').style.display = 'inline-block';

        // 3. Response output
        responseOutput.innerText = log.llm_response;

        // Print final terminal outputs
        if (log.action_taken === 'Blocked') {
            logToTerminal(`Outbound Prompt Blocked! Found restricted content: ${log.detected_risks.map(r => r.type).join(', ')}`, 'error');
            showToast('Prompt BLOCKED by GuardRail AI policy!', 'error');
        } else if (log.action_taken === 'Redacted') {
            logToTerminal(`Prompt sanitized. Redacted ${log.detected_risks.length} tokens. Forwarding packet to destination.`, 'warn');
            logToTerminal(`Completions returned successfully from target endpoint (latency: ${log.latency_ms}ms).`, 'success');
            showToast(`Redacted ${log.detected_risks.length} vulnerabilities! Forwarded safely.`);
        } else {
            logToTerminal(`Packet passed security scanner cleanly. Routing to destination.`, 'success');
            logToTerminal(`Completions returned successfully from target endpoint (latency: ${log.latency_ms}ms).`, 'success');
            showToast(`Prompt transmitted safely.`);
        }

        // Auto Sync telemetry data to refresh Dashboard cards & tables
        await syncTelemetry();

    } catch (err) {
        console.error(err);
        scanStatus.innerText = 'Scanning Error';
        scanStatus.className = 'scan-status-idle';
        scanningIndicator.style.display = 'none';
        
        stepIntercept.className = 'pipeline-step';
        stepNim.className = 'pipeline-step';
        stepRedact.className = 'pipeline-step';
        
        rawOutput.innerText = 'Analysis failed due to server daemon timeout.';
        logToTerminal('Proxy socket pipeline broken. Check server.py standard output.', 'warn');
        showToast('Communication link broken.', 'error');
    } finally {
        runGuardrailBtn.disabled = false;
    }
}

// Helper to delay animations
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Extends String prototype for clean white space trim
String.prototype.strip = function() {
    return this.replace(/^\s+|\s+$/g, '');
};

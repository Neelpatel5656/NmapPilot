/* ═══════════════════════════════════════════════════════════════
   NmapPilot AI — Client-Side Application (v3 — Fixed)
   ═══════════════════════════════════════════════════════════════ */

// ── State ──
let socket = null;
let isWaitingForAI = false;
let currentStreamMsg = null;
let currentStreamRaw = '';
let scanHistory = [];
let liveProgressEl = null;
let aiTimeoutTimer = null;

// ── Initialize ──
document.addEventListener('DOMContentLoaded', () => {
    initSocket();
    initNavigation();
    initChatInput();
    checkStatus();
});

// ═══════════════════════════════════════════════════════════════
//  WebSocket
// ═══════════════════════════════════════════════════════════════

function initSocket() {
    socket = io({ transports: ['polling'] });

    socket.on('connect', () => updateAIStatus('connected', 'AI Online'));
    socket.on('disconnect', () => updateAIStatus('disconnected', 'Disconnected'));

    socket.on('connected', (data) => {
        updateAIStatus(data.ai_available ? 'connected' : 'disconnected',
                       data.ai_available ? data.model : 'Ollama offline');
    });

    socket.on('scan_progress', (data) => {
        updateScanProgress(data);
        updateLiveProgressCard(data);
    });

    socket.on('scan_output', (data) => {
        appendTerminal(data.line);
        appendLiveOutput(data.line);
    });

    socket.on('ai_response', (data) => handleAIStream(data));

    socket.on('scan_detected', (data) => {
        if (data.target) {
            insertLiveProgressCard(data.target);
            showToast(`🚀 Scan launched: ${data.target}`, 'info');
        }
    });

    // Reconnect safety
    socket.on('reconnect', () => {
        resetWaitingState();
        updateAIStatus('connected', 'Reconnected');
    });
}

function updateAIStatus(state, text) {
    const dot = document.getElementById('status-dot');
    const txt = document.getElementById('status-text');
    dot.className = 'status-dot ' + state;
    txt.textContent = text;
}

// ═══════════════════════════════════════════════════════════════
//  Navigation
// ═══════════════════════════════════════════════════════════════

function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(btn => {
        btn.addEventListener('click', () => switchPanel(btn.dataset.panel));
    });
}

function switchPanel(panelId) {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const navBtn = document.querySelector(`[data-panel="${panelId}"]`);
    if (navBtn) navBtn.classList.add('active');
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    const panel = document.getElementById(`panel-${panelId}`);
    if (panel) panel.classList.add('active');
}

// ═══════════════════════════════════════════════════════════════
//  Chat — Send Message
// ═══════════════════════════════════════════════════════════════

function initChatInput() {
    const input = document.getElementById('chat-input');
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });
    input.addEventListener('input', () => {
        input.style.height = 'auto';
        input.style.height = Math.min(input.scrollHeight, 110) + 'px';
    });
}

function sendMessage() {
    const input = document.getElementById('chat-input');
    const message = input.value.trim();
    if (!message || isWaitingForAI) return;

    addMessage('user', message);
    input.value = '';
    input.style.height = 'auto';

    isWaitingForAI = true;
    document.getElementById('send-btn').disabled = true;
    showTypingIndicator();

    // Safety timeout — if nothing comes back in 60s, unlock the UI
    clearTimeout(aiTimeoutTimer);
    aiTimeoutTimer = setTimeout(() => {
        if (isWaitingForAI) {
            resetWaitingState();
            addMessage('ai', '⚠️ The AI took too long to respond. The model may still be loading — please try again.');
        }
    }, 60000);

    // Send via SocketIO — streaming, no HTTP timeout
    socket.emit('chat_message', { message });
}

function resetWaitingState() {
    clearTimeout(aiTimeoutTimer);
    removeTypingIndicator();
    isWaitingForAI = false;
    currentStreamMsg = null;
    currentStreamRaw = '';
    document.getElementById('send-btn').disabled = false;
}

// ═══════════════════════════════════════════════════════════════
//  Chat — Messages
// ═══════════════════════════════════════════════════════════════

function addMessage(role, content, isMarkdown = false) {
    const messages = document.getElementById('chat-messages');
    const div = document.createElement('div');
    div.className = `message ${role}-message`;

    const avatar = role === 'ai' ? '🤖' : '👤';
    let rendered = isMarkdown ? renderMarkdown(content) : escapeHtml(content);

    div.innerHTML = `
        <div class="msg-row ${role === 'user' ? 'msg-row-right' : ''}">
            <div class="message-avatar">${avatar}</div>
            <div class="message-bubble">${rendered}</div>
        </div>
    `;

    messages.appendChild(div);
    scrollChatToBottom();
}

function renderMarkdown(text) {
    if (typeof marked !== 'undefined') {
        try { return marked.parse(text); } catch(e) { /* fall through */ }
    }
    return escapeHtml(text);
}

// Clean AI response — strip JSON scan blocks the AI outputs
function cleanAIResponse(text) {
    // Remove ```json {...} ``` blocks that contain "action": "scan"
    let cleaned = text.replace(/```json\s*\n?\s*\{[^`]*"action"\s*:\s*"scan"[^`]*\}\s*\n?\s*```/gs, '');
    // Remove bare JSON objects with scan action
    cleaned = cleaned.replace(/\{[^{}]*"action"\s*:\s*"scan"[^{}]*\}/g, '');
    // Clean up leftover extra blank lines
    cleaned = cleaned.replace(/\n{3,}/g, '\n\n').trim();
    return cleaned || text;
}

// ═══════════════════════════════════════════════════════════════
//  Chat — Streaming AI Response
// ═══════════════════════════════════════════════════════════════

function handleAIStream(data) {
    // First token — create the message container
    if (!currentStreamMsg && !data.done) {
        removeTypingIndicator();
        clearTimeout(aiTimeoutTimer);

        const messages = document.getElementById('chat-messages');
        currentStreamMsg = document.createElement('div');
        currentStreamMsg.className = 'message ai-message';
        currentStreamMsg.innerHTML = `
            <div class="msg-row">
                <div class="message-avatar">🤖</div>
                <div class="message-bubble stream-bubble"></div>
            </div>
        `;
        messages.appendChild(currentStreamMsg);
        currentStreamRaw = '';
    }

    // Append token
    if (data.token) {
        currentStreamRaw += data.token;
    }

    // Update rendered content
    if (currentStreamMsg) {
        const bubble = currentStreamMsg.querySelector('.stream-bubble');
        if (bubble) {
            const cleaned = cleanAIResponse(currentStreamRaw);
            bubble.innerHTML = renderMarkdown(cleaned);
        }
        scrollChatToBottom();
    }

    // Done — finalize
    if (data.done) {
        currentStreamMsg = null;
        currentStreamRaw = '';
        resetWaitingState();
    }
}

// ═══════════════════════════════════════════════════════════════
//  Typing Indicator
// ═══════════════════════════════════════════════════════════════

function showTypingIndicator() {
    removeTypingIndicator();
    const messages = document.getElementById('chat-messages');
    const div = document.createElement('div');
    div.className = 'message ai-message';
    div.id = 'typing-indicator';
    div.innerHTML = `
        <div class="msg-row">
            <div class="message-avatar">🤖</div>
            <div class="message-bubble">
                <div class="typing-indicator">
                    <div class="typing-dots">
                        <div class="typing-dot"></div>
                        <div class="typing-dot"></div>
                        <div class="typing-dot"></div>
                    </div>
                    <span class="typing-label">AI is thinking...</span>
                </div>
            </div>
        </div>
    `;
    messages.appendChild(div);
    scrollChatToBottom();
}

function removeTypingIndicator() {
    const el = document.getElementById('typing-indicator');
    if (el) el.remove();
}

function scrollChatToBottom() {
    const container = document.getElementById('chat-container');
    requestAnimationFrame(() => { container.scrollTop = container.scrollHeight; });
}

function useExample(btn) {
    const input = document.getElementById('chat-input');
    let text = btn.textContent.trim().replace(/^[^\w"]*/, '').trim().replace(/^[""]|[""]$/g, '');
    input.value = text;
    input.focus();
}

function resetChat() {
    fetch('/api/ai/reset', { method: 'POST' }).then(() => {
        const messages = document.getElementById('chat-messages');
        const welcome = messages.querySelector('.welcome-msg');
        messages.innerHTML = '';
        if (welcome) messages.appendChild(welcome);
        liveProgressEl = null;
        resetWaitingState();
        showToast('Conversation reset', 'info');
    });
}


// ═══════════════════════════════════════════════════════════════
//  LIVE PROGRESS CARD
// ═══════════════════════════════════════════════════════════════

function insertLiveProgressCard(target) {
    if (liveProgressEl) liveProgressEl.remove();
    const messages = document.getElementById('chat-messages');
    const card = document.createElement('div');
    card.className = 'live-progress-card';
    card.id = 'live-progress-card';
    card.innerHTML = `
        <div class="live-progress-header">
            <div class="live-progress-title">
                <div class="pulse-ring"></div>
                <span>Live Scan</span>
            </div>
            <span class="live-badge scanning" id="live-badge">INITIALIZING</span>
        </div>
        <div class="live-progress-body">
            <div class="live-target" id="live-target">${escapeHtml(target)}</div>
            <div class="live-bar-track">
                <div class="live-bar-fill" id="live-bar" style="width: 2%"></div>
            </div>
            <div class="live-stats">
                <span class="live-percent" id="live-percent">0%</span>
                <span class="live-task" id="live-task">Validating target...</span>
            </div>
            <div class="live-metrics" id="live-metrics">
                <div class="live-metric"><span class="live-metric-val" id="lm-ports">—</span><span class="live-metric-label">ports</span></div>
                <div class="live-metric"><span class="live-metric-val" id="lm-svcs">—</span><span class="live-metric-label">services</span></div>
                <div class="live-metric"><span class="live-metric-val" id="lm-vulns">—</span><span class="live-metric-label">vulns</span></div>
                <div class="live-metric"><span class="live-metric-val" id="lm-exploits">—</span><span class="live-metric-label">exploits</span></div>
            </div>
            <div class="live-output-lines" id="live-output"></div>
        </div>
    `;
    messages.appendChild(card);
    liveProgressEl = card;
    scrollChatToBottom();
}

function updateLiveProgressCard(data) {
    if (!liveProgressEl) return;
    const badge = document.getElementById('live-badge');
    if (badge) { badge.textContent = data.status.toUpperCase(); badge.className = 'live-badge ' + data.status; }

    const targetEl = document.getElementById('live-target');
    if (targetEl && data.target_info) targetEl.textContent = data.target_info.hostname || data.target_info.ip;

    const bar = document.getElementById('live-bar');
    if (bar) bar.style.width = Math.max(2, data.progress) + '%';

    const pct = document.getElementById('live-percent');
    if (pct) pct.textContent = Math.round(data.progress) + '%';

    const task = document.getElementById('live-task');
    if (task) task.textContent = data.current_task || '';

    if (data.scan_result) {
        const p = document.getElementById('lm-ports'); if (p) p.textContent = data.scan_result.open_port_count || 0;
        const s = document.getElementById('lm-svcs'); if (s) s.textContent = (data.scan_result.all_services || []).length;
    }
    const v = document.getElementById('lm-vulns'); if (v) v.textContent = (data.vuln_findings || []).length;
    const e = document.getElementById('lm-exploits'); if (e) e.textContent = (data.exploits || []).length;

    scrollChatToBottom();

    if (data.status === 'complete') finalizeLiveCard(data, false);
    else if (data.status === 'error') finalizeLiveCard(data, true);
}

function appendLiveOutput(line) {
    if (!liveProgressEl) return;
    const output = document.getElementById('live-output');
    if (!output) return;
    const div = document.createElement('div');
    div.className = 'live-output-line';
    if (line.includes('✔')) div.className += ' ok';
    else if (line.includes('⚠')) div.className += ' warn';
    else if (line.includes('✘') || line.includes('Error')) div.className += ' err';
    else if (line.includes('⟳') || line.includes('Running')) div.className += ' scan';
    div.textContent = line;
    output.appendChild(div);
    while (output.children.length > 6) output.removeChild(output.firstChild);
    output.scrollTop = output.scrollHeight;
}

function finalizeLiveCard(data, isError) {
    if (!liveProgressEl) return;
    const pulse = liveProgressEl.querySelector('.pulse-ring');
    if (pulse) pulse.style.animation = 'none';

    if (!isError && data.scan_result) {
        const ports = data.scan_result.open_port_count || 0;
        const vulns = (data.vuln_findings || []).length;
        const exploits = (data.exploits || []).length;
        const target = data.target_info ? (data.target_info.hostname || data.target_info.ip) : '';
        setTimeout(() => {
            addMessage('ai', `**Scan complete: ${escapeHtml(target)}** — ` +
                `${ports} open ports, ${vulns} vulns, ${exploits} exploits found.\n\n` +
                `Go to **Results** tab for details, or ask me to analyze the findings.`, true);
            showToast('✔ Scan complete!', 'success');
        }, 500);
        addToHistory(target, data);
    }
    if (isError) {
        setTimeout(() => {
            addMessage('ai', `⚠️ **Scan Error:** ${data.error_message || 'Unknown error'}`, true);
        }, 300);
    }
    liveProgressEl = null;
}


// ═══════════════════════════════════════════════════════════════
//  Scan Progress (Dashboard)
// ═══════════════════════════════════════════════════════════════

function updateScanProgress(data) {
    const badge = document.getElementById('scan-status-badge');
    badge.textContent = data.status.toUpperCase();
    badge.className = 'status-badge ' + data.status;

    const targetDisplay = document.getElementById('target-display');
    if (data.target_info) {
        targetDisplay.innerHTML = `
            <div class="target-value">${escapeHtml(data.target_info.hostname || data.target_info.ip)}</div>
            <div class="target-label">${escapeHtml(data.target_info.ip || '')}</div>
        `;
    }

    const pc = document.getElementById('progress-container');
    if (data.status !== 'idle') {
        pc.style.display = 'block';
        document.getElementById('progress-fill').style.width = data.progress + '%';
        document.getElementById('progress-text').textContent = Math.round(data.progress) + '%';
        document.getElementById('progress-task').textContent = data.current_task || '';
    }

    if (data.scan_result) {
        document.getElementById('stat-ports').textContent = data.scan_result.open_port_count || 0;
        document.getElementById('stat-services').textContent = (data.scan_result.all_services || []).length;
    }
    document.getElementById('stat-vulns').textContent = (data.vuln_findings || []).length;
    document.getElementById('stat-exploits').textContent = (data.exploits || []).length;

    if (data.status === 'complete') renderResults(data);
}


// ═══════════════════════════════════════════════════════════════
//  Results Rendering
// ═══════════════════════════════════════════════════════════════

function renderResults(data) {
    document.getElementById('results-empty').style.display = 'none';
    if (data.scan_result && data.scan_result.all_ports) {
        const openPorts = data.scan_result.all_ports.filter(p => p.state === 'open');
        if (openPorts.length > 0) {
            const tbody = document.getElementById('ports-tbody');
            tbody.innerHTML = '';
            openPorts.sort((a, b) => parseInt(a.port_id) - parseInt(b.port_id)).forEach(port => {
                const svc = port.service || {};
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="port-num">${escapeHtml(port.port_id)}/${escapeHtml(port.protocol)}</td>
                    <td class="state-open">${escapeHtml(port.state)}</td>
                    <td class="service-name">${escapeHtml(svc.name || '—')}</td>
                    <td class="product-name">${escapeHtml(svc.product || '—')}</td>
                    <td>${escapeHtml(svc.version || '—')}</td>
                `;
                tbody.appendChild(tr);
            });
            document.getElementById('ports-section').style.display = 'block';
        }
    }
    if (data.vuln_findings && data.vuln_findings.length > 0) {
        renderFindings(data.vuln_findings, 'vulns');
        document.getElementById('vulns-section').style.display = 'block';
    }
    if (data.exploits && data.exploits.length > 0) {
        renderExploits(data.exploits);
        document.getElementById('exploits-section').style.display = 'block';
    }
}

function renderFindings(findings, prefix) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
    const summary = document.getElementById('severity-summary');
    summary.innerHTML = Object.entries(counts).filter(([_, v]) => v > 0)
        .map(([s, c]) => `<span class="severity-badge ${s.toLowerCase()}">${s}: ${c}</span>`).join('');
    const list = document.getElementById(`${prefix}-list`);
    list.innerHTML = '';
    findings.forEach(f => {
        const card = document.createElement('div');
        card.className = `finding-card severity-${f.severity.toLowerCase()}`;
        card.innerHTML = `
            <div class="finding-header" onclick="toggleFinding(this)">
                <span class="finding-severity ${f.severity.toLowerCase()}">${escapeHtml(f.severity)}</span>
                <span class="finding-title">${escapeHtml(f.title)}</span>
                ${f.port ? `<span class="finding-port">:${escapeHtml(f.port)}</span>` : ''}
                <span class="finding-toggle">▼</span>
            </div>
            <div class="finding-details">${escapeHtml(f.details || 'No details')}
${f.cve && f.cve.length ? f.cve.map(c => `<span class="cve-tag">${escapeHtml(c)}</span>`).join('') : ''}</div>
        `;
        list.appendChild(card);
    });
}

function renderExploits(exploits) {
    const list = document.getElementById('exploits-list');
    list.innerHTML = '';
    exploits.forEach(exp => {
        const card = document.createElement('div');
        card.className = 'finding-card severity-high';
        card.innerHTML = `
            <div class="finding-header" onclick="toggleFinding(this)">
                <span class="finding-severity high">EXPLOIT</span>
                <span class="finding-title">${escapeHtml(exp.title)}</span>
                ${exp.port ? `<span class="finding-port">:${escapeHtml(exp.port)}</span>` : ''}
                <span class="finding-toggle">▼</span>
            </div>
            <div class="finding-details">Service: ${escapeHtml(exp.service || '—')} | Type: ${escapeHtml(exp.exploit_type || '—')} | Platform: ${escapeHtml(exp.platform || '—')}\nPath: ${escapeHtml(exp.path || '—')}</div>
        `;
        list.appendChild(card);
    });
}

function toggleFinding(header) { header.parentElement.classList.toggle('expanded'); }


// ═══════════════════════════════════════════════════════════════
//  Manual / Quick Scan
// ═══════════════════════════════════════════════════════════════

function startManualScan() {
    const target = document.getElementById('manual-target').value.trim();
    if (!target) { showToast('Enter a target first', 'warning'); return; }
    const data = {
        target,
        max_phase: parseInt(document.getElementById('manual-phase').value),
        no_vuln: document.getElementById('manual-no-vuln').checked,
        no_dos: document.getElementById('manual-no-dos').checked,
    };
    document.getElementById('manual-scan-btn').disabled = true;
    fetch('/api/scan/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
    .then(r => r.json()).then(result => {
        document.getElementById('manual-scan-btn').disabled = false;
        if (result.error) showToast(result.error, 'error');
        else { showToast(`🚀 Scan: ${target}`, 'success'); switchPanel('chat'); insertLiveProgressCard(target); }
    }).catch(e => { document.getElementById('manual-scan-btn').disabled = false; showToast(e.message, 'error'); });
}

function quickScan(type) {
    const target = prompt('Enter target IP or hostname:');
    if (!target) return;
    const phaseMap = { quick: 1, aggressive: 3, comprehensive: 4 };
    fetch('/api/scan/start', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim(), max_phase: phaseMap[type] || 2 }) })
    .then(r => r.json()).then(result => {
        if (result.error) showToast(result.error, 'error');
        else { showToast(`🚀 ${type} scan: ${target}`, 'success'); switchPanel('chat'); insertLiveProgressCard(target.trim()); }
    }).catch(e => showToast(e.message, 'error'));
}


// ═══════════════════════════════════════════════════════════════
//  AI Analysis
// ═══════════════════════════════════════════════════════════════

function analyzeResults() {
    const btn = document.getElementById('btn-analyze');
    btn.disabled = true; btn.innerHTML = '<span>⏳</span> Analyzing...';
    fetch('/api/analyze', { method: 'POST' }).then(r => r.json()).then(data => {
        btn.disabled = false; btn.innerHTML = '<span>🤖</span> Analyze';
        if (data.error) { showToast(data.error, 'error'); return; }
        const section = document.getElementById('ai-analysis-section');
        const content = document.getElementById('ai-analysis-content');
        content.innerHTML = renderMarkdown(data.analysis || 'No analysis');
        section.style.display = 'block';
        section.scrollIntoView({ behavior: 'smooth' });
        showToast('AI analysis ready', 'success');
    }).catch(e => { btn.disabled = false; btn.innerHTML = '<span>🤖</span> Analyze'; showToast(e.message, 'error'); });
}


// ═══════════════════════════════════════════════════════════════
//  Terminal / History / Status / Toast / Utility
// ═══════════════════════════════════════════════════════════════

function appendTerminal(line) {
    const t = document.getElementById('terminal-output');
    const div = document.createElement('div');
    div.className = 'terminal-line';
    if (line.includes('✔')) div.className += ' success';
    else if (line.includes('⚠')) div.className += ' warning';
    else if (line.includes('✘') || line.includes('Error')) div.className += ' error';
    else if (line.includes('⟳')) div.className += ' system';
    div.textContent = line;
    t.appendChild(div); t.scrollTop = t.scrollHeight;
}

function clearTerminal() { document.getElementById('terminal-output').innerHTML = '<div class="terminal-line system">Terminal cleared</div>'; }

function addToHistory(target, data) {
    scanHistory.unshift({ target, time: new Date().toLocaleTimeString(), data });
    const c = document.getElementById('scan-history'); c.innerHTML = '';
    scanHistory.slice(0, 10).forEach(h => {
        const div = document.createElement('div'); div.className = 'history-item';
        div.innerHTML = `<div class="history-target">${escapeHtml(h.target)}</div><div class="history-time">${h.time}</div>`;
        div.onclick = () => { renderResults(h.data); switchPanel('results'); };
        c.appendChild(div);
    });
}

function checkStatus() {
    fetch('/api/status').then(r => r.json()).then(d => {
        updateAIStatus(d.ai_available ? 'connected' : 'disconnected', d.ai_available ? d.model : 'Ollama offline');
    }).catch(() => updateAIStatus('disconnected', 'Server offline'));
}

function showToast(message, type = 'info') {
    const c = document.getElementById('toast-container');
    const t = document.createElement('div'); t.className = `toast ${type}`; t.textContent = message;
    c.appendChild(t);
    setTimeout(() => { t.style.animation = 'toast-out 0.3s forwards'; setTimeout(() => t.remove(), 300); }, 4000);
}

function escapeHtml(str) {
    if (!str) return '';
    const d = document.createElement('div'); d.textContent = String(str); return d.innerHTML;
}

/* ═══════════════════════════════════════════════════════════════
   NmapPilot AI — Client-Side Application (v5 — Reports + Mobile)
   ═══════════════════════════════════════════════════════════════ */

// ── State ──
let socket = null;
let isWaitingForAI = false;
let currentStreamMsg = null;
let currentStreamRaw = '';
let aiTimeoutTimer = null;
let commandRunning = false;
let currentCmdOutput = null;
let lastCmdData = null;  // Store last completed command data for reports

// ── Initialize ──
document.addEventListener('DOMContentLoaded', () => {
    initSocket();
    initNavigation();
    initChatInput();
    initMobileMenu();
    checkStatus();
    loadSettings();
});

// ═══════════════════════════════════════════════════════════════
//  WebSocket
// ═══════════════════════════════════════════════════════════════

function initSocket() {
    socket = io({ transports: ['polling'] });

    socket.on('connect', () => updateAIStatus('connected', 'Connected'));
    socket.on('disconnect', () => updateAIStatus('disconnected', 'Disconnected'));

    socket.on('connected', (data) => {
        updateAIStatus(data.ai_available ? 'connected' : 'disconnected',
                       data.ai_available ? data.model : 'No AI configured');
        if (data.status) updateStatusText(data.status);
    });

    socket.on('ai_response', (data) => handleAIStream(data));

    socket.on('status_update', (data) => {
        updateAIStatus(data.backend !== 'none' ? 'connected' : 'disconnected',
                       data.model || 'No AI');
        updateStatusText(data.status || '');
    });

    // Command execution events
    socket.on('command_started', (data) => {
        commandRunning = true;
        appendTerminal(`\n▶ Running: ${data.cmd}`, 'system');
        if (currentCmdOutput) {
            const badge = currentCmdOutput.querySelector('.cmd-exec-badge');
            if (badge) { badge.textContent = 'RUNNING'; badge.className = 'cmd-exec-badge running'; }
        }
    });

    socket.on('command_output', (data) => {
        appendTerminal(data.line);
        appendCmdOutputLine(data.line);
    });

    socket.on('command_complete', (data) => {
        commandRunning = false;
        lastCmdData = data;
        const status = data.exit_code === 0 ? 'COMPLETE' : `EXIT: ${data.exit_code}`;
        appendTerminal(`✔ Command finished (${status})`, 'success');

        if (currentCmdOutput) {
            const badge = currentCmdOutput.querySelector('.cmd-exec-badge');
            if (badge) {
                badge.textContent = status;
                badge.className = 'cmd-exec-badge ' + (data.exit_code === 0 ? 'complete' : 'error');
            }
            const stopBtn = currentCmdOutput.querySelector('.cmd-stop-btn');
            if (stopBtn) stopBtn.style.display = 'none';

            // Show report actions
            showReportActions(currentCmdOutput, data);
        }
        currentCmdOutput = null;
    });

    socket.on('command_error', (data) => {
        commandRunning = false;
        appendTerminal(`✘ Error: ${data.error}`, 'error');
        showToast(data.error, 'error');
        if (currentCmdOutput) {
            const badge = currentCmdOutput.querySelector('.cmd-exec-badge');
            if (badge) { badge.textContent = 'ERROR'; badge.className = 'cmd-exec-badge error'; }
        }
        currentCmdOutput = null;
    });

    socket.on('reconnect', () => {
        resetWaitingState();
        updateAIStatus('connected', 'Reconnected');
    });
}

function updateAIStatus(state, text) {
    const dot = document.getElementById('status-dot');
    const txt = document.getElementById('status-text');
    if (dot) dot.className = 'status-dot ' + state;
    if (txt) txt.textContent = text;
}

function updateStatusText(text) {
    const el = document.getElementById('status-detail');
    if (el) el.textContent = text;
}

// ═══════════════════════════════════════════════════════════════
//  Navigation + Mobile Menu
// ═══════════════════════════════════════════════════════════════

function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(btn => {
        btn.addEventListener('click', () => {
            switchPanel(btn.dataset.panel);
            // Close mobile sidebar
            document.getElementById('sidebar').classList.remove('mobile-open');
            document.getElementById('sidebar-overlay').classList.remove('active');
        });
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

function initMobileMenu() {
    const menuBtn = document.getElementById('mobile-menu-btn');
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');

    if (menuBtn) {
        menuBtn.addEventListener('click', () => {
            sidebar.classList.toggle('mobile-open');
            overlay.classList.toggle('active');
        });
    }
    if (overlay) {
        overlay.addEventListener('click', () => {
            sidebar.classList.remove('mobile-open');
            overlay.classList.remove('active');
        });
    }
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

    clearTimeout(aiTimeoutTimer);
    aiTimeoutTimer = setTimeout(() => {
        if (isWaitingForAI) {
            resetWaitingState();
            addMessage('ai', '⚠️ The AI took too long to respond. Try again or check Settings.', true);
        }
    }, 120000);

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
    return escapeHtml(text).replace(/\n/g, '<br>');
}

// ═══════════════════════════════════════════════════════════════
//  Chat — AI Streaming + Command Card Extraction
// ═══════════════════════════════════════════════════════════════

function handleAIStream(data) {
    if (!currentStreamMsg && !data.done) {
        removeTypingIndicator();
        clearTimeout(aiTimeoutTimer);

        const messages = document.getElementById('chat-messages');
        currentStreamMsg = document.createElement('div');
        currentStreamMsg.className = 'message ai-message';
        currentStreamMsg.innerHTML = `
            <div class="msg-row">
                <div class="message-avatar">🤖</div>
                <div class="message-content-wrap">
                    <div class="message-bubble stream-bubble"></div>
                    <div class="command-cards-container"></div>
                </div>
            </div>
        `;
        messages.appendChild(currentStreamMsg);
        currentStreamRaw = '';
    }

    if (data.token) {
        currentStreamRaw += data.token;
    }

    if (currentStreamMsg) {
        const bubble = currentStreamMsg.querySelector('.stream-bubble');
        if (bubble) {
            const cleaned = stripCommandJSON(currentStreamRaw);
            bubble.innerHTML = renderMarkdown(cleaned);
        }
        scrollChatToBottom();
    }

    if (data.done) {
        if (currentStreamMsg) {
            const commands = extractCommands(currentStreamRaw);
            if (commands.length > 0) {
                const container = currentStreamMsg.querySelector('.command-cards-container');
                if (container) {
                    container.innerHTML = commands.map((c, i) => buildCommandCard(c, i)).join('');
                }
            }
            const bubble = currentStreamMsg.querySelector('.stream-bubble');
            if (bubble) {
                const cleaned = stripCommandJSON(currentStreamRaw);
                bubble.innerHTML = renderMarkdown(cleaned);
            }
        }
        currentStreamMsg = null;
        currentStreamRaw = '';
        resetWaitingState();
    }
}

function extractCommands(text) {
    const commands = [];
    const jsonBlocks = text.match(/```json\s*\n?([\s\S]*?)\n?\s*```/g);
    if (jsonBlocks) {
        for (const block of jsonBlocks) {
            const inner = block.replace(/```json\s*\n?/, '').replace(/\n?\s*```/, '');
            try {
                const parsed = JSON.parse(inner);
                if (parsed.commands && Array.isArray(parsed.commands)) {
                    for (const cmd of parsed.commands) {
                        if (cmd.cmd) {
                            commands.push({ cmd: cmd.cmd, description: cmd.description || '' });
                        }
                    }
                }
            } catch (e) { /* skip */ }
        }
    }
    return commands;
}

function stripCommandJSON(text) {
    let cleaned = text.replace(/```json\s*\n?\s*\{[\s\S]*?"commands"[\s\S]*?\}\s*\n?\s*```/g, '');
    cleaned = cleaned.replace(/\n{3,}/g, '\n\n').trim();
    return cleaned || text;
}

function buildCommandCard(cmd, index) {
    const escapedCmd = escapeHtml(cmd.cmd);
    const escapedDesc = escapeHtml(cmd.description);
    return `
        <div class="command-card" id="cmd-card-${index}">
            <div class="command-card-header">
                <span class="command-card-icon">⚡</span>
                <span class="command-card-desc">${escapedDesc}</span>
            </div>
            <div class="command-card-body">
                <code class="command-text">${escapedCmd}</code>
            </div>
            <div class="command-card-actions">
                <button class="cmd-run-btn" onclick="runCommand('${escapedCmd.replace(/'/g, "\\'")}', this)">
                    <span>▶</span> Run
                </button>
                <button class="cmd-copy-btn" onclick="copyCommand('${escapedCmd.replace(/'/g, "\\'")}')">
                    <span>📋</span> Copy
                </button>
            </div>
        </div>
    `;
}

function runCommand(cmd, btn) {
    if (commandRunning) {
        showToast('A command is already running', 'warning');
        return;
    }

    const card = btn.closest('.command-card');
    let outputArea = card.querySelector('.cmd-output-area');
    if (!outputArea) {
        outputArea = document.createElement('div');
        outputArea.className = 'cmd-output-area';
        outputArea.innerHTML = `
            <div class="cmd-output-header">
                <span class="cmd-exec-badge running">RUNNING</span>
                <button class="cmd-stop-btn" onclick="stopCommand()">⬜ Stop</button>
            </div>
            <div class="cmd-output-lines"></div>
        `;
        card.appendChild(outputArea);
    } else {
        outputArea.querySelector('.cmd-output-lines').innerHTML = '';
        const badge = outputArea.querySelector('.cmd-exec-badge');
        if (badge) { badge.textContent = 'RUNNING'; badge.className = 'cmd-exec-badge running'; }
        const stopBtn = outputArea.querySelector('.cmd-stop-btn');
        if (stopBtn) stopBtn.style.display = '';
        // Remove old report actions
        const oldReport = card.querySelector('.cmd-report-actions');
        if (oldReport) oldReport.remove();
    }

    currentCmdOutput = outputArea;
    btn.disabled = true;

    socket.emit('execute_command', { cmd: cmd });
    showToast(`▶ Running: ${cmd.substring(0, 50)}...`, 'info');
}

function stopCommand() {
    socket.emit('stop_command');
}

function copyCommand(cmd) {
    navigator.clipboard.writeText(cmd).then(() => {
        showToast('Command copied!', 'success');
    }).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = cmd; document.body.appendChild(ta); ta.select();
        document.execCommand('copy'); document.body.removeChild(ta);
        showToast('Command copied!', 'success');
    });
}

function appendCmdOutputLine(line) {
    if (!currentCmdOutput) return;
    const container = currentCmdOutput.querySelector('.cmd-output-lines');
    if (!container) return;
    const div = document.createElement('div');
    div.className = 'cmd-output-line';
    if (line.includes('open')) div.className += ' highlight-open';
    else if (line.includes('closed') || line.includes('filtered')) div.className += ' highlight-closed';
    else if (line.startsWith('|') || line.startsWith('PORT')) div.className += ' highlight-header';
    div.textContent = line;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
    scrollChatToBottom();
}

// ═══════════════════════════════════════════════════════════════
//  Report — Pretty results + HTML export
// ═══════════════════════════════════════════════════════════════

function showReportActions(outputArea, data) {
    const card = outputArea.closest('.command-card');
    if (!card) return;

    // Remove existing report actions
    const old = card.querySelector('.cmd-report-actions');
    if (old) old.remove();

    const actions = document.createElement('div');
    actions.className = 'cmd-report-actions';
    actions.innerHTML = `
        <div class="report-header">
            <span class="report-icon">📊</span>
            <span class="report-title">Scan Complete — ${data.line_count || 0} lines</span>
        </div>
        <div class="report-buttons">
            <button class="report-btn view-report" onclick="viewReport(this)" data-cmd="${escapeAttr(data.cmd || '')}" data-output="${escapeAttr(data.output || '')}">
                <span>📋</span> View Report
            </button>
            <button class="report-btn export-html" onclick="exportHTMLReport(this)" data-cmd="${escapeAttr(data.cmd || '')}" data-output="${escapeAttr(data.output || '')}">
                <span>💾</span> Export HTML
            </button>
            <button class="report-btn ask-ai" onclick="analyzeWithAI('${escapeAttr(data.cmd || '')}')">
                <span>🤖</span> Ask AI to Analyze
            </button>
        </div>
    `;
    card.appendChild(actions);
    scrollChatToBottom();
}

function viewReport(btn) {
    const cmd = btn.dataset.cmd;
    const output = btn.dataset.output;

    // Parse output for pretty display
    const lines = output.split('\n');
    let summaryHTML = '';

    // Extract ports
    const ports = [];
    for (const line of lines) {
        const match = line.match(/^(\d+\/\w+)\s+(open|closed|filtered)\s+(.*)/);
        if (match) {
            ports.push({ port: match[1], state: match[2], service: match[3].trim() });
        }
    }

    if (ports.length > 0) {
        const openPorts = ports.filter(p => p.state === 'open');
        summaryHTML += `<div class="report-summary-stat"><span class="stat-num">${openPorts.length}</span><span class="stat-label">Open Ports</span></div>`;
        summaryHTML += `<div class="report-summary-stat"><span class="stat-num">${ports.length}</span><span class="stat-label">Total Scanned</span></div>`;
    }

    // Build inline report
    const reportDiv = document.createElement('div');
    reportDiv.className = 'inline-report';

    let portsTable = '';
    if (ports.length > 0) {
        portsTable = `
            <div class="report-section">
                <div class="report-section-title">📡 Discovered Ports</div>
                <table class="report-table">
                    <thead><tr><th>Port</th><th>State</th><th>Service</th></tr></thead>
                    <tbody>
                        ${ports.map(p => `<tr><td class="port-cell">${escapeHtml(p.port)}</td><td class="state-${p.state}">${escapeHtml(p.state)}</td><td>${escapeHtml(p.service)}</td></tr>`).join('')}
                    </tbody>
                </table>
            </div>`;
    }

    reportDiv.innerHTML = `
        <div class="report-card">
            <div class="report-card-header">
                <span>📊</span> Scan Report
                <button class="report-close" onclick="this.closest('.inline-report').remove()">✕</button>
            </div>
            <div class="report-cmd">${escapeHtml(cmd)}</div>
            ${summaryHTML ? `<div class="report-summary">${summaryHTML}</div>` : ''}
            ${portsTable}
            <div class="report-section">
                <div class="report-section-title">📋 Raw Output</div>
                <div class="report-raw">${escapeHtml(output)}</div>
            </div>
        </div>
    `;

    // Insert after the command card
    const card = btn.closest('.command-card');
    const existing = card.parentElement.querySelector('.inline-report');
    if (existing) existing.remove();
    card.after(reportDiv);
    scrollChatToBottom();
}

function exportHTMLReport(btn) {
    const cmd = btn.dataset.cmd;
    const output = btn.dataset.output;

    fetch('/api/report/html', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cmd, output }),
    }).then(r => r.blob()).then(blob => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `nmappilot_report_${new Date().toISOString().slice(0,19).replace(/[:-]/g,'')}.html`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast('Report exported!', 'success');
    }).catch(e => showToast('Export failed: ' + e.message, 'error'));
}

function analyzeWithAI(cmd) {
    switchPanel('chat');
    const input = document.getElementById('chat-input');
    input.value = `Analyze the results of my last scan: ${cmd}`;
    input.focus();
    showToast('Switch to Chat to send the analysis request', 'info');
}

function escapeAttr(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
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
    // Close mobile sidebar
    document.getElementById('sidebar').classList.remove('mobile-open');
    document.getElementById('sidebar-overlay').classList.remove('active');
}

function resetChat() {
    fetch('/api/ai/reset', { method: 'POST' }).then(() => {
        const messages = document.getElementById('chat-messages');
        const welcome = messages.querySelector('.welcome-msg');
        messages.innerHTML = '';
        if (welcome) messages.appendChild(welcome);
        currentCmdOutput = null;
        lastCmdData = null;
        resetWaitingState();
        showToast('Conversation reset', 'info');
    });
}

// ═══════════════════════════════════════════════════════════════
//  Terminal Panel
// ═══════════════════════════════════════════════════════════════

function appendTerminal(line, type = '') {
    const t = document.getElementById('terminal-output');
    if (!t) return;
    const div = document.createElement('div');
    div.className = 'terminal-line';
    if (type) div.className += ' ' + type;
    else if (line.includes('open')) div.className += ' success';
    else if (line.includes('✔')) div.className += ' success';
    else if (line.includes('⚠')) div.className += ' warning';
    else if (line.includes('✘') || line.includes('Error')) div.className += ' error';
    else if (line.includes('⟳') || line.startsWith('▶')) div.className += ' system';
    div.textContent = line;
    t.appendChild(div);
    t.scrollTop = t.scrollHeight;
}

function clearTerminal() {
    document.getElementById('terminal-output').innerHTML =
        '<div class="terminal-line system">NmapPilot AI Terminal — Ready</div>';
}

function sendTerminalCommand() {
    const input = document.getElementById('terminal-input');
    if (!input) return;
    const cmd = input.value.trim();
    if (!cmd) return;
    input.value = '';

    if (!cmd.startsWith('nmap')) {
        appendTerminal('⚠ Only nmap commands are allowed', 'warning');
        return;
    }

    if (commandRunning) {
        appendTerminal('⚠ A command is already running', 'warning');
        return;
    }

    appendTerminal(`$ ${cmd}`, 'system');
    socket.emit('execute_command', { cmd });
}

// ═══════════════════════════════════════════════════════════════
//  Settings Panel
// ═══════════════════════════════════════════════════════════════

function loadSettings() {
    fetch('/api/config').then(r => r.json()).then(cfg => {
        const keyInput = document.getElementById('settings-api-key');
        if (keyInput && cfg.api_key_preview) keyInput.placeholder = cfg.api_key_set ? `Current: ${cfg.api_key_preview}` : 'sk-or-v1-...';

        const modelSelect = document.getElementById('settings-model');
        if (modelSelect && cfg.free_models) {
            modelSelect.innerHTML = '<option value="">Auto (best available)</option>';
            cfg.free_models.forEach(m => {
                const opt = document.createElement('option');
                opt.value = m;
                opt.textContent = m;
                if (m === cfg.preferred_model) opt.selected = true;
                modelSelect.appendChild(opt);
            });
        }

        const backendBadge = document.getElementById('settings-backend');
        if (backendBadge) {
            backendBadge.textContent = cfg.backend === 'openrouter' ? `OpenRouter: ${cfg.current_model}` :
                                       cfg.backend === 'ollama' ? `Ollama: ${cfg.ollama_model}` : 'Not configured';
            backendBadge.className = 'settings-badge ' + (cfg.backend !== 'none' ? 'active' : 'inactive');
        }
    }).catch(() => {});
}

function saveApiKey() {
    const input = document.getElementById('settings-api-key');
    const key = input.value.trim();
    if (!key) { showToast('Enter an API key', 'warning'); return; }

    const btn = document.getElementById('save-key-btn');
    btn.disabled = true; btn.textContent = 'Saving...';

    fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: key }),
    }).then(r => r.json()).then(cfg => {
        btn.disabled = false; btn.textContent = 'Save Key';
        input.value = '';
        if (cfg.backend === 'openrouter') {
            showToast(`✔ Connected! Using ${cfg.current_model}`, 'success');
        } else {
            showToast('Key saved but could not connect to OpenRouter', 'warning');
        }
        loadSettings();
        checkStatus();
    }).catch(e => {
        btn.disabled = false; btn.textContent = 'Save Key';
        showToast('Failed to save: ' + e.message, 'error');
    });
}

function savePreferredModel() {
    const select = document.getElementById('settings-model');
    const model = select.value;

    fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ preferred_model: model }),
    }).then(r => r.json()).then(cfg => {
        showToast(`Model set: ${cfg.current_model}`, 'success');
        checkStatus();
    }).catch(e => showToast('Failed: ' + e.message, 'error'));
}

function refreshModels() {
    const btn = document.getElementById('refresh-models-btn');
    btn.disabled = true; btn.textContent = '⟳ Fetching...';

    fetch('/api/config/refresh-models', { method: 'POST' })
    .then(r => r.json()).then(cfg => {
        btn.disabled = false; btn.textContent = '⟳ Refresh';
        showToast(`Found ${cfg.free_models.length} free models`, 'success');
        loadSettings();
    }).catch(e => {
        btn.disabled = false; btn.textContent = '⟳ Refresh';
        showToast('Failed: ' + e.message, 'error');
    });
}

// ═══════════════════════════════════════════════════════════════
//  Status / Toast / Utility
// ═══════════════════════════════════════════════════════════════

function checkStatus() {
    fetch('/api/status').then(r => r.json()).then(d => {
        updateAIStatus(d.ai_available ? 'connected' : 'disconnected',
                       d.ai_available ? d.model : 'No AI configured');
        if (d.status) updateStatusText(d.status);
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

// Doppel Dashboard Client - Minimalist & Proactive
document.addEventListener('DOMContentLoaded', () => {
  // Read saved state immediately to avoid FOUC (screen flash on reload)
  const savedStatus = localStorage.getItem('doppel_last_status') || 'STOPPED';
  const savedView = localStorage.getItem('doppel_active_view') || (savedStatus === 'RUNNING' ? 'dashboard' : 'launch');
  let activeSessionId = localStorage.getItem('doppel_active_session_id') || null;
  let honeypotStatus = savedStatus;
  let ws = null;
  let sessionsCache = {};
  let currentDiagnostics = null;
  let activeView = savedView;
  let pingInterval = null;
  let eventSource = null;
  let wsActive = false;

  // Plain-English Explanations for Info Buttons
  const INFO_DEFINITIONS = {
    llm: `<strong>AI Deception Model</strong><br><br>
The AI engine dynamically synthesizes authentic Linux terminal outputs, fake system files, and realistic honeytokens (like database passwords and API keys) on the fly. It also acts as your automated SOC analyst, tagging every attacker command with MITRE ATT&CK techniques.<br><br>
<strong>What is Mock Mode?</strong><br>
Mock Mode runs Doppel using built-in, realistic pre-programmed responses without connecting to an actual AI model. This is useful for offline testing, code review, or when your GPU / Ollama server is offline.`,
    
    docker: `<strong>Execution Sandbox (Docker)</strong><br><br>
Runs standard, safe Linux commands (such as <code>ls</code>, <code>pwd</code>, <code>id</code>) inside an isolated, disposable micro-container with zero network egress (<code>--network none</code>).<br><br>
<strong>Do I need Docker?</strong><br>
No! Docker is completely optional. If Docker Desktop is closed, Doppel automatically operates in pure AI simulation mode—the LLM simulates the entire bash environment with zero risk to your host machine.`,
    
    port: `<strong>SSH Listener Port</strong><br><br>
The TCP network port where Doppel waits for incoming attacker SSH connections. The default is <code>2222</code> so it does not conflict with your host machine's standard SSH daemon (port 22).<br><br>
<strong>Port Conflicts:</strong><br>
If port 2222 is already in use by another program, click one of our 1-click alternative buttons (like 2223 or 22222) to switch ports instantly.`,
    
    persona: `<strong>Deception Persona</strong><br><br>
Controls the honeypot's camouflage identity. When an attacker probes with <code>uname</code>, inspects <code>/etc/os-release</code>, or searches for configurations, all responses authentically match this persona (e.g. an Ubuntu 22.04 Web Server vs. an AWS EC2 Worker Node).`
  };

  // DOM Elements - Views
  const viewLaunch = document.getElementById('view-launch');
  const viewDashboard = document.getElementById('view-dashboard');
  const btnViewSwitch = document.getElementById('btn-view-switch');
  const btnViewSwitchLabel = document.getElementById('btn-view-switch-label');

  // DOM Elements - Top Bar
  const statusDot = document.getElementById('status-dot');
  const statusText = document.getElementById('status-text');
  const metaPort = document.getElementById('nav-meta-port');
  const metaModel = document.getElementById('nav-meta-model');
  const navBadgeLlm = document.getElementById('nav-badge-llm');
  const dotNavLlm = document.getElementById('dot-nav-llm');
  const textNavLlm = document.getElementById('text-nav-llm');
  const navBadgeDocker = document.getElementById('nav-badge-docker');
  const dotNavDocker = document.getElementById('dot-nav-docker');
  const textNavDocker = document.getElementById('text-nav-docker');
  const btnToggle = document.getElementById('btn-toggle-honeypot');
  const btnToggleLabel = document.getElementById('btn-toggle-label');

  // DOM Elements - Global Warning Banner
  const systemWarningBanner = document.getElementById('system-warning-banner');
  const warningBannerMessages = document.getElementById('warning-banner-messages');
  const btnBannerRecheck = document.getElementById('btn-banner-recheck');
  const btnBannerMock = document.getElementById('btn-banner-mock');
  const btnBannerDismiss = document.getElementById('btn-banner-dismiss');

  // DOM Elements - Launch Screen Diagnostics
  const pillLlm = document.getElementById('pill-llm');
  const descLlm = document.getElementById('desc-llm');
  const selectLlmModel = document.getElementById('select-llm-model');
  const actionBarLlm = document.getElementById('action-bar-llm');

  const pillDocker = document.getElementById('pill-docker');
  const descDocker = document.getElementById('desc-docker');
  const actionBarDocker = document.getElementById('action-bar-docker');

  const pillPort = document.getElementById('pill-port');
  const descPort = document.getElementById('desc-port');
  const actionBarPort = document.getElementById('action-bar-port');
  const inputCustomPort = document.getElementById('input-custom-port');
  const btnApplyCustomPort = document.getElementById('btn-apply-custom-port');

  const pillPersona = document.getElementById('pill-persona');
  const personaRadios = document.querySelectorAll('input[name="persona-select"]');

  const launchSummaryDot = document.getElementById('launch-summary-dot');
  const launchSummaryText = document.getElementById('launch-summary-text');
  const btnLaunchPrimary = document.getElementById('btn-launch-primary');

  // DOM Elements - Dashboard Fleet & Inspector
  const sessionCountPill = document.getElementById('session-count-pill');
  const sessionsContainer = document.getElementById('sessions-container');
  const sessionsEmpty = document.getElementById('sessions-empty');
  const emptyInspector = document.getElementById('empty-inspector');
  const sessionDetail = document.getElementById('session-detail');
  const detailLivePill = document.getElementById('detail-live-pill');
  const detailIp = document.getElementById('detail-ip');
  const detailUser = document.getElementById('detail-user');
  const detailSessionId = document.getElementById('detail-session-id');
  const detailThreatScore = document.getElementById('detail-threat-score');
  const detailCmdCount = document.getElementById('detail-cmd-count');
  const detailCwd = document.getElementById('detail-cwd');
  const terminalOutput = document.getElementById('terminal-output');
  const terminalWindow = document.getElementById('terminal-window');
  const telemetryTableBody = document.getElementById('telemetry-table-body');
  const reportEmpty = document.getElementById('report-empty');
  const reportContent = document.getElementById('report-content');

  // DOM Elements - Info Modal
  const infoModal = document.getElementById('info-modal');
  const infoModalTitle = document.getElementById('info-modal-title');
  const infoModalBody = document.getElementById('info-modal-body');
  const btnCloseInfo = document.getElementById('btn-close-info');

  // DOM Elements - AI Assistant & Benchmark Modal
  const btnOpenAssistant = document.getElementById('btn-open-assistant');
  const assistantModal = document.getElementById('assistant-modal');
  const btnCloseAssistant = document.getElementById('btn-close-assistant');
  const assistantModelSelect = document.getElementById('assistant-model-select');
  const assistantChips = document.querySelectorAll('.assistant-chip');
  const assistantChatBody = document.getElementById('assistant-chat-body');
  const assistantInputForm = document.getElementById('assistant-input-form');
  const assistantInput = document.getElementById('assistant-input');
  const btnSendAssistant = document.getElementById('btn-send-assistant');

  // --- View Management ---

  function switchView(viewName, manual = false) {
    activeView = viewName;
    localStorage.setItem('doppel_active_view', viewName);
    if (manual) {
      localStorage.setItem('doppel_user_clicked_view', 'true');
    }

    if (viewName === 'launch') {
      viewLaunch.classList.remove('hidden');
      viewDashboard.classList.add('hidden');
      document.documentElement.classList.remove('init-dashboard');
      btnViewSwitchLabel.textContent = 'Live Dashboard';
    } else {
      viewLaunch.classList.add('hidden');
      viewDashboard.classList.remove('hidden');
      document.documentElement.classList.add('init-dashboard');
      btnViewSwitchLabel.textContent = 'Setup & Config';
    }
  }

  // Restore initial view instantly on DOM load
  switchView(activeView);

  btnViewSwitch.addEventListener('click', () => {
    switchView(activeView === 'launch' ? 'dashboard' : 'launch', true);
  });

  // --- Robust Offline Markdown Parser ---
  function renderMarkdown(md) {
    if (!md) return '';

    // Extract code blocks first to protect formatting
    const codeBlocks = [];
    let text = md.replace(/```([a-zA-Z0-9_\-]*)?\n([\s\S]*?)```/g, (match, lang, code) => {
      const idx = codeBlocks.length;
      codeBlocks.push(`<pre class="md-code-block"><code class="language-${lang || 'bash'}">${escapeHtml(code.trim())}</code></pre>`);
      return `@@@CODEBLOCK_${idx}@@@`;
    });

    // Escape raw HTML entities
    text = escapeHtml(text);

    // Headings
    text = text.replace(/^#### (.*$)/gim, '<h4>$1</h4>');
    text = text.replace(/^### (.*$)/gim, '<h3>$1</h3>');
    text = text.replace(/^## (.*$)/gim, '<h2>$1</h2>');
    text = text.replace(/^# (.*$)/gim, '<h1>$1</h1>');

    // Horizontal Rule
    text = text.replace(/^---$/gim, '<hr>');

    // Blockquotes
    text = text.replace(/^\> (.*$)/gim, '<blockquote>$1</blockquote>');

    // Bold and Italic
    text = text.replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>');
    text = text.replace(/\*(.*?)\*/gim, '<em>$1</em>');

    // Inline Code
    text = text.replace(/`([^`]+)`/gim, '<code>$1</code>');

    // Parse lines for Lists, Tables, and Paragraphs
    const lines = text.split('\n');
    const output = [];
    let inList = false;
    let inTable = false;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();

      // Table row: | a | b | c |
      if (/^\|(.+)\|$/.test(line)) {
        if (line.includes('---')) {
          continue; // Separator row
        }
        const cols = line.split('|').slice(1, -1).map(c => c.trim());
        if (!inTable) {
          inTable = true;
          output.push('<table><thead><tr>');
          cols.forEach(c => output.push(`<th>${c}</th>`));
          output.push('</tr></thead><tbody>');
        } else {
          output.push('<tr>');
          cols.forEach(c => output.push(`<td>${c}</td>`));
          output.push('</tr>');
        }
        continue;
      } else if (inTable) {
        inTable = false;
        output.push('</tbody></table>');
      }

      // Unordered list: - item or * item
      if (/^[\-\*]\s+(.*)$/.test(line)) {
        const content = line.replace(/^[\-\*]\s+/, '');
        if (!inList) {
          inList = true;
          output.push('<ul>');
        }
        output.push(`<li>${content}</li>`);
        continue;
      } else if (inList) {
        inList = false;
        output.push('</ul>');
      }

      // Headers, HR, Codeblocks, Blockquotes
      if (line.startsWith('<h') || line.startsWith('<hr') || line.startsWith('<blockquote') || line.startsWith('@@@CODEBLOCK_')) {
        output.push(line);
      } else if (line.length > 0) {
        output.push(`<p>${line}</p>`);
      }
    }

    if (inList) output.push('</ul>');
    if (inTable) output.push('</tbody></table>');

    let result = output.join('\n');

    // Restore Code Blocks
    codeBlocks.forEach((cb, idx) => {
      result = result.replace(`@@@CODEBLOCK_${idx}@@@`, cb);
    });

    return result;
  }

  // --- Initialize Telemetry ---
  fetchStatus();
  fetchDiagnostics();
  fetchSessions();
  connectStream();

  // Background diagnostics auto-refresh every 8 seconds
  setInterval(fetchDiagnostics, 8000);

  // --- API Calls ---

  async function fetchStatus() {
    try {
      const res = await fetch('/api/status');
      const data = await res.json();
      updateStatusUI(data.status, data.config);
    } catch (e) {
      console.error('Error fetching status:', e);
    }
  }

  async function fetchDiagnostics() {
    try {
      const res = await fetch('/api/diagnostics');
      const data = await res.json();
      currentDiagnostics = data;
      renderDiagnosticsUI(data);
    } catch (e) {
      console.error('Error fetching diagnostics:', e);
    }
  }

  async function fetchSessions() {
    try {
      const res = await fetch('/api/sessions');
      const data = await res.json();
      renderSessionsList(data.sessions || []);
    } catch (e) {
      console.error('Error fetching sessions:', e);
    }
  }

  async function applyQuickFix(action, value) {
    try {
      const res = await fetch('/api/quick-fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, value })
      });
      const data = await res.json();
      if (data.diagnostics) {
        renderDiagnosticsUI(data.diagnostics);
      }
      fetchStatus();
    } catch (e) {
      console.error('Error applying quick fix:', e);
    }
  }

  // --- Render Diagnostics on Launch Screen ---

  function renderDiagnosticsUI(diag) {
    if (!diag) return;

    const llm = diag.llm || {};
    const docker = diag.docker || {};
    const port = diag.port || {};
    const persona = diag.persona || {};

    // 1. Update Top Navigation Subsystem Badges
    if (navBadgeLlm && dotNavLlm && textNavLlm) {
      if (llm.status === 'ready') {
        dotNavLlm.className = 'subsystem-dot ready';
        textNavLlm.textContent = 'LLM Ready';
        navBadgeLlm.title = `AI Model ready (${llm.latency_ms || 0}ms): ${llm.configured_model || ''}`;
      } else if (llm.status === 'mock_mode') {
        dotNavLlm.className = 'subsystem-dot neutral';
        textNavLlm.textContent = 'LLM Mock';
        navBadgeLlm.title = 'AI Mock Mode active';
      } else if (llm.status === 'model_missing') {
        dotNavLlm.className = 'subsystem-dot warning';
        textNavLlm.textContent = 'Model Missing';
        navBadgeLlm.title = `Model '${llm.configured_model || ''}' not pulled`;
      } else {
        dotNavLlm.className = 'subsystem-dot error';
        textNavLlm.textContent = 'LLM Offline';
        navBadgeLlm.title = `LLM endpoint unreachable at ${llm.endpoint || 'local'}`;
      }
    }

    if (navBadgeDocker && dotNavDocker && textNavDocker) {
      if (docker.status === 'ready') {
        dotNavDocker.className = 'subsystem-dot ready';
        textNavDocker.textContent = 'Docker Ready';
        navBadgeDocker.title = `Docker Sandbox active (v${docker.version || 'Engine'})`;
      } else if (docker.status === 'disabled') {
        dotNavDocker.className = 'subsystem-dot neutral';
        textNavDocker.textContent = 'Docker Off';
        navBadgeDocker.title = 'Docker sandbox disabled in configuration';
      } else {
        dotNavDocker.className = 'subsystem-dot warning';
        textNavDocker.textContent = 'Docker Offline';
        navBadgeDocker.title = 'Docker Engine not running (safe simulation mode)';
      }
    }

    // 2. Global Subsystem Warning Banner Evaluation
    const warningItems = [];
    let hasCriticalError = false;

    if (llm.status === 'unreachable') {
      hasCriticalError = true;
      warningItems.push({
        type: 'error',
        tag: 'LLM Offline',
        html: `Ollama is unreachable at <code>${escapeHtml(llm.endpoint || 'http://127.0.0.1:11434')}</code>. Start Ollama with <code>ollama serve</code> or switch to Mock Mode.`
      });
    } else if (llm.status === 'model_missing') {
      hasCriticalError = true;
      warningItems.push({
        type: 'warning',
        tag: 'Model Missing',
        html: `Configured model <code>${escapeHtml(llm.configured_model || '')}</code> is not pulled. Run <code>ollama pull ${escapeHtml(llm.configured_model || '')}</code> or switch to Mock Mode.`
      });
    }

    if (docker.status === 'unavailable' && docker.enabled !== false) {
      warningItems.push({
        type: 'warning',
        tag: 'Docker Offline',
        html: `Docker Engine is not running. Commands will execute in simulated mode without container isolation.`
      });
    }

    if (!port.available) {
      warningItems.push({
        type: 'warning',
        tag: 'Port Busy',
        html: `SSH port <code>${port.port}</code> is occupied by another service.`
      });
    }

    if (systemWarningBanner && warningBannerMessages) {
      if (warningItems.length === 0) {
        systemWarningBanner.classList.add('hidden');
        sessionStorage.removeItem('doppel_banner_dismissed');
      } else {
        const isDismissed = sessionStorage.getItem('doppel_banner_dismissed') === 'true';
        if (!isDismissed) {
          systemWarningBanner.classList.remove('hidden');
        } else {
          systemWarningBanner.classList.add('hidden');
        }

        if (hasCriticalError) {
          systemWarningBanner.classList.add('banner-critical');
        } else {
          systemWarningBanner.classList.remove('banner-critical');
        }

        let msgsHtml = '';
        warningItems.forEach(item => {
          msgsHtml += `
            <div class="warning-banner-item">
              <span class="warning-banner-tag ${item.type === 'error' ? 'tag-error' : ''}">${escapeHtml(item.tag)}</span>
              <span>${item.html}</span>
            </div>
          `;
        });
        warningBannerMessages.innerHTML = msgsHtml;

        if (btnBannerMock) {
          if (llm.status === 'unreachable' || llm.status === 'model_missing') {
            btnBannerMock.classList.remove('hidden');
          } else {
            btnBannerMock.classList.add('hidden');
          }
        }
      }
    }

    // 3. Card 1: LLM Diagnostics
    if (llm.status === 'ready') {
      pillLlm.className = 'diag-pill ready';
      pillLlm.textContent = `Ready (${llm.latency_ms}ms)`;
      descLlm.textContent = llm.detail;
      actionBarLlm.innerHTML = '';
    } else if (llm.status === 'mock_mode') {
      pillLlm.className = llm.backend_available ? 'diag-pill ready' : 'diag-pill neutral';
      pillLlm.textContent = llm.backend_available ? 'Mock Mode (Backend Online)' : 'Mock Mode';
      descLlm.textContent = llm.detail;
      actionBarLlm.innerHTML = `
        <button type="button" class="btn-quick-fix" id="btn-fix-disable-mock">${llm.backend_available ? 'Connect to Live LLM' : 'Switch to Live LLM'}</button>
      `;
      document.getElementById('btn-fix-disable-mock')?.addEventListener('click', () => {
        applyQuickFix('toggle_mock', false);
      });
    } else if (llm.status === 'model_missing') {
      pillLlm.className = 'diag-pill warning';
      pillLlm.textContent = 'Model Missing';
      descLlm.textContent = llm.detail;
      actionBarLlm.innerHTML = `
        <button type="button" class="btn-quick-fix" id="btn-fix-recheck-llm">Recheck Models</button>
        <button type="button" class="btn-quick-fix" id="btn-fix-enable-mock">Switch to Mock Mode</button>
      `;
      document.getElementById('btn-fix-recheck-llm')?.addEventListener('click', () => {
        applyQuickFix('recheck');
      });
      document.getElementById('btn-fix-enable-mock')?.addEventListener('click', () => {
        applyQuickFix('toggle_mock', true);
      });
    } else {
      pillLlm.className = 'diag-pill error';
      pillLlm.textContent = 'Offline';
      descLlm.textContent = `${llm.detail} ${llm.suggestion || ''}`;
      actionBarLlm.innerHTML = `
        <button type="button" class="btn-quick-fix" id="btn-fix-recheck-llm">Recheck Ollama</button>
        <button type="button" class="btn-quick-fix" id="btn-fix-enable-mock">Switch to Mock Mode</button>
      `;
      document.getElementById('btn-fix-recheck-llm')?.addEventListener('click', () => {
        applyQuickFix('recheck');
      });
      document.getElementById('btn-fix-enable-mock')?.addEventListener('click', () => {
        applyQuickFix('toggle_mock', true);
      });
    }

    // Populate model select with installed models if available
    if (llm.models_available && llm.models_available.length > 0) {
      selectLlmModel.innerHTML = '';
      if (assistantModelSelect) {
        assistantModelSelect.innerHTML = '';
        const defOpt = document.createElement('option');
        defOpt.value = '';
        defOpt.textContent = `Default (${llm.configured_model || 'System'})`;
        assistantModelSelect.appendChild(defOpt);
      }

      llm.models_available.forEach(m => {
        const opt = document.createElement('option');
        opt.value = m;
        opt.textContent = m;
        if (m.toLowerCase() === (llm.configured_model || '').toLowerCase()) {
          opt.selected = true;
        }
        selectLlmModel.appendChild(opt);

        if (assistantModelSelect) {
          const aOpt = document.createElement('option');
          aOpt.value = m;
          aOpt.textContent = m;
          if (m.toLowerCase() === (llm.configured_model || '').toLowerCase()) {
            aOpt.selected = true;
          }
          assistantModelSelect.appendChild(aOpt);
        }
      });
    }

    // 4. Card 2: Docker Diagnostics
    if (docker.status === 'ready') {
      pillDocker.className = 'diag-pill ready';
      pillDocker.textContent = 'Container Sandbox Active';
      descDocker.textContent = docker.detail;
      actionBarDocker.innerHTML = `
        <button type="button" class="btn-quick-fix" id="btn-fix-disable-sandbox">Switch to AI Simulation</button>
      `;
      document.getElementById('btn-fix-disable-sandbox')?.addEventListener('click', () => {
        applyQuickFix('toggle_sandbox', false);
      });
    } else if (docker.status === 'disabled') {
      pillDocker.className = 'diag-pill neutral';
      pillDocker.textContent = 'AI Simulation';
      descDocker.textContent = docker.detail;
      actionBarDocker.innerHTML = `
        <button type="button" class="btn-quick-fix" id="btn-fix-enable-sandbox">Enable Docker Sandbox</button>
      `;
      document.getElementById('btn-fix-enable-sandbox')?.addEventListener('click', () => {
        applyQuickFix('toggle_sandbox', true);
      });
    } else {
      pillDocker.className = 'diag-pill warning';
      pillDocker.textContent = 'Engine Offline';
      descDocker.textContent = docker.detail;
      actionBarDocker.innerHTML = `
        <button type="button" class="btn-quick-fix" id="btn-fix-recheck-docker">Recheck Docker</button>
        <button type="button" class="btn-quick-fix" id="btn-fix-disable-sandbox">Disable Sandbox (Pure AI Mode)</button>
      `;
      document.getElementById('btn-fix-recheck-docker')?.addEventListener('click', () => {
        applyQuickFix('recheck');
      });
      document.getElementById('btn-fix-disable-sandbox')?.addEventListener('click', () => {
        applyQuickFix('toggle_sandbox', false);
      });
    }

    // 5. Card 3: Port Diagnostics
    inputCustomPort.value = port.port;
    if (port.available) {
      pillPort.className = 'diag-pill ready';
      pillPort.textContent = `Port ${port.port} Free`;
      descPort.textContent = port.detail;
      actionBarPort.innerHTML = '';
    } else {
      pillPort.className = 'diag-pill error';
      pillPort.textContent = `Port ${port.port} Busy!`;
      descPort.textContent = port.detail;
      
      let alternativesHtml = '<span style="font-size:11px;margin-right:4px;">Quick-switch:</span>';
      (port.suggested_alternatives || [2223, 22222]).forEach(alt => {
        alternativesHtml += `<button type="button" class="btn-quick-fix btn-alt-port" data-port="${alt}">Use Port ${alt}</button> `;
      });
      actionBarPort.innerHTML = alternativesHtml;

      document.querySelectorAll('.btn-alt-port').forEach(btn => {
        btn.addEventListener('click', () => {
          applyQuickFix('set_port', btn.dataset.port);
        });
      });
    }

    // 6. Card 4: Persona
    if (diag.persona) {
      const currentPersona = diag.persona.current || 'ubuntu_web_server';
      personaRadios.forEach(radio => {
        radio.checked = (radio.value === currentPersona);
      });
      const names = {
        ubuntu_web_server: 'Ubuntu Web Server',
        cloud_worker: 'AWS Cloud Worker',
        fintech_api: 'Fintech Gateway'
      };
      pillPersona.textContent = names[currentPersona] || currentPersona;
    }

    // 7. Launch Summary Strip
    if (!port.available) {
      launchSummaryDot.className = 'summary-dot error';
      launchSummaryText.textContent = `Port conflict: port ${port.port} is busy. Use a quick-switch alternative above or change ports.`;
    } else if (llm.status === 'unreachable') {
      launchSummaryDot.className = 'summary-dot error';
      launchSummaryText.textContent = `Warning: LLM backend is offline. Start Ollama or switch to Mock Mode before launching.`;
    } else if (llm.status === 'model_missing') {
      launchSummaryDot.className = 'summary-dot warning';
      launchSummaryText.textContent = `Warning: Model '${llm.configured_model}' is not pulled. Pull model or switch to Mock Mode.`;
    } else if (docker.status === 'unavailable' && docker.enabled !== false) {
      launchSummaryDot.className = 'summary-dot warning';
      launchSummaryText.textContent = `Warning: Docker Engine is offline. Honeypot will launch in simulated mode without container isolation.`;
    } else {
      launchSummaryDot.className = 'summary-dot ready';
      launchSummaryText.textContent = `All subsystems ready. Listening on port ${port.port} with persona: ${pillPersona.textContent}.`;
    }
  }

  // --- Event Listeners for Controls on Launch Screen ---

  selectLlmModel.addEventListener('change', (e) => {
    applyQuickFix('set_model', e.target.value);
  });

  btnApplyCustomPort.addEventListener('click', () => {
    const val = parseInt(inputCustomPort.value, 10);
    if (val > 0 && val < 65536) {
      applyQuickFix('set_port', val);
    }
  });

  personaRadios.forEach(radio => {
    radio.addEventListener('change', async (e) => {
      await fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ persona: e.target.value })
      });
      fetchDiagnostics();
      fetchStatus();
    });
  });

  // Global Warning Banner Action Listeners
  if (btnBannerRecheck) {
    btnBannerRecheck.addEventListener('click', async () => {
      const origText = btnBannerRecheck.textContent;
      btnBannerRecheck.textContent = 'Checking...';
      sessionStorage.removeItem('doppel_banner_dismissed');
      await applyQuickFix('recheck');
      btnBannerRecheck.textContent = origText;
    });
  }

  if (btnBannerMock) {
    btnBannerMock.addEventListener('click', async () => {
      await applyQuickFix('toggle_mock', true);
    });
  }

  if (btnBannerDismiss) {
    btnBannerDismiss.addEventListener('click', () => {
      sessionStorage.setItem('doppel_banner_dismissed', 'true');
      if (systemWarningBanner) {
        systemWarningBanner.classList.add('hidden');
      }
    });
  }

  // Launch Button (Both primary on launch screen and nav button)
  async function launchHoneypot() {
    btnLaunchPrimary.disabled = true;
    btnToggle.disabled = true;
    try {
      await fetch('/api/start', { method: 'POST' });
    } catch (e) {
      console.error('Error starting honeypot:', e);
    } finally {
      btnLaunchPrimary.disabled = false;
      btnToggle.disabled = false;
      fetchStatus();
      fetchDiagnostics();
    }
  }

  async function stopHoneypot() {
    btnToggle.disabled = true;
    try {
      await fetch('/api/stop', { method: 'POST' });
    } catch (e) {
      console.error('Error stopping honeypot:', e);
    } finally {
      btnToggle.disabled = false;
      fetchStatus();
      fetchDiagnostics();
    }
  }

  btnLaunchPrimary.addEventListener('click', launchHoneypot);

  btnToggle.addEventListener('click', () => {
    if (honeypotStatus === 'RUNNING') {
      stopHoneypot();
    } else {
      launchHoneypot();
    }
  });

  // --- Info Tooltips Handler ---
  document.querySelectorAll('.info-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const topic = btn.dataset.info;
      const content = INFO_DEFINITIONS[topic];
      if (content) {
        const titles = {
          llm: 'AI Deception Model & Mock Mode',
          docker: 'Docker Sandbox vs AI Simulation',
          port: 'SSH Listener Port & Conflicts',
          persona: 'Deception Personas'
        };
        infoModalTitle.textContent = titles[topic] || 'Explanation';
        infoModalBody.innerHTML = content;
        infoModal.classList.remove('hidden');
      }
    });
  });

  btnCloseInfo.addEventListener('click', () => {
    infoModal.classList.add('hidden');
  });

  infoModal.addEventListener('click', (e) => {
    if (e.target === infoModal) {
      infoModal.classList.add('hidden');
    }
  });

  // --- Status UI & Auto-Switching ---

  function updateStatusUI(status, config) {
    honeypotStatus = status;
    localStorage.setItem('doppel_last_status', status);
    statusDot.className = 'status-dot ' + status.toLowerCase();
    statusText.textContent = status === 'RUNNING' ? 'Active' : status;

    if (config) {
      metaPort.textContent = `Port: ${config.honeypot_port}`;
      metaModel.textContent = `Model: ${config.llm_model}`;
    }

    if (status === 'RUNNING') {
      btnToggleLabel.textContent = 'Stop Honeypot';
      btnToggle.className = 'btn btn-primary danger';
      btnViewSwitch.classList.remove('hidden');

      // Auto-switch to live dashboard view if we were on launch screen unless explicitly clicked
      if (activeView === 'launch' && !localStorage.getItem('doppel_user_clicked_view')) {
        switchView('dashboard');
      }
    } else {
      btnToggleLabel.textContent = 'Start Honeypot';
      btnToggle.className = 'btn btn-primary';

      // If stopped and no sessions exist, return to setup screen
      if (activeView === 'dashboard' && Object.keys(sessionsCache).length === 0) {
        switchView('launch');
      }
    }
  }

  // --- Real-Time Telemetry Streaming: WebSocket with Automatic SSE Fallback ---

  function connectStream() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/stream`;

    try {
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        wsActive = true;
        // If SSE fallback was running, close it now that WS is connected
        if (eventSource) {
          eventSource.close();
          eventSource = null;
        }
        if (pingInterval) clearInterval(pingInterval);
        pingInterval = setInterval(() => {
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send('ping');
          }
        }, 25000);
      };

      ws.onmessage = (event) => {
        try {
          if (event.data === 'pong') return;
          const msg = JSON.parse(event.data);
          handleStreamMessage(msg);
        } catch (e) {
          console.error('WebSocket parse error:', e);
        }
      };

      ws.onerror = () => {
        // If WS failed to upgrade/connect (e.g. 404 No WebSocket library in Uvicorn), fallback to SSE
        if (!wsActive) {
          fallbackToSSE();
        }
      };

      ws.onclose = () => {
        if (pingInterval) clearInterval(pingInterval);
        const wasActive = wsActive;
        wsActive = false;
        if (wasActive) {
          setTimeout(connectStream, 3000);
        } else {
          fallbackToSSE();
        }
      };
    } catch (err) {
      fallbackToSSE();
    }
  }

  function fallbackToSSE() {
    if (eventSource) return;
    try {
      eventSource = new EventSource('/api/stream');
      eventSource.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          handleStreamMessage(msg);
        } catch (e) {
          console.error('SSE parse error:', e);
        }
      };
      eventSource.onerror = () => {
        // Native EventSource auto-reconnects with backoff
      };
    } catch (e) {
      console.error('Failed to initialize EventSource stream fallback:', e);
    }
  }

  function handleStreamMessage(msg) {
    if (msg.type === 'status_update') {
      updateStatusUI(msg.status, msg.config);
      if (msg.active_sessions && msg.active_sessions.length > 0) {
        renderSessionsList(msg.active_sessions);
      }
      fetchDiagnostics();
    } else if (msg.type === 'session_created') {
      const sess = msg.data;
      sess.is_active = true;
      sess.command_count = 0;
      sess.max_threat_score = 0;
      sessionsCache[sess.session_id] = sess;
      renderSessionsList(Object.values(sessionsCache));
      selectSession(sess.session_id);
      switchView('dashboard');
    } else if (msg.type === 'command_executed') {
      const data = msg.data;
      if (!sessionsCache[data.session_id]) {
        sessionsCache[data.session_id] = {
          session_id: data.session_id,
          remote_ip: 'active',
          username: 'ubuntu',
          is_active: true,
          command_count: 0,
          max_threat_score: 0,
        };
      }
      sessionsCache[data.session_id].command_count = (sessionsCache[data.session_id].command_count || 0) + 1;
      sessionsCache[data.session_id].last_command = data.command;
      sessionsCache[data.session_id].is_active = true;

      // Update card in DOM if present without wiping the list
      const card = document.querySelector(`.session-card[data-session-id="${data.session_id}"]`);
      if (card) {
        const lastCmdEl = card.querySelector('.card-last-cmd');
        if (lastCmdEl) lastCmdEl.textContent = data.command;
      } else {
        renderSessionsList(Object.values(sessionsCache));
      }

      // Auto-latch if no session is currently selected, or if current selection is an ended session
      const currentSelected = activeSessionId ? sessionsCache[activeSessionId] : null;
      if (!activeSessionId || (currentSelected && !currentSelected.is_active)) {
        selectSession(data.session_id);
      }

      if (activeSessionId === data.session_id) {
        appendTerminalCommand(data.cwd, data.command, data.output, data.decision);
        appendTelemetryRow(data.timestamp, data.command, data.decision, '—', '—', 0);
        detailCwd.textContent = data.cwd;
        detailCmdCount.textContent = (parseInt(detailCmdCount.textContent, 10) || 0) + 1;
      }
    } else if (msg.type === 'threat_analyzed') {
      const data = msg.data;
      const score = data.threat_score || 0;
      if (sessionsCache[data.session_id]) {
        sessionsCache[data.session_id].max_threat_score = Math.max(
          sessionsCache[data.session_id].max_threat_score || 0,
          score
        );
        const card = document.querySelector(`.session-card[data-session-id="${data.session_id}"]`);
        if (card) {
          const scoreEl = card.querySelector('.card-score');
          if (scoreEl) {
            scoreEl.textContent = score;
            scoreEl.className = `card-score ${score >= 60 ? 'high' : (score >= 30 ? 'medium' : 'low')}`;
          }
        }
      }

      if (activeSessionId === data.session_id) {
        detailThreatScore.textContent = `${score} / 100`;
        updateLastTelemetryRow(data.threat);
      }
    } else if (msg.type === 'session_closed') {
      const data = msg.data;
      if (sessionsCache[data.session_id]) {
        sessionsCache[data.session_id].is_active = false;
        const card = document.querySelector(`.session-card[data-session-id="${data.session_id}"]`);
        if (card) {
          const dot = card.querySelector('.card-status-dot');
          if (dot) {
            dot.classList.remove('live');
            dot.classList.add('ended');
          }
        }
      }
      if (activeSessionId === data.session_id) {
        detailLivePill.textContent = 'ENDED';
        detailLivePill.classList.add('ended');
        fetchSessionReport(data.session_id);
      }
      fetchSessions();
    }
  }

  // --- Session List & Inspector Logic ---

  function renderSessionsList(sessions) {
    sessions.forEach(s => {
      sessionsCache[s.session_id] = Object.assign(sessionsCache[s.session_id] || {}, s);
    });

    sessionCountPill.textContent = sessions.length;

    if (sessions.length === 0) {
      sessionsEmpty.classList.remove('hidden');
      return;
    }

    sessionsEmpty.classList.add('hidden');

    // Auto-select: prioritize a truly active session over an ended/historical session
    const currentIsActive = activeSessionId && sessionsCache[activeSessionId] && Boolean(sessionsCache[activeSessionId].is_active);
    if (!currentIsActive) {
      const liveSession = sessions.find(s => Boolean(s.is_active));
      const targetSession = liveSession || sessions[0];
      if (targetSession) {
        selectSession(targetSession.session_id);
      }
    }

    Array.from(sessionsContainer.children).forEach(child => {
      if (child.id !== 'sessions-empty') child.remove();
    });

    sessions.forEach(sess => {
      const card = document.createElement('div');
      card.className = `session-card ${sess.session_id === activeSessionId ? 'selected' : ''}`;
      card.dataset.sessionId = sess.session_id;

      const isLive = Boolean(sess.is_active);
      const score = sess.max_threat_score || sess.threat_score || 0;
      const scoreClass = score >= 60 ? 'high' : (score >= 30 ? 'medium' : 'low');

      card.innerHTML = `
        <div class="card-top">
          <div class="card-status">
            <span class="card-status-dot ${isLive ? 'live' : 'ended'}"></span>
            <span class="card-ip">${escapeHtml(sess.remote_ip || 'unknown')}</span>
          </div>
          <span class="card-score ${scoreClass}">${score}</span>
        </div>
        <div class="card-bottom">
          <span>${escapeHtml(sess.username || 'user')}</span>
          <span class="card-last-cmd">${escapeHtml(sess.last_command || 'connected')}</span>
        </div>
      `;

      card.addEventListener('click', () => {
        selectSession(sess.session_id);
      });

      sessionsContainer.appendChild(card);
    });
  }

  function selectSession(sessionId) {
    activeSessionId = sessionId;
    localStorage.setItem('doppel_active_session_id', sessionId);

    document.querySelectorAll('.session-card').forEach(card => {
      card.classList.toggle('selected', card.dataset.sessionId === sessionId);
    });

    fetchSessionDetails(sessionId);
    fetchSessionReport(sessionId);
  }

  async function fetchSessionDetails(sessionId) {
    try {
      const res = await fetch(`/api/sessions/${sessionId}`);
      if (!res.ok) return;
      const details = await res.json();
      renderSessionDetail(details);
    } catch (e) {
      console.error('Error fetching session details:', e);
    }
  }

  async function fetchSessionReport(sessionId) {
    try {
      const res = await fetch(`/api/sessions/${sessionId}/report`);
      if (res.ok) {
        const markdown = await res.text();
        reportEmpty.classList.add('hidden');
        reportContent.classList.remove('hidden');
        reportContent.innerHTML = renderMarkdown(markdown);
      } else {
        reportEmpty.classList.remove('hidden');
        reportContent.classList.add('hidden');
      }
    } catch (e) {
      reportEmpty.classList.remove('hidden');
      reportContent.classList.add('hidden');
    }
  }

  function renderSessionDetail(session) {
    if (activeSessionId && session.session_id !== activeSessionId) return;
    emptyInspector.classList.add('hidden');
    sessionDetail.classList.remove('hidden');

    const isLive = Boolean(session.is_active);
    detailLivePill.textContent = isLive ? 'LIVE' : 'ENDED';
    detailLivePill.className = `live-pill ${isLive ? '' : 'ended'}`;

    detailIp.textContent = `${session.remote_ip}:${session.remote_port || 0}`;
    detailUser.textContent = `user: ${session.username}`;
    detailSessionId.textContent = `ID: ${session.session_id}`;
    detailThreatScore.textContent = `${session.max_threat_score || 0} / 100`;
    detailCmdCount.textContent = Math.max((session.commands || []).length, parseInt(detailCmdCount.textContent, 10) || 0);
    detailCwd.textContent = session.cwd || '/home/ubuntu';

    const serverCmds = session.commands || [];
    const currentTerminalLines = terminalOutput.children.length;
    if (serverCmds.length > 0 || currentTerminalLines === 0) {
      terminalOutput.innerHTML = '';
      serverCmds.forEach(cmd => {
        appendTerminalCommand(cmd.cwd || session.cwd, cmd.command, cmd.output, cmd.route_decision);
      });

      telemetryTableBody.innerHTML = '';
      serverCmds.forEach(cmd => {
        appendTelemetryRow(
          cmd.timestamp,
          cmd.command,
          cmd.route_decision,
          cmd.technique_id || '—',
          cmd.technique_name || '—',
          cmd.threat_score || 0
        );
      });
    }
  }

  function appendTerminalCommand(cwd, command, output, decision) {
    const line = document.createElement('div');
    line.className = 'terminal-line';

    const routeClass = decision === 'sandbox' ? 'sandbox' : 'deception';
    const routeLabel = decision === 'sandbox' ? 'Sandbox' : (decision === 'builtin' ? 'Builtin' : 'Deception');
    const formattedOutput = output ? escapeHtml(output).replace(/\r\n/g, '\n') : '';

    line.innerHTML = `
      <div>
        <span class="terminal-prompt">ubuntu@prod-api-node-01:${escapeHtml(cwd || '~')}$ </span>
        <span class="terminal-cmd">${escapeHtml(command)}</span>
        <span class="terminal-route-tag ${routeClass}">${routeLabel}</span>
      </div>
      ${formattedOutput ? `<div class="terminal-output-block">${formattedOutput}</div>` : ''}
    `;

    terminalOutput.appendChild(line);
    terminalWindow.scrollTop = terminalWindow.scrollHeight;
  }

  function appendTelemetryRow(timestamp, command, decision, techId, techName, score) {
    const tr = document.createElement('tr');
    const timeStr = timestamp ? timestamp.split('T')[1]?.substring(0, 8) : '—';
    tr.innerHTML = `
      <td>${timeStr}</td>
      <td><code>${escapeHtml(command)}</code></td>
      <td><span class="badge-tag">${escapeHtml(decision || '—')}</span></td>
      <td><span class="badge-tag">${escapeHtml(techId || '—')}</span></td>
      <td>${escapeHtml(techName || '—')}</td>
      <td>${score}</td>
    `;
    telemetryTableBody.appendChild(tr);
  }

  function updateLastTelemetryRow(threat) {
    if (!threat || !telemetryTableBody.lastElementChild) return;
    const lastRow = telemetryTableBody.lastElementChild;
    const cells = lastRow.querySelectorAll('td');
    if (cells.length >= 6) {
      cells[3].innerHTML = `<span class="badge-tag">${escapeHtml(threat.technique_id || '—')}</span>`;
      cells[4].textContent = threat.technique_name || '—';
      cells[5].textContent = threat.threat_score || 0;
    }
  }

  // Tabs switching
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const tabId = `tab-${btn.dataset.tab}`;
      const targetContent = document.getElementById(tabId);
      if (targetContent) targetContent.classList.add('active');
    });
  });

  // --- AI Assistant & Benchmark Console Logic ---
  function syncAssistantModels() {
    if (!assistantModelSelect) return;
    if (assistantModelSelect.options.length <= 1 && selectLlmModel && selectLlmModel.options.length > 0) {
      const curVal = assistantModelSelect.value;
      assistantModelSelect.innerHTML = '';
      const defOpt = document.createElement('option');
      defOpt.value = '';
      defOpt.textContent = 'Default Configured Model';
      assistantModelSelect.appendChild(defOpt);

      Array.from(selectLlmModel.options).forEach(opt => {
        const aOpt = document.createElement('option');
        aOpt.value = opt.value;
        aOpt.textContent = opt.textContent;
        if (opt.value === curVal || opt.selected) {
          aOpt.selected = true;
        }
        assistantModelSelect.appendChild(aOpt);
      });
    }
  }

  if (btnOpenAssistant) {
    btnOpenAssistant.addEventListener('click', () => {
      syncAssistantModels();
      assistantModal.classList.remove('hidden');
      assistantInput.focus();
    });
  }

  if (btnCloseAssistant) {
    btnCloseAssistant.addEventListener('click', () => {
      assistantModal.classList.add('hidden');
    });
  }

  if (assistantModal) {
    assistantModal.addEventListener('click', (e) => {
      if (e.target === assistantModal) {
        assistantModal.classList.add('hidden');
      }
    });
  }

  async function sendAssistantMessage(messageText) {
    const text = (messageText || '').trim();
    if (!text) return;

    // 1. Append User Message Bubble
    const userMsg = document.createElement('div');
    userMsg.className = 'assistant-msg assistant-msg-user';
    userMsg.innerHTML = `<div class="assistant-bubble">${escapeHtml(text)}</div>`;
    assistantChatBody.appendChild(userMsg);
    assistantInput.value = '';

    // 2. Append Loading Indicator
    const targetModel = assistantModelSelect ? assistantModelSelect.value : '';
    const loadingMsg = document.createElement('div');
    loadingMsg.className = 'assistant-msg assistant-msg-bot';
    loadingMsg.id = 'assistant-temp-loading';
    loadingMsg.innerHTML = `
      <div class="assistant-loading-indicator">
        <span class="assistant-spinner"></span>
        <span>Evaluating inference${targetModel ? ` on ${escapeHtml(targetModel)}` : ''}...</span>
      </div>
    `;
    assistantChatBody.appendChild(loadingMsg);
    assistantChatBody.scrollTop = assistantChatBody.scrollHeight;

    // Disable input while running
    assistantInput.disabled = true;
    btnSendAssistant.disabled = true;

    try {
      const payload = { message: text };
      if (targetModel) {
        payload.model = targetModel;
      }

      const res = await fetch('/api/chat-assistant', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const loadingElem = document.getElementById('assistant-temp-loading');
      if (loadingElem) loadingElem.remove();

      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }

      const data = await res.json();
      if (!data.success && data.error) {
        throw new Error(data.error);
      }

      // Render assistant message with formatted markdown and performance metrics
      const botMsg = document.createElement('div');
      botMsg.className = 'assistant-msg assistant-msg-bot';

      const formattedBody = renderMarkdown(data.reply || '(Empty response)');
      const speedStr = typeof data.tokens_per_second === 'number' ? `${data.tokens_per_second.toFixed(1)} tok/s` : '';
      const latencyStr = typeof data.latency_seconds === 'number' ? `${data.latency_seconds.toFixed(2)}s` : '';
      const tokensStr = typeof data.tokens_generated === 'number' ? `${data.tokens_generated} tokens` : '';
      const modelStr = data.model || targetModel || 'default';

      botMsg.innerHTML = `
        <div class="assistant-bubble">${formattedBody}</div>
        <div class="assistant-metrics-bar">
          ${speedStr ? `<span class="metric-pill speed">${speedStr}</span>` : ''}
          ${latencyStr ? `<span class="metric-pill latency">${latencyStr} latency</span>` : ''}
          ${tokensStr ? `<span class="metric-pill tokens">${tokensStr}</span>` : ''}
          <span class="metric-pill model">${escapeHtml(modelStr)}</span>
        </div>
      `;
      assistantChatBody.appendChild(botMsg);
    } catch (err) {
      const loadingElem = document.getElementById('assistant-temp-loading');
      if (loadingElem) loadingElem.remove();

      const errMsg = document.createElement('div');
      errMsg.className = 'assistant-msg assistant-msg-bot';
      errMsg.innerHTML = `
        <div class="assistant-bubble" style="border-color: var(--accent-red); color: var(--accent-red);">
          Failed to query assistant: ${escapeHtml(err.message || 'Unknown network error')}
        </div>
      `;
      assistantChatBody.appendChild(errMsg);
    } finally {
      assistantInput.disabled = false;
      btnSendAssistant.disabled = false;
      assistantInput.focus();
      assistantChatBody.scrollTop = assistantChatBody.scrollHeight;
    }
  }

  if (assistantInputForm) {
    assistantInputForm.addEventListener('submit', (e) => {
      e.preventDefault();
      sendAssistantMessage(assistantInput.value);
    });
  }

  assistantChips.forEach(chip => {
    chip.addEventListener('click', () => {
      const prompt = chip.getAttribute('data-prompt');
      if (prompt) {
        sendAssistantMessage(prompt);
      }
    });
  });

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
});

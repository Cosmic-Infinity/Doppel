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

  // Shell prompt as the SSH server renders it; replaced by /api/status config
  let promptConfig = {
    hostname: 'prod-api-node-01',
    format: '{user}@{hostname}:{cwd}$ ',
    root_format: '{user}@{hostname}:{cwd}# ',
  };

  // Campaigns (cross-session correlation)
  let campaignsCache = [];
  let campaignBySession = {};
  let campaignsRefreshTimer = null;
  let sessionListCount = 0;
  const expandedCampaigns = new Set();
  let activeSidebarTab = localStorage.getItem('doppel_sidebar_tab') === 'campaigns' ? 'campaigns' : 'sessions';

  // Session replay playback state. Playback is a flat list of steps: for each
  // recorded command, a 'command' step (after the idle delay) and an 'output'
  // step (after the response time).
  const REPLAY_PAUSE_CAP_MS = 5000;
  const replay = {
    sessionId: null,
    data: null,
    steps: [],
    step: 0,
    playing: false,
    timer: null,
    armedStep: -1,
    armedAt: 0,
    armedSpeed: 1,
    remainingMs: 0,
    lines: [],
    shownEvents: 0,
    elapsedMs: 0,
    loadToken: 0,
  };

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
  const sidebarTabs = document.querySelectorAll('.sidebar-tab');
  const campaignsContainer = document.getElementById('campaigns-container');
  const campaignsEmpty = document.getElementById('campaigns-empty');
  const detailCampaignPill = document.getElementById('detail-campaign-pill');

  // DOM Elements - Replay
  const replayPlayBtn = document.getElementById('replay-play-btn');
  const replayPauseBtn = document.getElementById('replay-pause-btn');
  const replayStepBtn = document.getElementById('replay-step-btn');
  const replayResetBtn = document.getElementById('replay-reset-btn');
  const replaySpeedSelect = document.getElementById('replay-speed');
  const replaySkipIdle = document.getElementById('replay-skip-idle');
  const replayStepCur = document.getElementById('replay-step-cur');
  const replayStepTotal = document.getElementById('replay-step-total');
  const replayTimeCur = document.getElementById('replay-time-cur');
  const replayTimeTotal = document.getElementById('replay-time-total');
  const replayProgressFill = document.getElementById('replay-progress-fill');
  const replayNotice = document.getElementById('replay-notice');
  const replayTerminalWindow = document.getElementById('replay-terminal-window');
  const replayTerminalOutput = document.getElementById('replay-terminal-output');
  const emptyInspector = document.getElementById('empty-inspector');
  const sessionDetail = document.getElementById('session-detail');
  const detailLivePill = document.getElementById('detail-live-pill');
  const detailPhasePill = document.getElementById('detail-phase-pill');
  const detailProfileTag = document.getElementById('detail-profile-tag');
  const sensorTicker = document.getElementById('sensor-ticker');
  let sensorTickerTimer = null;
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
  const btnDeleteSession = document.getElementById('btn-delete-session');
  const reportToolbar = document.getElementById('report-toolbar');
  const reportStatusBadge = document.getElementById('report-status-badge');
  const reportStatusText = document.getElementById('report-status-text');
  const btnStopReport = document.getElementById('btn-stop-report');
  const btnToggleRegenReport = document.getElementById('btn-toggle-regen-report');
  const btnCopyReport = document.getElementById('btn-copy-report');
  const reportRegenCard = document.getElementById('report-regen-card');
  const reportCustomInstructions = document.getElementById('report-custom-instructions');
  const btnSubmitRegen = document.getElementById('btn-submit-regen');
  const btnCancelRegen = document.getElementById('btn-cancel-regen');
  const reportThoughtWrapper = document.getElementById('report-thought-wrapper');
  const reportThoughtDetails = document.getElementById('report-thought-details');
  const reportThoughtSummary = document.getElementById('report-thought-summary');
  const reportThoughtBody = document.getElementById('report-thought-body');

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
  const btnResetAssistant = document.getElementById('btn-reset-assistant');
  const assistantChips = document.querySelectorAll('.assistant-chip');
  const assistantChatBody = document.getElementById('assistant-chat-body');
  const assistantInputForm = document.getElementById('assistant-input-form');
  const assistantInput = document.getElementById('assistant-input');
  const btnSendAssistant = document.getElementById('btn-send-assistant');
  const btnStopAssistant = document.getElementById('btn-stop-assistant');
  let userChosenAssistantModel = localStorage.getItem('doppel_assistant_model') || '';

  // Active stream and task tracking
  let activeReportAbortController = null;
  let activeReportSessionId = null;
  let activeAssistantAbortController = null;

  // --- Signal Helpers: Kill-Chain, Profile, and Sensor Ticker ---

  function updatePhaseBadge(phaseName) {
    if (!detailPhasePill) return;
    const cleanPhase = phaseName || 'Reconnaissance';
    detailPhasePill.textContent = cleanPhase;
    detailPhasePill.className = 'phase-pill';
    const lower = cleanPhase.toLowerCase();
    if (lower.includes('privilege') || lower.includes('credential')) {
      detailPhasePill.classList.add('phase-priv-esc');
    } else if (lower.includes('exfiltration') || lower.includes('impact')) {
      detailPhasePill.classList.add('phase-exfil');
    } else if (lower.includes('execution') || lower.includes('persistence') || lower.includes('installation')) {
      detailPhasePill.classList.add('phase-exec');
    } else {
      detailPhasePill.classList.add('phase-recon');
    }
  }

  function updateProfileTag(profile) {
    if (!detailProfileTag || !profile) return;
    const type = profile.attacker_type || 'unknown';
    const conf = Math.round((profile.type_confidence || 0) * 100);
    detailProfileTag.className = 'profile-tag';

    if (type === 'bot') {
      detailProfileTag.textContent = `Bot / Script (${conf}%)`;
      detailProfileTag.classList.add('bot');
    } else if (type === 'human') {
      detailProfileTag.textContent = `Human Operator (${conf}%)`;
      detailProfileTag.classList.add('human');
    } else if (type === 'semi-automated') {
      detailProfileTag.textContent = `Automated Mass Scanner (${conf}%)`;
      detailProfileTag.classList.add('scanner');
    } else {
      detailProfileTag.textContent = 'Profiling...';
    }
  }

  function showWebProbeAlert(data) {
    if (!sensorTicker) return;
    const ip = data.remote_ip || 'unknown';
    const method = data.method || 'GET';
    const path = data.path || '/';
    const label = data.probe_label || 'probe';
    sensorTicker.innerHTML = `
      <span class="sensor-ticker-tag">HTTP SENSOR</span>
      <span>${escapeHtml(ip)} &rarr; ${escapeHtml(method)} ${escapeHtml(path)} (${escapeHtml(label)})</span>
      <span style="font-size: 10px; color: var(--text-muted);">${new Date().toLocaleTimeString()}</span>
    `;
    sensorTicker.classList.remove('hidden');
    if (sensorTickerTimer) clearTimeout(sensorTickerTimer);
    sensorTickerTimer = setTimeout(() => {
      sensorTicker.classList.add('hidden');
    }, 4000);
  }

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
  function renderMarkdown(md, isStreaming = false) {
    if (!md) return '';

    // Extract thought blocks (<think>...</think> or unclosed <think>...)
    const thinkBlocks = [];
    let text = md.replace(/<think>([\s\S]*?)(?:<\/think>|$)/gi, (match, thought) => {
      const trimmed = thought.trim();
      if (!trimmed) return '';
      const idx = thinkBlocks.length;
      const isUnclosed = !match.toLowerCase().includes('</think>');
      const summaryLabel = isUnclosed
        ? (isStreaming ? 'Thought Process' : 'Thought Process (Incomplete)')
        : 'Thought Process';
      const cursorInside = (isStreaming && isUnclosed) ? '<span class="assistant-streaming-cursor"></span>' : '';
      thinkBlocks.push(
        `<details class="thought-process"${isUnclosed ? ' open' : ''}>` +
        `<summary>${summaryLabel}</summary>` +
        `<div class="thought-body">${escapeHtml(trimmed)}${cursorInside}</div>` +
        `</details>`
      );
      return `\n@@@THINKBLOCK_${idx}@@@\n`;
    });

    // Extract code blocks first to protect formatting
    const codeBlocks = [];
    text = text.replace(/```([a-zA-Z0-9_\-]*)?\n([\s\S]*?)```/g, (match, lang, code) => {
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

      // Headers, HR, Codeblocks, Blockquotes, Thinkblocks
      if (line.startsWith('<h') || line.startsWith('<hr') || line.startsWith('<blockquote') || line.startsWith('@@@CODEBLOCK_') || line.startsWith('@@@THINKBLOCK_')) {
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

    // Restore Thought Blocks
    thinkBlocks.forEach((tb, idx) => {
      result = result.replace(`@@@THINKBLOCK_${idx}@@@`, tb);
    });

    return result;
  }

  // --- Initialize Telemetry ---
  fetchStatus();
  fetchDiagnostics();
  fetchSessions();
  fetchCampaigns();
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
      llm.models_available.forEach(m => {
        const opt = document.createElement('option');
        opt.value = m;
        opt.textContent = m;
        if (m.toLowerCase() === (llm.configured_model || '').toLowerCase()) {
          opt.selected = true;
        }
        selectLlmModel.appendChild(opt);
      });

      if (assistantModelSelect) {
        const currentSelected = userChosenAssistantModel !== '' ? userChosenAssistantModel : assistantModelSelect.value;
        const allModels = new Set(['', ...llm.models_available]);
        Array.from(assistantModelSelect.options).forEach(opt => {
          if (opt.value) allModels.add(opt.value);
        });

        assistantModelSelect.innerHTML = '';
        const defOpt = document.createElement('option');
        defOpt.value = '';
        defOpt.textContent = `Default (${llm.configured_model || 'System'})`;
        if (!currentSelected) {
          defOpt.selected = true;
        }
        assistantModelSelect.appendChild(defOpt);

        allModels.forEach(m => {
          if (!m) return;
          const aOpt = document.createElement('option');
          aOpt.value = m;
          aOpt.textContent = m;
          if (currentSelected && m.toLowerCase() === currentSelected.toLowerCase()) {
            aOpt.selected = true;
          }
          assistantModelSelect.appendChild(aOpt);
        });

        if (currentSelected) {
          assistantModelSelect.value = currentSelected;
        }
      }
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
        body: JSON.stringify({ persona: e.target.value, active_preset: e.target.value })
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
      if (config.prompt) {
        promptConfig = Object.assign({}, promptConfig, config.prompt);
      }
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
      scheduleCampaignsRefresh();
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
        appendTerminalCommand(
          data.prompt_cwd || data.cwd,
          data.command,
          data.output,
          data.decision,
          data.reasoning,
          data.prompt_user || sessionsCache[data.session_id].username
        );
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
    } else if (msg.type === 'session_closing') {
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
        setReportStatus('compiling', data.message || 'Session closed. Compiling incident report...');
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
      // The session's recording is now complete; reload replay if it is showing
      if (replay.sessionId === data.session_id) {
        replay.sessionId = null;
        if (activeSessionId === data.session_id && isTabActive('replay')) {
          loadReplay(data.session_id);
        }
      }
      fetchSessions();
      scheduleCampaignsRefresh();
    } else if (msg.type === 'session_deleted') {
      const data = msg.data;
      const deletedId = data.session_id;
      delete sessionsCache[deletedId];
      document.querySelectorAll(`.session-card[data-session-id="${deletedId}"]`).forEach(c => c.remove());
      const remainingCards = sessionsContainer.querySelectorAll('.session-card');
      sessionListCount = remainingCards.length;
      updateCountPill();
      if (remainingCards.length === 0 && sessionsEmpty) {
        sessionsEmpty.classList.remove('hidden');
      }
      scheduleCampaignsRefresh();
      if (activeSessionId === deletedId) {
        activeSessionId = null;
        localStorage.removeItem('doppel_active_session_id');
        if (sessionDetail) sessionDetail.classList.add('hidden');
        if (emptyInspector) emptyInspector.classList.remove('hidden');
        if (remainingCards.length > 0 && remainingCards[0].dataset.sessionId) {
          selectSession(remainingCards[0].dataset.sessionId);
        }
      }
    } else if (msg.type === 'honeytoken_activated') {
      const data = msg.data;
      console.warn('[CANARY TRIPWIRE ACTIVATION]', data);
      showHoneytokenNotice(data);
    } else if (msg.type === 'phase_transition') {
      const data = msg.data;
      if (sessionsCache[data.session_id]) {
        sessionsCache[data.session_id].current_phase = data.to_phase;
      }
      if (activeSessionId === data.session_id) {
        updatePhaseBadge(data.to_phase);
      }
    } else if (msg.type === 'profile_updated') {
      const data = msg.data;
      if (sessionsCache[data.session_id]) {
        sessionsCache[data.session_id].profile = data.profile;
        if (data.profile) {
          sessionsCache[data.session_id].attacker_type = data.profile.attacker_type;
          sessionsCache[data.session_id].type_confidence = data.profile.type_confidence;
        }
      }
      if (activeSessionId === data.session_id && data.profile) {
        updateProfileTag(data.profile);
      }
    } else if (msg.type === 'web_probe') {
      showWebProbeAlert(msg.data);
    }
  }

  // --- Session List & Inspector Logic ---

  function renderSessionsList(sessions) {
    sessions.forEach(s => {
      sessionsCache[s.session_id] = Object.assign(sessionsCache[s.session_id] || {}, s);
    });

    sessionListCount = sessions.length;
    updateCountPill();

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
      sessionsContainer.appendChild(buildSessionCard(sess));
    });
  }

  function threatClass(score) {
    return score >= 60 ? 'high' : (score >= 30 ? 'medium' : 'low');
  }

  function buildSessionCard(sess) {
    const card = document.createElement('div');
    card.className = `session-card ${sess.session_id === activeSessionId ? 'selected' : ''}`;
    card.dataset.sessionId = sess.session_id;

    const isLive = Boolean(sess.is_active);
    const score = sess.max_threat_score || sess.threat_score || 0;

    card.innerHTML = `
      <div class="card-top">
        <div class="card-status">
          <span class="card-status-dot ${isLive ? 'live' : 'ended'}"></span>
          <span class="card-ip">${escapeHtml(sess.remote_ip || 'unknown')}</span>
        </div>
        <span class="card-score ${threatClass(score)}">${score}</span>
      </div>
      <div class="card-bottom">
        <span>${escapeHtml(sess.username || 'user')}</span>
        <span class="card-last-cmd">${escapeHtml(sess.last_command || 'connected')}</span>
      </div>
    `;

    card.addEventListener('click', (e) => {
      e.stopPropagation();
      selectSession(sess.session_id);
    });
    return card;
  }

  function selectSession(sessionId) {
    const changed = activeSessionId !== sessionId;
    activeSessionId = sessionId;
    localStorage.setItem('doppel_active_session_id', sessionId);

    document.querySelectorAll('.session-card').forEach(card => {
      card.classList.toggle('selected', card.dataset.sessionId === sessionId);
    });

    if (changed) {
      stopReplay();
      if (isTabActive('replay')) loadReplay(sessionId);
    }
    updateCampaignPill();

    fetchSessionDetails(sessionId);
    fetchSessionReport(sessionId);
  }

  // --- Sidebar Tabs & Campaigns ---

  function updateCountPill() {
    if (!sessionCountPill) return;
    sessionCountPill.textContent = activeSidebarTab === 'campaigns' ? campaignsCache.length : sessionListCount;
  }

  function setSidebarTab(tab) {
    activeSidebarTab = tab === 'campaigns' ? 'campaigns' : 'sessions';
    localStorage.setItem('doppel_sidebar_tab', activeSidebarTab);
    sidebarTabs.forEach(btn => {
      btn.classList.toggle('active', btn.dataset.sidebar === activeSidebarTab);
    });
    sessionsContainer.classList.toggle('hidden', activeSidebarTab !== 'sessions');
    campaignsContainer.classList.toggle('hidden', activeSidebarTab !== 'campaigns');
    updateCountPill();
  }

  sidebarTabs.forEach(btn => {
    btn.addEventListener('click', () => {
      setSidebarTab(btn.dataset.sidebar);
      if (activeSidebarTab === 'campaigns') fetchCampaigns();
    });
  });
  setSidebarTab(activeSidebarTab);

  function scheduleCampaignsRefresh(delayMs = 800) {
    if (campaignsRefreshTimer) clearTimeout(campaignsRefreshTimer);
    campaignsRefreshTimer = setTimeout(() => {
      campaignsRefreshTimer = null;
      fetchCampaigns();
    }, delayMs);
  }

  async function fetchCampaigns() {
    try {
      const res = await fetch('/api/campaigns');
      if (!res.ok) return;
      const data = await res.json();
      campaignsCache = data.campaigns || [];
      campaignBySession = {};
      campaignsCache.forEach(c => {
        (c.session_ids || []).forEach(id => { campaignBySession[id] = c; });
      });
      renderCampaignsList();
      updateCampaignPill();
      updateCountPill();
    } catch (e) {
      console.error('Error fetching campaigns:', e);
    }
  }

  const LINK_REASON_LABELS = {
    shared_ip: 'Shared IP',
    shared_credentials: 'Shared credentials',
    command_sequence: 'Same command sequence',
  };

  function plural(n, one, many) {
    return `${n} ${n === 1 ? one : many}`;
  }

  function parseServerTime(value) {
    if (!value) return null;
    // Older rows may hold "YYYY-MM-DD HH:MM:SS" (UTC) instead of ISO-8601
    const normalized = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value) ? value.replace(' ', 'T') + 'Z' : value;
    const d = new Date(normalized);
    return isNaN(d.getTime()) ? null : d;
  }

  function formatRelativeTime(value) {
    const d = parseServerTime(value);
    if (!d) return '';
    const seconds = Math.round((Date.now() - d.getTime()) / 1000);
    if (seconds < 60) return 'just now';
    const minutes = Math.round(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.round(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    return `${Math.round(hours / 24)}d ago`;
  }

  function renderCampaignsList() {
    Array.from(campaignsContainer.children).forEach(child => {
      if (child.id !== 'campaigns-empty') child.remove();
    });
    campaignsEmpty.classList.toggle('hidden', campaignsCache.length > 0);

    campaignsCache.forEach(c => {
      const card = document.createElement('div');
      const expanded = expandedCampaigns.has(c.campaign_id);
      card.className = `campaign-card ${expanded ? 'expanded' : ''}`;
      card.dataset.campaignId = c.campaign_id;

      const score = c.peak_threat || 0;
      const tags = (c.link_reasons || [])
        .map(r => `<span class="campaign-tag">${escapeHtml(LINK_REASON_LABELS[r] || r)}</span>`)
        .join('');
      const lastSeen = formatRelativeTime(c.last_seen);

      card.innerHTML = `
        <div class="campaign-card-header" role="button" tabindex="0" aria-expanded="${expanded}">
          <div class="card-top">
            <div class="card-status">
              <svg class="campaign-chevron" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <polyline points="9 6 15 12 9 18"></polyline>
              </svg>
              <span class="campaign-id">${escapeHtml(c.campaign_id)}</span>
            </div>
            <span class="card-score ${threatClass(score)}">${score}</span>
          </div>
          <div class="campaign-meta">
            <span>${plural(c.session_count || 0, 'session', 'sessions')}</span>
            <span>${plural(c.unique_ips || 0, 'IP', 'IPs')}</span>
            ${lastSeen ? `<span>${escapeHtml(lastSeen)}</span>` : ''}
          </div>
          ${tags ? `<div class="campaign-tags">${tags}</div>` : ''}
        </div>
        <div class="campaign-members ${expanded ? '' : 'hidden'}"></div>
      `;

      const header = card.querySelector('.campaign-card-header');
      const members = card.querySelector('.campaign-members');
      const toggle = () => toggleCampaign(c.campaign_id, card, header, members);
      header.addEventListener('click', toggle);
      header.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          toggle();
        }
      });

      campaignsContainer.appendChild(card);
      if (expanded) loadCampaignMembers(c.campaign_id, members);
    });
  }

  function toggleCampaign(campaignId, card, header, members) {
    const expand = !expandedCampaigns.has(campaignId);
    if (expand) expandedCampaigns.add(campaignId);
    else expandedCampaigns.delete(campaignId);
    card.classList.toggle('expanded', expand);
    header.setAttribute('aria-expanded', String(expand));
    members.classList.toggle('hidden', !expand);
    if (expand) loadCampaignMembers(campaignId, members);
  }

  async function loadCampaignMembers(campaignId, container) {
    if (!container.children.length) {
      container.innerHTML = '<div class="campaign-members-status">Loading...</div>';
    }
    try {
      const res = await fetch(`/api/campaigns/${encodeURIComponent(campaignId)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      container.innerHTML = '';
      (data.sessions || []).forEach(s => {
        container.appendChild(buildSessionCard(Object.assign({}, sessionsCache[s.session_id] || {}, s)));
      });
    } catch (e) {
      container.innerHTML = '<div class="campaign-members-status">Sessions could not be loaded.</div>';
    }
  }

  function updateCampaignPill() {
    if (!detailCampaignPill) return;
    const campaign = activeSessionId ? campaignBySession[activeSessionId] : null;
    if (!campaign) {
      detailCampaignPill.classList.add('hidden');
      detailCampaignPill.dataset.campaignId = '';
      return;
    }
    detailCampaignPill.textContent = `Campaign · ${plural(campaign.session_count || 0, 'session', 'sessions')}`;
    detailCampaignPill.dataset.campaignId = campaign.campaign_id;
    detailCampaignPill.classList.remove('hidden');
  }

  if (detailCampaignPill) {
    detailCampaignPill.addEventListener('click', () => {
      const campaignId = detailCampaignPill.dataset.campaignId;
      if (!campaignId) return;
      expandedCampaigns.add(campaignId);
      setSidebarTab('campaigns');
      renderCampaignsList();
      const card = campaignsContainer.querySelector(`.campaign-card[data-campaign-id="${CSS.escape(campaignId)}"]`);
      if (card) card.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    });
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

  function setReportStatus(status, text) {
    if (!reportStatusBadge) return;
    reportStatusBadge.className = 'report-status-badge';
    const statusMap = {
      reasoning: { label: 'Reasoning', cls: 'reasoning', defText: 'Model is reasoning...' },
      compiling: { label: 'Compiling', cls: 'compiling', defText: 'Compiling report...' },
      ready: { label: 'Ready', cls: 'ready', defText: 'Report ready' },
      stopped: { label: 'Stopped', cls: 'stopped', defText: 'Generation stopped' },
      error: { label: 'Failed', cls: 'error', defText: 'Generation error' },
      neutral: { label: 'Report', cls: 'neutral', defText: '' },
    };
    const s = statusMap[status] || statusMap.neutral;
    reportStatusBadge.classList.add(s.cls);
    reportStatusBadge.textContent = s.label;
    if (reportStatusText) {
      reportStatusText.textContent = text !== undefined ? text : s.defText;
    }
  }

  function showReportEmptyState(sessionId) {
    if (reportEmpty) reportEmpty.classList.remove('hidden');
    if (reportContent) reportContent.classList.add('hidden');
    if (reportThoughtWrapper) reportThoughtWrapper.classList.add('hidden');
    setReportStatus('neutral', '');
    const isLive = sessionsCache[sessionId] && Boolean(sessionsCache[sessionId].is_active);
    if (reportEmpty) {
      reportEmpty.textContent = isLive
        ? 'Report will be compiled automatically when the session terminates. You can also generate now using the Regenerate button.'
        : 'No report has been compiled for this session yet. Click Regenerate to compile an incident report.';
    }
  }

  async function streamSessionReport(sessionId, customInstructions = '') {
    if (!sessionId) return;

    if (activeReportAbortController) {
      activeReportAbortController.abort();
      activeReportAbortController = null;
    }

    activeReportAbortController = new AbortController();
    activeReportSessionId = sessionId;

    // Reset UI for generation
    if (reportEmpty) reportEmpty.classList.add('hidden');
    if (reportContent) {
      reportContent.classList.remove('hidden');
      reportContent.innerHTML = `
        <div class="assistant-loading-indicator">
          <span class="assistant-spinner"></span>
          <span>Initiating report generation stream...</span>
        </div>
      `;
    }
    if (reportThoughtBody) reportThoughtBody.innerHTML = '';
    if (reportThoughtWrapper) reportThoughtWrapper.classList.add('hidden');
    if (reportThoughtDetails) reportThoughtDetails.open = true;
    if (reportThoughtSummary) reportThoughtSummary.textContent = 'Model Reasoning';

    if (btnStopReport) btnStopReport.classList.remove('hidden');
    if (btnToggleRegenReport) btnToggleRegenReport.classList.add('hidden');
    if (reportRegenCard) reportRegenCard.classList.add('hidden');
    setReportStatus('reasoning', 'Initiating analysis...');

    let accumulatedThought = '';
    let accumulatedContent = '';

    try {
      const activeModel = (selectLlmModel && selectLlmModel.value) || (assistantModelSelect && assistantModelSelect.value) || '';
      const payload = {
        custom_instructions: customInstructions || null,
        model: activeModel || null,
      };

      const res = await fetch(`/api/sessions/${sessionId}/report/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: activeReportAbortController.signal,
      });

      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }
      if (!res.body) {
        throw new Error('Streaming response body is unavailable');
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || !trimmed.startsWith('data:')) continue;
          const dataStr = trimmed.slice(5).trim();
          if (!dataStr) continue;

          try {
            const chunk = JSON.parse(dataStr);
            if (chunk.stage === 'reasoning') {
              setReportStatus('reasoning', 'Model is reasoning...');
              const piece = chunk.thought || chunk.delta || '';
              if (piece) {
                accumulatedThought += piece;
                if (reportThoughtWrapper) reportThoughtWrapper.classList.remove('hidden');
                if (reportThoughtBody) {
                  reportThoughtBody.innerHTML = renderMarkdown(accumulatedThought, true) + '<span class="assistant-streaming-cursor"></span>';
                }
              }
            } else if (chunk.stage === 'compiling') {
              setReportStatus('compiling', 'Compiling markdown report...');
              const piece = chunk.content || chunk.delta || '';
              if (piece) {
                accumulatedContent += piece;
                if (reportContent) {
                  reportContent.innerHTML = renderMarkdown(accumulatedContent, true) + '<span class="assistant-streaming-cursor"></span>';
                }
              }
            } else if (chunk.stage === 'ready' || chunk.stage === 'completed' || chunk.done) {
              const finalReport = chunk.report || chunk.content || accumulatedContent;
              if (finalReport) {
                accumulatedContent = finalReport;
              }
              setReportStatus('ready', 'Completed');
              if (reportContent) {
                reportContent.innerHTML = renderMarkdown(accumulatedContent || 'Incident report completed.', false);
              }
              if (reportThoughtBody && accumulatedThought) {
                reportThoughtBody.innerHTML = renderMarkdown(accumulatedThought, false);
              }
            } else if (chunk.stage === 'stopped' || chunk.stopped) {
              setReportStatus('stopped', chunk.message || 'Generation stopped');
              if (reportContent && accumulatedContent) {
                reportContent.innerHTML = renderMarkdown(accumulatedContent, false) +
                  '<div style="color: var(--accent-orange); margin-top: 12px; font-size: 11px;">[Generation stopped by user]</div>';
              }
            } else if (chunk.stage === 'error' || chunk.error) {
              setReportStatus('error', chunk.error || 'Generation failed');
              if (reportContent) {
                reportContent.innerHTML = `<div style="color: var(--accent-red); padding: 12px;">Failed to generate report: ${escapeHtml(chunk.error || 'Unknown error')}</div>`;
              }
            }
          } catch (jsonErr) {
            // Ignore partial JSON
          }
        }
      }

      if (accumulatedContent && reportContent) {
        if (reportEmpty) reportEmpty.classList.add('hidden');
        reportContent.classList.remove('hidden');
        reportContent.innerHTML = renderMarkdown(accumulatedContent, false);
      } else if (!accumulatedContent && activeSessionId === sessionId) {
        await fetchSessionReport(sessionId);
      }
      if (accumulatedThought && reportThoughtBody) {
        reportThoughtBody.innerHTML = renderMarkdown(accumulatedThought, false);
      }
    } catch (err) {
      if (err.name === 'AbortError') {
        setReportStatus('stopped', 'Generation stopped by user');
        if (reportContent && accumulatedContent) {
          reportContent.innerHTML = renderMarkdown(accumulatedContent, false) +
            '<div style="color: var(--accent-orange); margin-top: 12px; font-size: 11px;">[Generation stopped by user]</div>';
        }
      } else {
        setReportStatus('error', err.message || 'Error streaming report');
        if (reportContent) {
          reportContent.innerHTML = `<div style="color: var(--accent-red); padding: 12px;">Report generation failed: ${escapeHtml(err.message)}</div>`;
        }
      }
    } finally {
      activeReportAbortController = null;
      if (btnStopReport) btnStopReport.classList.add('hidden');
      if (btnToggleRegenReport) btnToggleRegenReport.classList.remove('hidden');
    }
  }

  async function fetchSessionReport(sessionId) {
    if (activeReportSessionId === sessionId && activeReportAbortController) {
      return; // Generation actively streaming
    }

    try {
      const res = await fetch(`/api/sessions/${sessionId}/report`);
      if (res.status === 202) {
        setReportStatus('compiling', 'Compiling incident report...');
        if (reportEmpty) reportEmpty.classList.add('hidden');
        if (reportContent) {
          reportContent.classList.remove('hidden');
          reportContent.innerHTML = `
            <div class="assistant-loading-indicator">
              <span class="assistant-spinner"></span>
              <span>Compiling incident report in background...</span>
            </div>
          `;
        }
        setTimeout(() => {
          if (activeSessionId === sessionId && !activeReportAbortController) {
            fetchSessionReport(sessionId);
          }
        }, 3000);
        return;
      }
      if (res.ok) {
        const markdown = await res.text();
        if (markdown && markdown.trim()) {
          reportEmpty.classList.add('hidden');
          reportContent.classList.remove('hidden');
          reportContent.innerHTML = renderMarkdown(markdown);
          if (reportThoughtWrapper) reportThoughtWrapper.classList.add('hidden');
          setReportStatus('ready', 'Completed');
        } else {
          showReportEmptyState(sessionId);
        }
      } else {
        showReportEmptyState(sessionId);
      }
    } catch (e) {
      showReportEmptyState(sessionId);
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

    updatePhaseBadge(session.current_phase || (sessionsCache[session.session_id] && sessionsCache[session.session_id].current_phase) || 'Reconnaissance');
    updateProfileTag({
      attacker_type: session.attacker_type || (sessionsCache[session.session_id] && sessionsCache[session.session_id].attacker_type),
      type_confidence: session.type_confidence || (sessionsCache[session.session_id] && sessionsCache[session.session_id].type_confidence),
    });

    const serverCmds = session.commands || [];
    const currentTerminalLines = terminalOutput.children.length;
    if (serverCmds.length > 0 || currentTerminalLines === 0) {
      terminalOutput.innerHTML = '';
      serverCmds.forEach(cmd => {
        appendTerminalCommand(
          cmd.cwd || session.cwd,
          cmd.command,
          cmd.output,
          cmd.route_decision,
          cmd.reasoning,
          cmd.prompt_user || session.username
        );
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

  // Render the shell prompt the way the SSH server does (see ssh_server._get_prompt)
  function formatPrompt(user, cwd) {
    const name = user || 'ubuntu';
    const isRoot = name === 'root';
    const home = isRoot ? '/root' : `/home/${name}`;
    let shownCwd = cwd || home;
    if (shownCwd === home) shownCwd = '~';
    else if (shownCwd.startsWith(home + '/')) shownCwd = '~' + shownCwd.slice(home.length);
    const fmt = (isRoot ? promptConfig.root_format : promptConfig.format) || '{user}@{hostname}:{cwd}$ ';
    return fmt
      .replace(/\{user\}/g, name)
      .replace(/\{hostname\}/g, promptConfig.hostname || '')
      .replace(/\{cwd\}/g, shownCwd);
  }

  const ROUTE_TAGS = {
    sandbox: { cls: 'sandbox', label: 'Sandbox' },
    grounded_deception: { cls: 'grounded', label: 'Grounded' },
    builtin: { cls: 'builtin', label: 'Builtin' },
  };

  function buildTerminalLine({ cwd, user, command, output = null, decision, reasoning = null }) {
    const line = document.createElement('div');
    line.className = 'terminal-line';
    const route = ROUTE_TAGS[decision] || { cls: 'deception', label: 'Deception' };

    let reasoningHtml = '';
    if (reasoning) {
      reasoningHtml = `
        <details class="terminal-reasoning-details">
          <summary class="terminal-reasoning-summary">Model Reasoning</summary>
          <div class="terminal-reasoning-content">${escapeHtml(reasoning)}</div>
        </details>
      `;
    }

    line.innerHTML = `
      <div>
        <span class="terminal-prompt">${escapeHtml(formatPrompt(user, cwd))}</span>
        <span class="terminal-cmd">${escapeHtml(command)}</span>
        <span class="terminal-route-tag ${route.cls}">${route.label}</span>
      </div>
      ${reasoningHtml}
    `;
    setTerminalLineOutput(line, output);
    return line;
  }

  function setTerminalLineOutput(line, output) {
    if (!output) return;
    const block = document.createElement('div');
    block.className = 'terminal-output-block';
    block.innerHTML = escapeHtml(output).replace(/\r\n/g, '\n');
    line.appendChild(block);
  }

  function appendTerminalCommand(cwd, command, output, decision, reasoning = null, user = null) {
    terminalOutput.appendChild(buildTerminalLine({ cwd, user, command, output, decision, reasoning }));
    terminalWindow.scrollTop = terminalWindow.scrollHeight;
  }

  // --- Session Replay ---

  function isTabActive(tab) {
    const btn = document.querySelector(`.tab-btn[data-tab="${tab}"]`);
    return Boolean(btn && btn.classList.contains('active'));
  }

  function formatClock(ms) {
    const total = Math.max(0, Math.round((ms || 0) / 1000));
    const h = Math.floor(total / 3600);
    const m = Math.floor((total % 3600) / 60);
    const s = String(total % 60).padStart(2, '0');
    return h > 0 ? `${h}:${String(m).padStart(2, '0')}:${s}` : `${m}:${s}`;
  }

  function showReplayNotice(text) {
    replayNotice.textContent = text || '';
    replayNotice.classList.toggle('hidden', !text);
  }

  function clearReplayTimer() {
    if (replay.timer) {
      clearTimeout(replay.timer);
      replay.timer = null;
    }
  }

  // Stop the countdown for the current step but remember how much is left
  function holdReplayTimer() {
    if (!replay.timer) return;
    clearReplayTimer();
    const elapsedReal = performance.now() - replay.armedAt;
    replay.remainingMs = Math.max(0, replay.remainingMs - elapsedReal * replay.armedSpeed);
  }

  function replaySpeed() {
    return parseFloat(replaySpeedSelect.value) || 1;
  }

  function replayWaitFor(step) {
    const wait = step.wait || 0;
    return replaySkipIdle.checked ? Math.min(wait, REPLAY_PAUSE_CAP_MS) : wait;
  }

  function replayAvailable() {
    return Boolean(replay.data && replay.steps.length);
  }

  function updateReplayControls() {
    const available = replayAvailable();
    const atEnd = replay.step >= replay.steps.length;
    replayPlayBtn.classList.toggle('hidden', replay.playing);
    replayPauseBtn.classList.toggle('hidden', !replay.playing);
    replayPlayBtn.disabled = !available;
    replayStepBtn.disabled = !available || atEnd;
    replayResetBtn.disabled = !available || replay.step === 0;
    replaySpeedSelect.disabled = !available;
    replaySkipIdle.disabled = !available;
  }

  function updateReplayProgress() {
    const events = replay.data ? replay.data.events || [] : [];
    replayStepCur.textContent = replay.shownEvents;
    replayStepTotal.textContent = events.length;
    replayTimeCur.textContent = formatClock(replay.elapsedMs);
    replayTimeTotal.textContent = formatClock(replay.data ? replay.data.total_duration_ms : 0);
    const pct = replay.steps.length ? (replay.step / replay.steps.length) * 100 : 0;
    replayProgressFill.style.width = `${pct}%`;
  }

  function resetReplay() {
    clearReplayTimer();
    replay.playing = false;
    replay.step = 0;
    replay.armedStep = -1;
    replay.remainingMs = 0;
    replay.lines = [];
    replay.shownEvents = 0;
    replay.elapsedMs = 0;
    replayTerminalOutput.innerHTML = '';

    if (replay.data && replay.steps.length) {
      const started = parseServerTime(replay.data.start_time);
      const header = document.createElement('div');
      header.className = 'replay-session-start';
      header.textContent = [
        started ? `Session started ${started.toLocaleString()}` : 'Session started',
        replay.data.remote_ip ? `from ${replay.data.remote_ip}` : '',
        replay.data.username ? `as ${replay.data.username}` : '',
      ].filter(Boolean).join(' ');
      replayTerminalOutput.appendChild(header);
    }
    updateReplayControls();
    updateReplayProgress();
  }

  // Full stop when leaving a session; the replay reloads when next shown
  function stopReplay() {
    clearReplayTimer();
    replay.loadToken += 1;
    replay.sessionId = null;
    replay.data = null;
    replay.steps = [];
    showReplayNotice('');
    resetReplay();
  }

  async function loadReplay(sessionId) {
    if (!sessionId) return;
    clearReplayTimer();
    const token = ++replay.loadToken;
    replay.sessionId = sessionId;
    replay.data = null;
    replay.steps = [];
    resetReplay();

    const cached = sessionsCache[sessionId];
    if (cached && cached.is_active) {
      showReplayNotice('Replay is available after the session ends.');
      return;
    }

    showReplayNotice('Loading replay...');
    try {
      const res = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/replay`);
      if (token !== replay.loadToken) return;
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (token !== replay.loadToken) return;

      replay.data = data;
      replay.steps = [];
      (data.events || []).forEach((ev, i) => {
        replay.steps.push({ kind: 'command', i, wait: ev.delay_ms || 0 });
        replay.steps.push({ kind: 'output', i, wait: ev.duration_ms || 0 });
      });
      showReplayNotice(replay.steps.length ? '' : 'No commands were recorded in this session.');
      resetReplay();
    } catch (e) {
      if (token !== replay.loadToken) return;
      console.error('Error loading replay:', e);
      showReplayNotice('Replay could not be loaded.');
    }
  }

  function executeReplayStep(step) {
    const ev = replay.data.events[step.i];
    if (step.kind === 'command') {
      const line = buildTerminalLine({
        cwd: ev.cwd,
        user: ev.prompt_user || replay.data.username,
        command: ev.command,
        decision: ev.route_decision,
      });
      line.classList.add('awaiting-output');
      replayTerminalOutput.appendChild(line);
      replay.lines[step.i] = line;
      replay.shownEvents = step.i + 1;
      replay.elapsedMs += ev.delay_ms || 0;
    } else {
      const line = replay.lines[step.i];
      if (line) {
        line.classList.remove('awaiting-output');
        setTerminalLineOutput(line, ev.output);
      }
      replay.elapsedMs += ev.duration_ms || 0;
    }
    replayTerminalWindow.scrollTop = replayTerminalWindow.scrollHeight;
  }

  function scheduleReplayStep() {
    if (!replay.playing) return;
    if (replay.step >= replay.steps.length) {
      replay.playing = false;
      updateReplayControls();
      return;
    }
    if (replay.armedStep !== replay.step) {
      replay.armedStep = replay.step;
      replay.remainingMs = replayWaitFor(replay.steps[replay.step]);
    }
    replay.armedAt = performance.now();
    replay.armedSpeed = replaySpeed();
    replay.timer = setTimeout(() => {
      replay.timer = null;
      executeReplayStep(replay.steps[replay.step]);
      replay.step += 1;
      updateReplayProgress();
      updateReplayControls();
      scheduleReplayStep();
    }, replay.remainingMs / replay.armedSpeed);
  }

  function playReplay() {
    if (!replayAvailable()) return;
    if (replay.step >= replay.steps.length) resetReplay();
    replay.playing = true;
    updateReplayControls();
    scheduleReplayStep();
  }

  function pauseReplay() {
    holdReplayTimer();
    replay.playing = false;
    updateReplayControls();
  }

  // Show the rest of the current command (its prompt line and output) immediately
  function stepReplay() {
    if (!replayAvailable() || replay.step >= replay.steps.length) return;
    clearReplayTimer();
    replay.playing = false;
    const first = replay.steps[replay.step];
    executeReplayStep(first);
    replay.step += 1;
    if (first.kind === 'command' && replay.step < replay.steps.length) {
      executeReplayStep(replay.steps[replay.step]);
      replay.step += 1;
    }
    replay.armedStep = -1;
    updateReplayProgress();
    updateReplayControls();
  }

  replayPlayBtn.addEventListener('click', playReplay);
  replayPauseBtn.addEventListener('click', pauseReplay);
  replayStepBtn.addEventListener('click', stepReplay);
  replayResetBtn.addEventListener('click', resetReplay);

  // Speed and pause-skipping apply to the step already counting down
  replaySpeedSelect.addEventListener('change', () => {
    if (replay.playing && replay.timer) {
      holdReplayTimer();
      scheduleReplayStep();
    }
  });
  replaySkipIdle.addEventListener('change', () => {
    if (replay.playing && replay.timer && replaySkipIdle.checked) {
      holdReplayTimer();
      replay.remainingMs = Math.min(replay.remainingMs, REPLAY_PAUSE_CAP_MS);
      scheduleReplayStep();
    }
  });

  updateReplayControls();
  updateReplayProgress();

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

      if (btn.dataset.tab === 'report' && activeSessionId) {
        if (!activeReportAbortController) {
          fetchSessionReport(activeSessionId);
        }
      }

      if (btn.dataset.tab === 'replay') {
        if (activeSessionId && replay.sessionId !== activeSessionId) {
          loadReplay(activeSessionId);
        }
      } else if (replay.playing) {
        pauseReplay();
      }

    });
  });

  // --- Attack Session Management & Report Toolbar Controls ---
  if (btnDeleteSession) {
    btnDeleteSession.addEventListener('click', async () => {
      if (!activeSessionId) return;
      const targetId = activeSessionId;
      const confirmed = confirm(
        `Are you sure you want to delete session ${targetId}?\nThis will permanently delete the attack session, command history, MITRE telemetry, and generated reports from the database.`
      );
      if (!confirmed) return;

      try {
        btnDeleteSession.disabled = true;
        const res = await fetch(`/api/sessions/${targetId}`, { method: 'DELETE' });
        if (!res.ok) {
          throw new Error(`Failed to delete session (HTTP ${res.status})`);
        }

        delete sessionsCache[targetId];
        document.querySelectorAll(`.session-card[data-session-id="${targetId}"]`).forEach(c => c.remove());

        const remainingCards = sessionsContainer.querySelectorAll('.session-card');
        sessionListCount = remainingCards.length;
        updateCountPill();
        scheduleCampaignsRefresh();

        if (activeSessionId === targetId) {
          activeSessionId = null;
          localStorage.removeItem('doppel_active_session_id');
          if (sessionDetail) sessionDetail.classList.add('hidden');
          if (emptyInspector) emptyInspector.classList.remove('hidden');

          if (remainingCards.length > 0) {
            const nextId = remainingCards[0].dataset.sessionId;
            if (nextId) selectSession(nextId);
          } else {
            if (sessionsEmpty) sessionsEmpty.classList.remove('hidden');
          }
        }
      } catch (err) {
        alert(`Error deleting session: ${err.message}`);
      } finally {
        btnDeleteSession.disabled = false;
      }
    });
  }

  if (btnStopReport) {
    btnStopReport.addEventListener('click', async () => {
      if (activeReportAbortController) {
        activeReportAbortController.abort();
        activeReportAbortController = null;
      }
      if (activeSessionId) {
        try {
          await fetch(`/api/sessions/${activeSessionId}/report/stop`, { method: 'POST' });
        } catch (e) {
          console.warn('Error stopping server report task:', e);
        }
      }
      setReportStatus('stopped', 'Generation stopped by user');
      if (btnStopReport) btnStopReport.classList.add('hidden');
      if (btnToggleRegenReport) btnToggleRegenReport.classList.remove('hidden');
    });
  }

  if (btnToggleRegenReport) {
    btnToggleRegenReport.addEventListener('click', () => {
      if (!reportRegenCard) return;
      reportRegenCard.classList.toggle('hidden');
      if (!reportRegenCard.classList.contains('hidden') && reportCustomInstructions) {
        reportCustomInstructions.focus();
      }
    });
  }

  if (btnCancelRegen) {
    btnCancelRegen.addEventListener('click', () => {
      if (reportRegenCard) reportRegenCard.classList.add('hidden');
    });
  }

  if (btnSubmitRegen) {
    btnSubmitRegen.addEventListener('click', () => {
      if (!activeSessionId) return;
      const instructions = reportCustomInstructions ? reportCustomInstructions.value.trim() : '';
      streamSessionReport(activeSessionId, instructions);
    });
  }

  if (btnCopyReport) {
    btnCopyReport.addEventListener('click', async () => {
      if (!activeSessionId) return;
      try {
        const res = await fetch(`/api/sessions/${activeSessionId}/report`);
        let textToCopy = '';
        if (res.ok) {
          textToCopy = await res.text();
        } else if (reportContent && !reportContent.classList.contains('hidden')) {
          textToCopy = reportContent.innerText || reportContent.textContent || '';
        }
        if (textToCopy) {
          await navigator.clipboard.writeText(textToCopy);
          const originalTitle = btnCopyReport.getAttribute('title') || 'Copy report markdown';
          btnCopyReport.setAttribute('title', 'Copied to clipboard!');
          const labelSpan = btnCopyReport.querySelector('span');
          if (labelSpan) {
            const originalText = labelSpan.textContent;
            labelSpan.textContent = 'Copied!';
            setTimeout(() => {
              labelSpan.textContent = originalText;
              btnCopyReport.setAttribute('title', originalTitle);
            }, 1800);
          }
        }
      } catch (err) {
        console.warn('Clipboard copy failed:', err);
      }
    });
  }

  // --- AI Assistant & Benchmark Console Logic ---
  function syncAssistantModels() {
    if (!assistantModelSelect) return;
    const currentSelected = userChosenAssistantModel !== '' ? userChosenAssistantModel : assistantModelSelect.value;

    if (selectLlmModel && selectLlmModel.options.length > 0) {
      const existingValues = new Set(Array.from(assistantModelSelect.options).map(o => o.value));
      Array.from(selectLlmModel.options).forEach(opt => {
        if (opt.value && !existingValues.has(opt.value)) {
          const aOpt = document.createElement('option');
          aOpt.value = opt.value;
          aOpt.textContent = opt.textContent;
          assistantModelSelect.appendChild(aOpt);
        }
      });
    }

    if (currentSelected) {
      assistantModelSelect.value = currentSelected;
    }
  }

  if (assistantModelSelect) {
    if (userChosenAssistantModel) {
      assistantModelSelect.value = userChosenAssistantModel;
    }
    assistantModelSelect.addEventListener('change', (e) => {
      userChosenAssistantModel = e.target.value;
      localStorage.setItem('doppel_assistant_model', userChosenAssistantModel);
    });
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

    // 2. Setup Assistant Response Message Bubble with live metrics bar
    const targetModel = (assistantModelSelect && assistantModelSelect.value) ? assistantModelSelect.value : (userChosenAssistantModel || '');

    const botMsg = document.createElement('div');
    botMsg.className = 'assistant-msg assistant-msg-bot';

    const bubble = document.createElement('div');
    bubble.className = 'assistant-bubble';
    bubble.innerHTML = `
      <div class="assistant-loading-indicator">
        <span class="assistant-spinner"></span>
        <span>Connecting to inference stream${targetModel ? ` (${escapeHtml(targetModel)})` : ''}...</span>
      </div>
    `;
    botMsg.appendChild(bubble);

    const metricsBar = document.createElement('div');
    metricsBar.className = 'assistant-metrics-bar hidden';
    botMsg.appendChild(metricsBar);

    assistantChatBody.appendChild(botMsg);
    assistantChatBody.scrollTop = assistantChatBody.scrollHeight;

    // Setup AbortController for user-controlled stream stopping
    if (activeAssistantAbortController) {
      activeAssistantAbortController.abort();
      activeAssistantAbortController = null;
    }
    activeAssistantAbortController = new AbortController();

    // Disable input while running and toggle send/stop buttons
    assistantInput.disabled = true;
    if (btnSendAssistant) btnSendAssistant.classList.add('hidden');
    if (btnStopAssistant) {
      btnStopAssistant.classList.remove('hidden');
      btnStopAssistant.disabled = false;
    }

    let accumulatedText = '';
    let lastMetrics = null;

    try {
      const payload = { message: text };
      if (targetModel) {
        payload.model = targetModel;
      }

      const res = await fetch('/api/chat-assistant/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: activeAssistantAbortController.signal,
      });

      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }

      if (!res.body) {
        throw new Error('Streaming response body is unavailable');
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop(); // Keep incomplete partial line in buffer

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || !trimmed.startsWith('data:')) continue;
          const dataStr = trimmed.slice(5).trim();
          if (!dataStr) continue;

          try {
            const chunk = JSON.parse(dataStr);
            if (chunk.error) {
              throw new Error(chunk.error);
            }

            if (chunk.delta) {
              accumulatedText += chunk.delta;
            }

            lastMetrics = chunk;

            if (accumulatedText) {
              const isInsideThink = accumulatedText.lastIndexOf('<think>') > accumulatedText.lastIndexOf('</think>');
              const renderedHtml = renderMarkdown(accumulatedText, !chunk.done);
              const cursorHtml = (!chunk.done && !isInsideThink)
                ? '<span class="assistant-streaming-cursor"></span>'
                : '';
              bubble.innerHTML = (renderedHtml || '') + cursorHtml;

              const speedStr = (typeof chunk.tokens_per_second === 'number' && chunk.tokens_per_second > 0)
                ? `${chunk.tokens_per_second.toFixed(1)} tok/s` : '';
              const latencyStr = typeof chunk.latency_seconds === 'number'
                ? `${chunk.latency_seconds.toFixed(2)}s latency` : '';
              const tokensStr = (typeof chunk.tokens === 'number' && chunk.tokens > 0)
                ? `${chunk.tokens} tokens` : '';
              const modelStr = chunk.model || targetModel || 'default';

              metricsBar.className = 'assistant-metrics-bar';
              metricsBar.innerHTML = `
                ${speedStr ? `<span class="metric-pill speed ${chunk.done ? '' : 'streaming'}">${speedStr}</span>` : ''}
                ${latencyStr ? `<span class="metric-pill latency">${latencyStr}</span>` : ''}
                ${tokensStr ? `<span class="metric-pill tokens">${tokensStr}</span>` : ''}
                <span class="metric-pill model">${escapeHtml(modelStr)}</span>
              `;
            }

            assistantChatBody.scrollTop = assistantChatBody.scrollHeight;
          } catch (jsonErr) {
            if (jsonErr.message && !jsonErr.message.includes('JSON')) {
              throw jsonErr;
            }
          }
        }
      }

      // Finalization pass upon stream completion
      bubble.innerHTML = renderMarkdown(accumulatedText || '(Empty response)', false);
      if (lastMetrics) {
        const speedStr = (typeof lastMetrics.tokens_per_second === 'number' && lastMetrics.tokens_per_second > 0)
          ? `${lastMetrics.tokens_per_second.toFixed(1)} tok/s` : '';
        const latencyStr = typeof lastMetrics.latency_seconds === 'number'
          ? `${lastMetrics.latency_seconds.toFixed(2)}s latency` : '';
        const tokensStr = (typeof lastMetrics.tokens === 'number' && lastMetrics.tokens > 0)
          ? `${lastMetrics.tokens} tokens` : '';
        const modelStr = lastMetrics.model || targetModel || 'default';

        metricsBar.className = 'assistant-metrics-bar';
        metricsBar.innerHTML = `
          ${speedStr ? `<span class="metric-pill speed">${speedStr}</span>` : ''}
          ${latencyStr ? `<span class="metric-pill latency">${latencyStr}</span>` : ''}
          ${tokensStr ? `<span class="metric-pill tokens">${tokensStr}</span>` : ''}
          <span class="metric-pill model">${escapeHtml(modelStr)}</span>
        `;
      }
    } catch (err) {
      if (err.name === 'AbortError') {
        bubble.innerHTML = renderMarkdown(accumulatedText || '', false) +
          '<div style="color: var(--accent-orange); margin-top: 8px; font-size: 11px;">[Output stopped by user]</div>';
      } else if (!accumulatedText) {
        bubble.innerHTML = `Failed to query assistant: ${escapeHtml(err.message || 'Unknown network error')}`;
        bubble.style.borderColor = 'var(--accent-red)';
        bubble.style.color = 'var(--accent-red)';
      } else {
        bubble.innerHTML = renderMarkdown(accumulatedText, false) +
          `<div style="color: var(--accent-red); margin-top: 8px; font-size: 11px;">[Stream interrupted: ${escapeHtml(err.message)}]</div>`;
      }
    } finally {
      if (btnStopAssistant) btnStopAssistant.classList.add('hidden');
      if (btnSendAssistant) {
        btnSendAssistant.classList.remove('hidden');
        btnSendAssistant.disabled = false;
      }
      activeAssistantAbortController = null;
      assistantInput.disabled = false;
      assistantInput.focus();
      assistantChatBody.scrollTop = assistantChatBody.scrollHeight;
    }
  }

  if (btnStopAssistant) {
    btnStopAssistant.addEventListener('click', async () => {
      if (activeAssistantAbortController) {
        activeAssistantAbortController.abort();
        activeAssistantAbortController = null;
      }
      try {
        await fetch('/api/chat-assistant/stop', { method: 'POST' });
      } catch (e) {
        console.warn('Error sending stop chat assistant:', e);
      }
      if (btnStopAssistant) btnStopAssistant.classList.add('hidden');
      if (btnSendAssistant) {
        btnSendAssistant.classList.remove('hidden');
        btnSendAssistant.disabled = false;
      }
      if (assistantInput) {
        assistantInput.disabled = false;
        assistantInput.focus();
      }
    });
  }

  if (assistantInputForm) {
    assistantInputForm.addEventListener('submit', (e) => {
      e.preventDefault();
      sendAssistantMessage(assistantInput.value);
    });
  }

  if (btnResetAssistant) {
    btnResetAssistant.addEventListener('click', () => {
      if (assistantChatBody) {
        assistantChatBody.innerHTML = `
          <div class="assistant-msg assistant-msg-system">
            <div class="assistant-bubble">
              Chat history cleared. Test inference speed across models or query honeypot telemetry, attacker behaviors, and defensive recommendations.
            </div>
          </div>
        `;
      }
      if (assistantInput) {
        assistantInput.value = '';
        assistantInput.focus();
      }
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


  function showHoneytokenNotice(data) {
    if (systemWarningBanner && warningBannerMessages) {
      warningBannerMessages.innerHTML = `
        <div class="warning-banner-item">
          <strong>TRIPWIRE ACTIVATION:</strong> Decoy Honeytoken (${escapeHtml(data.token_type)}) was triggered by <code>${escapeHtml(data.remote_ip)}</code> via ${escapeHtml(data.method)} /auth/v1/verify
        </div>
      `;
      systemWarningBanner.classList.remove('hidden');
    }
  }

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

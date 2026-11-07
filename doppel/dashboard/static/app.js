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
  const navBadgeLlm = document.getElementById('nav-badge-llm');
  const dotNavLlm = document.getElementById('dot-nav-llm');
  const textNavLlm = document.getElementById('text-nav-llm');
  const navBadgeDocker = document.getElementById('nav-badge-docker');
  const dotNavDocker = document.getElementById('dot-nav-docker');
  const textNavDocker = document.getElementById('text-nav-docker');
  const btnToggle = document.getElementById('btn-toggle-honeypot');
  const btnToggleLabel = document.getElementById('btn-toggle-label');
  // Model badge: name from /api/status, health from /api/diagnostics
  let currentModel = '';
  let lastLlmDiag = null;

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
  const detailThreatBar = document.getElementById('detail-threat-bar');
  const detailStarted = document.getElementById('detail-started');
  const detailCampaignNone = document.getElementById('detail-campaign-none');
  const btnCopySessionId = document.getElementById('btn-copy-session-id');
  const btnSessionMenu = document.getElementById('btn-session-menu');
  const sessionMenu = document.getElementById('session-menu');
  const sessionSearch = document.getElementById('session-search');
  const sessionLiveOnly = document.getElementById('session-live-only');
  const hintPort = document.getElementById('hint-port');
  const btnTestModelSpeed = document.getElementById('btn-test-model-speed');
  const btnLaunchPrimaryLabel = document.getElementById('btn-launch-primary-label');
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

  // Below this confidence the label is shown as tentative
  const PROFILE_CONFIDENT = 0.75;

  function updateProfileTag(profile) {
    if (!detailProfileTag || !profile) return;
    const type = profile.attacker_type || 'unknown';
    const conf = Math.round((profile.type_confidence || 0) * 100);
    const labels = { bot: 'Automated', human: 'Human', 'semi-automated': 'Semi-automated' };
    detailProfileTag.className = 'profile-tag';
    const sub = document.getElementById('detail-profile-sub');

    if (!labels[type]) {
      detailProfileTag.textContent = 'Profiling';
      detailProfileTag.title = 'Not enough commands to classify yet';
      if (sub) sub.textContent = 'Needs a few more commands';
      return;
    }
    const tentative = (profile.type_confidence || 0) < PROFILE_CONFIDENT;
    detailProfileTag.textContent = tentative ? `Likely ${labels[type].toLowerCase()}` : labels[type];
    detailProfileTag.classList.add(type === 'bot' ? 'bot' : (type === 'human' ? 'human' : 'scanner'));
    detailProfileTag.title = `Confidence ${conf}%`;
    if (sub) sub.textContent = `${conf}% confidence`;
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
      btnViewSwitchLabel.textContent = 'Dashboard';
    } else {
      viewLaunch.classList.add('hidden');
      viewDashboard.classList.remove('hidden');
      document.documentElement.classList.add('init-dashboard');
      btnViewSwitchLabel.textContent = 'Settings';
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
      renderBackgroundQueue(data.background);
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
    lastLlmDiag = llm;
    renderModelBadge();
    renderReasoningToggle(llm);

    if (navBadgeDocker && dotNavDocker && textNavDocker) {
      if (docker.status === 'ready') {
        dotNavDocker.className = 'subsystem-dot ready';
        textNavDocker.textContent = 'Sandbox';
        navBadgeDocker.title = `Sandbox ready (Docker ${docker.version || 'Engine'})`;
      } else if (docker.status === 'disabled') {
        dotNavDocker.className = 'subsystem-dot neutral';
        textNavDocker.textContent = 'Sandbox off';
        navBadgeDocker.title = 'Sandbox disabled in configuration: every command is simulated';
      } else {
        dotNavDocker.className = 'subsystem-dot warning';
        textNavDocker.textContent = 'Sandbox offline';
        navBadgeDocker.title = 'Docker is not running: every command is simulated';
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

    // While the honeypot runs, the port is held by Doppel itself
    const listening = honeypotStatus === 'RUNNING';
    if (!port.available && !listening) {
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
    if ((!llm.models_available || llm.models_available.length === 0) && llm.configured_model && !selectLlmModel.options.length) {
      const opt = document.createElement('option');
      opt.value = llm.configured_model;
      opt.textContent = llm.configured_model;
      selectLlmModel.appendChild(opt);
    }
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
    if (docker.status === 'ready' || docker.status === 'disabled') {
      const enabled = docker.status === 'ready';
      pillDocker.className = enabled ? 'diag-pill ready' : 'diag-pill neutral';
      pillDocker.textContent = enabled ? 'Sandbox On' : 'Sandbox Off';
      descDocker.textContent = docker.detail;
      actionBarDocker.innerHTML = `
        <label class="switch-row">
          <input type="checkbox" class="switch-input" id="toggle-sandbox" ${enabled ? 'checked' : ''}>
          <span class="switch-track" aria-hidden="true"></span>
          <span class="switch-text">
            <span class="switch-label">Run commands in the sandbox</span>
            <span class="control-hint">${enabled
              ? 'Ordinary commands run in a disposable container with no network.'
              : 'Every command is answered by the model.'}</span>
          </span>
        </label>
      `;
      document.getElementById('toggle-sandbox')?.addEventListener('change', (e) => {
        applyQuickFix('toggle_sandbox', e.target.checked);
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
    if (hintPort) {
      hintPort.textContent = listening ? 'Applying a new port restarts the listener.' : '';
    }
    if (listening) {
      pillPort.className = 'diag-pill ready';
      pillPort.textContent = `Listening on ${port.port}`;
      descPort.textContent = `The SSH listener is accepting connections on port ${port.port}.`;
      actionBarPort.innerHTML = '';
    } else if (port.available) {
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
    if (listening) {
      launchSummaryDot.className = 'summary-dot ready';
      launchSummaryText.textContent = `Running on port ${port.port} with persona: ${pillPersona.textContent}. Changes above apply immediately.`;
    } else if (!port.available) {
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

  selectLlmModel.addEventListener('change', async (e) => {
    await applyQuickFix('set_model', e.target.value);
    fetchDiagnostics();  // the reasoning switch depends on the new model
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

  btnLaunchPrimary.addEventListener('click', () => {
    // While running, the footer button leads to the live view instead of starting again
    if (honeypotStatus === 'RUNNING') {
      switchView('dashboard', true);
    } else {
      launchHoneypot();
    }
  });

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

  // Reasoning for terminal replies: greyed out when the model cannot reason
  const toggleTerminalReasoning = document.getElementById('toggle-terminal-reasoning');
  const rowTerminalReasoning = document.getElementById('row-terminal-reasoning');
  const hintTerminalReasoning = document.getElementById('hint-terminal-reasoning');

  // Chat has its own reasoning switch, on by default and remembered in this browser
  const toggleChatReasoning = document.getElementById('toggle-chat-reasoning');
  const rowChatReasoning = document.getElementById('row-chat-reasoning');
  let chatReasoningWanted = localStorage.getItem('doppel_chat_reasoning') !== 'false';

  function chatModel() {
    return (assistantModelSelect && assistantModelSelect.value) || (lastLlmDiag && lastLlmDiag.configured_model) || currentModel;
  }

  function chatReasoningSupported() {
    const llm = lastLlmDiag;
    if (!llm || llm.status === 'mock_mode') return llm ? false : null;
    if (llm.reasoning_unknown || !(llm.models_available || []).length) return null;
    return (llm.reasoning_models || []).includes(chatModel());
  }

  function renderChatReasoningToggle() {
    if (!toggleChatReasoning) return;
    const supported = chatReasoningSupported();
    const unavailable = supported === false;
    toggleChatReasoning.disabled = unavailable;
    toggleChatReasoning.checked = !unavailable && chatReasoningWanted;
    rowChatReasoning.classList.toggle('is-disabled', unavailable);
    rowChatReasoning.title = unavailable
      ? 'This model does not support reasoning'
      : supported === null
        ? 'The model reasons before answering (support could not be confirmed for this server)'
        : 'The model reasons before answering: better answers, slower replies';
  }

  function chatReasoningEnabled() {
    return Boolean(toggleChatReasoning && !toggleChatReasoning.disabled && toggleChatReasoning.checked);
  }

  if (toggleChatReasoning) {
    toggleChatReasoning.addEventListener('change', (e) => {
      chatReasoningWanted = e.target.checked;
      localStorage.setItem('doppel_chat_reasoning', String(chatReasoningWanted));
    });
  }

  function renderReasoningToggle(llm) {
    renderChatReasoningToggle();
    if (!toggleTerminalReasoning) return;
    const supported = llm.supports_reasoning;  // true, false, or null (server cannot tell)
    const unavailable = llm.status === 'mock_mode' || supported === false;
    toggleTerminalReasoning.disabled = unavailable;
    toggleTerminalReasoning.checked = !unavailable && Boolean(llm.terminal_reasoning);
    rowTerminalReasoning.classList.toggle('is-disabled', unavailable);
    let hint;
    if (llm.status === 'mock_mode') hint = 'Not used in mock mode.';
    else if (supported === false) hint = 'This model does not support reasoning.';
    else if (toggleTerminalReasoning.checked) hint = 'The model reasons before each reply: more consistent output, much slower replies.';
    else hint = 'Off by default: replies skip the reasoning step. Reports still use it.';
    if (supported === null && llm.status !== 'mock_mode') hint += ' This server does not report whether the model supports it.';
    hintTerminalReasoning.textContent = hint;
  }

  if (toggleTerminalReasoning) {
    toggleTerminalReasoning.addEventListener('change', async (e) => {
      await applyQuickFix('set_terminal_reasoning', e.target.checked);
      fetchDiagnostics();
    });
  }

  // One badge for the model: its name, with health as the dot colour
  function renderModelBadge() {
    if (!navBadgeLlm || !dotNavLlm || !textNavLlm) return;
    const llm = lastLlmDiag || {};
    const model = llm.configured_model || currentModel || 'Model';
    textNavLlm.textContent = model;
    if (!lastLlmDiag) {
      dotNavLlm.className = 'subsystem-dot checking';
      navBadgeLlm.title = `Model: ${model}`;
    } else if (llm.status === 'ready') {
      dotNavLlm.className = 'subsystem-dot ready';
      navBadgeLlm.title = `Model ready (${llm.latency_ms || 0} ms): ${model}`;
    } else if (llm.status === 'mock_mode') {
      dotNavLlm.className = 'subsystem-dot neutral';
      textNavLlm.textContent = 'Mock mode';
      navBadgeLlm.title = 'Mock mode: replies are generated without a model';
    } else if (llm.status === 'model_missing') {
      dotNavLlm.className = 'subsystem-dot warning';
      navBadgeLlm.title = `Model '${model}' is not downloaded on the server`;
    } else {
      dotNavLlm.className = 'subsystem-dot error';
      navBadgeLlm.title = `Model server unreachable at ${llm.endpoint || 'local'}`;
    }
  }

  function updateStatusUI(status, config) {
    honeypotStatus = status;
    localStorage.setItem('doppel_last_status', status);
    statusDot.className = 'status-dot ' + status.toLowerCase();
    statusText.textContent = status === 'RUNNING' ? 'Active' : status;

    if (config) {
      metaPort.textContent = `:${config.honeypot_port}`;
      currentModel = config.llm_model || '';
      renderModelBadge();
      if (config.prompt) {
        promptConfig = Object.assign({}, promptConfig, config.prompt);
      }
    }

    if (btnLaunchPrimaryLabel) {
      btnLaunchPrimaryLabel.textContent = status === 'RUNNING' ? 'Open Live Dashboard' : 'Start Honeypot';
    }

    if (status === 'RUNNING') {
      btnToggleLabel.textContent = 'Stop';
      btnToggle.className = 'btn btn-primary danger';
      btnViewSwitch.classList.remove('hidden');

      // Auto-switch to live dashboard view if we were on launch screen unless explicitly clicked
      if (activeView === 'launch' && !localStorage.getItem('doppel_user_clicked_view')) {
        switchView('dashboard');
      }
    } else {
      btnToggleLabel.textContent = 'Start';
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
    if (msg.type === 'background_queue') {
      renderBackgroundQueue(msg.data);
    } else if (msg.type === 'status_update') {
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
      if (sessionsCache[data.session_id]) {
        const cached = sessionsCache[data.session_id];
        cached.command_count = (cached.command_count || 0) + 1;
        cached.last_command = data.command;
      }
      if (card) {
        const countEl = card.querySelector('.card-cmds');
        if (countEl) countEl.textContent = plural(sessionsCache[data.session_id]?.command_count || 0, 'cmd', 'cmds');
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
          data.prompt_user || sessionsCache[data.session_id].username,
          data.duration_ms
        );
        appendTelemetryRow(data.timestamp, data.command, data.decision, '—', '—', 0);
        detailCwd.textContent = data.cwd;
        setCommandCount((parseInt(detailCmdCount.textContent, 10) || 0) + 1);
      }
    } else if (msg.type === 'threat_analyzed') {
      const data = msg.data;
      const score = data.threat_score || 0;
      if (sessionsCache[data.session_id]) {
        sessionsCache[data.session_id].max_threat_score = Math.max(
          sessionsCache[data.session_id].max_threat_score || 0,
          score
        );
        const best = sessionsCache[data.session_id].max_threat_score;
        const card = document.querySelector(`.session-card[data-session-id="${data.session_id}"]`);
        if (card) {
          const scoreEl = card.querySelector('.card-score');
          if (scoreEl) {
            scoreEl.textContent = best;
            scoreEl.className = `card-score ${threatClass(best)}`;
          }
          const fill = card.querySelector('.card-threat-fill');
          if (fill) {
            fill.style.width = `${Math.min(100, best)}%`;
            fill.className = `card-threat-fill ${threatClass(best)}`;
          }
        }
      }

      if (activeSessionId === data.session_id) {
        // The session score is the highest score of any of its commands
        setThreatDisplay(Math.max(score, Number(detailThreatScore.textContent) || 0));
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
          card.dataset.live = '0';
          applySessionFilter();
        }
      }
      if (activeSessionId === data.session_id) {
        detailLivePill.textContent = 'ENDED';
        detailLivePill.classList.add('ended');
        setReportStatus(data.stage === 'queued' ? 'queued' : 'compiling', data.message || 'Session closed. Compiling incident report...');
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
          card.dataset.live = '0';
          applySessionFilter();
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
    applySessionFilter();
    applyQueueIndicators();
  }

  function threatClass(score) {
    return score >= 60 ? 'high' : (score >= 30 ? 'medium' : 'low');
  }

  function formatDuration(ms) {
    const s = Math.max(0, Math.round(ms / 1000));
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m ${String(s % 60).padStart(2, '0')}s`;
    return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, '0')}m`;
  }

  function sessionTiming(sess) {
    const start = parseServerTime(sess.start_time);
    if (!start) return { started: '', duration: '' };
    const end = sess.is_active ? new Date() : parseServerTime(sess.end_time);
    const sameDay = start.toDateString() === new Date().toDateString();
    const started = sameDay
      ? start.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      : start.toLocaleDateString([], { month: 'short', day: 'numeric' });
    return { started, duration: end ? formatDuration(end - start) : '' };
  }

  function buildSessionCard(sess) {
    const card = document.createElement('div');
    card.className = `session-card ${sess.session_id === activeSessionId ? 'selected' : ''}`;
    card.dataset.sessionId = sess.session_id;

    const isLive = Boolean(sess.is_active);
    const score = sess.max_threat_score || sess.threat_score || 0;
    const timing = sessionTiming(sess);
    const isWeb = String(sess.session_id || '').startsWith('http_');
    const user = isWeb ? 'web' : (sess.username || 'user');
    const count = sess.command_count || 0;
    card.dataset.live = isLive ? '1' : '0';
    card.dataset.search = [sess.remote_ip, user, sess.session_id, sess.campaign_id].filter(Boolean).join(' ').toLowerCase();

    card.innerHTML = `
      <div class="card-top">
        <div class="card-status">
          <span class="card-status-dot ${isLive ? 'live' : 'ended'}"></span>
          <span class="card-user">${escapeHtml(user)}</span><span class="card-ip">@${escapeHtml(sess.remote_ip || 'unknown')}</span>
        </div>
        <span class="card-time" title="${escapeHtml(sess.start_time || '')}">${escapeHtml(timing.started)}</span>
      </div>
      <div class="card-bottom">
        <span class="card-meta"><span class="card-cmds">${plural(count, 'cmd', 'cmds')}</span>${timing.duration ? ` · ${escapeHtml(timing.duration)}` : ''}</span>
        <span class="card-score ${threatClass(score)}" title="Threat score">${score}</span>
      </div>
      <div class="card-threat"><span class="card-threat-fill ${threatClass(score)}" style="width:${Math.min(100, score)}%"></span></div>
    `;

    card.addEventListener('click', (e) => {
      e.stopPropagation();
      selectSession(sess.session_id);
    });
    return card;
  }

  // function applySessionFilter() {
  //   const query = (sessionSearch ? sessionSearch.value : '').trim().toLowerCase();
  //   const liveOnly = Boolean(sessionLiveOnly && sessionLiveOnly.checked);
  //   let shown = 0;
  //   sessionsContainer.querySelectorAll('.session-card').forEach(card => {
  //     const visible = (!query || (card.dataset.search || '').includes(query)) && (!liveOnly || card.dataset.live === '1');
  //     card.classList.toggle('hidden', !visible);
  //     if (visible) shown += 1;
  //   });
  //   return shown;
  // }

  // --- Multi-Facet Session Filtering ---
  function applySessionFilter() {
    const query = (sessionSearch ? sessionSearch.value : '').trim().toLowerCase();
    const threatFilter = document.getElementById('filter-threat')?.value || '';
    const typeFilter = document.getElementById('filter-type')?.value || '';
    const campaignFilter = document.getElementById('filter-campaign')?.value || '';
    const dateFilter = document.getElementById('filter-date')?.value || '';
    const liveOnly = Boolean(sessionLiveOnly && sessionLiveOnly.checked);

    const now = new Date();
    const resetBtn = document.getElementById('btn-clear-filters');
    const hasActiveFilters = query || threatFilter || typeFilter || campaignFilter || dateFilter || liveOnly;
    if (resetBtn) resetBtn.classList.toggle('hidden', !hasActiveFilters);

    let shown = 0;
    sessionsContainer.querySelectorAll('.session-card').forEach(card => {
      const s = sessionsCache[card.dataset.sessionId] || {};

      if (liveOnly && card.dataset.live !== '1') {
        card.classList.add('hidden');
        return;
      }

      if (query) {
        const match = (s.remote_ip || '').toLowerCase().includes(query) ||
                      (s.username || '').toLowerCase().includes(query) ||
                      (s.session_id || '').toLowerCase().includes(query) ||
                      (s.campaign_id || '').toLowerCase().includes(query) ||
                      (card.dataset.search || '').includes(query);
        if (!match) {
          card.classList.add('hidden');
          return;
        }
      }

      if (threatFilter) {
        const score = s.max_threat_score || 0;
        if (threatFilter === 'critical' && score < 90) { card.classList.add('hidden'); return; }
        if (threatFilter === 'high' && (score < 70 || score >= 90)) { card.classList.add('hidden'); return; }
        if (threatFilter === 'medium' && (score < 40 || score >= 70)) { card.classList.add('hidden'); return; }
        if (threatFilter === 'low' && score >= 40) { card.classList.add('hidden'); return; }
      }

      if (typeFilter) {
        const profile = s.profile || {};
        const t = (s.attacker_type || profile.attacker_type || 'unknown').toLowerCase();
        if (t !== typeFilter) { card.classList.add('hidden'); return; }
      }

      if (campaignFilter === 'in_campaign' && !s.campaign_id) { card.classList.add('hidden'); return; }
      if (campaignFilter === 'no_campaign' && s.campaign_id) { card.classList.add('hidden'); return; }

      if (dateFilter && s.start_time) {
        const start = parseServerTime(s.start_time);
        if (start) {
          const diffMs = now - start;
          if (dateFilter === 'today' && start.toDateString() !== now.toDateString()) { card.classList.add('hidden'); return; }
          if (dateFilter === '7d' && diffMs > 7 * 86400000) { card.classList.add('hidden'); return; }
          if (dateFilter === '30d' && diffMs > 30 * 86400000) { card.classList.add('hidden'); return; }
        }
      }

      card.classList.remove('hidden');
      shown += 1;
    });
    return shown;
  }

  // Clear filters button
  document.getElementById('btn-clear-filters')?.addEventListener('click', () => {
    if (sessionSearch) sessionSearch.value = '';
    if (document.getElementById('filter-threat')) document.getElementById('filter-threat').value = '';
    if (document.getElementById('filter-type')) document.getElementById('filter-type').value = '';
    if (document.getElementById('filter-campaign')) document.getElementById('filter-campaign').value = '';
    if (document.getElementById('filter-date')) document.getElementById('filter-date').value = '';
    if (sessionLiveOnly) sessionLiveOnly.checked = false;
    applySessionFilter();
  });

  // Bind filter change events
  ['session-search', 'filter-threat', 'filter-type', 'filter-campaign', 'filter-date', 'session-live-only'].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('input', applySessionFilter);
      el.addEventListener('change', applySessionFilter);
    }
  });

  // --- IOC Panel Populator ---
  function renderIOCPanel(iocs) {
    const tabBtn = document.getElementById('tab-btn-iocs');
    const countBadge = document.getElementById('badge-ioc-count');
    const emptyCard = document.getElementById('iocs-empty-card');
    const container = document.getElementById('iocs-container');
    const summaryText = document.getElementById('iocs-summary-text');

    const total = iocs ? (iocs.total_count || 0) : 0;
    if (countBadge) countBadge.textContent = total;

    if (!iocs || !iocs.has_iocs) {
      if (tabBtn) {
        tabBtn.classList.add('disabled');
        tabBtn.setAttribute('title', 'No links or network IOCs observed in commands');
      }
      if (emptyCard) emptyCard.classList.remove('hidden');
      if (container) container.classList.add('hidden');
      return;
    }

    if (tabBtn) {
      tabBtn.classList.remove('disabled');
      tabBtn.removeAttribute('title');
    }
    if (emptyCard) emptyCard.classList.add('hidden');
    if (container) container.classList.remove('hidden');

    if (summaryText) {
      summaryText.textContent = `${total} Indicator${total !== 1 ? 's' : ''} observed`;
    }

    function renderGroup(groupId, listId, countId, items) {
      const groupEl = document.getElementById(groupId);
      const listEl = document.getElementById(listId);
      const countEl = document.getElementById(countId);

      if (!items || items.length === 0) {
        if (groupEl) groupEl.classList.add('hidden');
        return;
      }

      if (groupEl) groupEl.classList.remove('hidden');
      if (countEl) countEl.textContent = items.length;
      if (listEl) {
        listEl.innerHTML = items.map(item => `
          <div class="ioc-card">
            <span class="ioc-value">${escapeHtml(item.value)}</span>
            <button type="button" class="ioc-copy-btn" data-copy="${escapeHtml(item.value)}">Copy</button>
          </div>
        `).join('');
      }
    }

    renderGroup('ioc-group-urls', 'ioc-list-urls', 'ioc-count-urls', iocs.urls);
    renderGroup('ioc-group-ips', 'ioc-list-ips', 'ioc-count-ips', iocs.ips);
    renderGroup('ioc-group-domains', 'ioc-list-domains', 'ioc-count-domains', iocs.domains);

    // Individual copy buttons
    container.querySelectorAll('.ioc-copy-btn').forEach(btn => {
      btn.onclick = (e) => {
        e.stopPropagation();
        const val = btn.getAttribute('data-copy');
        navigator.clipboard.writeText(val).then(() => {
          btn.textContent = 'Copied';
          btn.classList.add('copied');
          setTimeout(() => {
            btn.textContent = 'Copy';
            btn.classList.remove('copied');
          }, 1500);
        });
      };
    });

    // Copy all button
    const copyAllBtn = document.getElementById('btn-copy-all-iocs');
    if (copyAllBtn) {
      copyAllBtn.onclick = () => {
        const all = [
          ...(iocs.urls || []).map(x => x.value),
          ...(iocs.ips || []).map(x => x.value),
          ...(iocs.domains || []).map(x => x.value),
        ];
        navigator.clipboard.writeText(all.join('\n')).then(() => {
          const orig = copyAllBtn.textContent;
          copyAllBtn.textContent = 'Copied All!';
          setTimeout(() => { copyAllBtn.textContent = orig; }, 1500);
        });
      };
    }
  }

  if (sessionSearch) sessionSearch.addEventListener('input', applySessionFilter);
  if (sessionLiveOnly) sessionLiveOnly.addEventListener('change', applySessionFilter);

  function selectSession(sessionId) {
    const changed = activeSessionId !== sessionId;
    activeSessionId = sessionId;
    localStorage.setItem('doppel_active_session_id', sessionId);

    document.querySelectorAll('.session-card').forEach(card => {
      card.classList.toggle('selected', card.dataset.sessionId === sessionId);
    });

    if (changed) {
      // Never let the previous session's lines remain in the new session's view
      terminalOutput.innerHTML = '';
      telemetryTableBody.innerHTML = '';
      setCommandCount(0);
      const top = document.getElementById('detail-threat-top');
      if (top) top.textContent = '';
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

  function setCommandCount(n) {
    detailCmdCount.textContent = String(n);
    const noun = document.getElementById('detail-cmd-noun');
    if (noun) noun.textContent = n === 1 ? 'command' : 'commands';
  }

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
    const campaignSub = document.getElementById('detail-campaign-sub');
    const campaign = activeSessionId ? campaignBySession[activeSessionId] : null;
    if (!campaign) {
      detailCampaignPill.classList.add('hidden');
      detailCampaignPill.dataset.campaignId = '';
      if (detailCampaignNone) detailCampaignNone.classList.remove('hidden');
      if (campaignSub) campaignSub.textContent = '';
      return;
    }
    detailCampaignPill.textContent = plural(campaign.session_count || 0, 'session', 'sessions');
    if (campaignSub) {
      campaignSub.textContent = (campaign.link_reasons || []).map(r => LINK_REASON_LABELS[r] || r).join(' · ');
    }
    detailCampaignPill.dataset.campaignId = campaign.campaign_id;
    detailCampaignPill.classList.remove('hidden');
    if (detailCampaignNone) detailCampaignNone.classList.add('hidden');
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

  // ATT&CK tagging and reports queued behind terminal replies
  const navBadgeQueue = document.getElementById('nav-badge-queue');
  const dotNavQueue = document.getElementById('dot-nav-queue');
  const textNavQueue = document.getElementById('text-nav-queue');
  const queuePop = document.getElementById('queue-pop');

  let lastBackground = null;

  const ACTIVITY_LABEL = { tagging: 'Tagging', report: 'Writing report' };

  function sessionLabel(sessionId) {
    const sess = sessionsCache[sessionId];
    if (!sess) return String(sessionId).slice(0, 8);
    const user = String(sessionId).startsWith('http_') ? 'web' : (sess.username || 'user');
    return `${user}@${sess.remote_ip || 'unknown'}`;
  }

  // Spinner on the card of the session whose analysis is running
  function applyQueueIndicators() {
    const bg = lastBackground;
    document.querySelectorAll('.session-card .card-activity').forEach(el => el.remove());
    if (!bg || !bg.running || !bg.running_session) return;
    const card = document.querySelector(`.session-card[data-session-id="${bg.running_session}"]`);
    const meta = card && card.querySelector('.card-meta');
    if (!meta) return;
    const activity = document.createElement('span');
    activity.className = 'card-activity';
    activity.title = 'Analysis in progress';
    const spinner = document.createElement('span');
    spinner.className = 'activity-spinner';
    activity.append(spinner, document.createTextNode(ACTIVITY_LABEL[bg.running] || 'Analyzing'));
    meta.appendChild(activity);
  }

  function setQueuePopOpen(open) {
    if (!queuePop || !navBadgeQueue) return;
    queuePop.classList.toggle('hidden', !open);
    navBadgeQueue.setAttribute('aria-expanded', open ? 'true' : 'false');
    if (open) renderQueuePop();
  }

  function renderQueuePop() {
    const bg = lastBackground;
    if (!queuePop || queuePop.classList.contains('hidden') || !bg) return;
    let head;
    if (bg.running) head = 'Analyzing now. Terminal replies take priority.';
    else if (bg.terminal_active) head = 'Waiting while the terminal is using the model.';
    else if (bg.forced) head = 'Starting now.';
    else head = `Starts after ${bg.idle_seconds} s without terminal activity.`;

    queuePop.replaceChildren();
    const headEl = document.createElement('div');
    headEl.className = 'queue-pop-head';
    headEl.textContent = head;
    queuePop.appendChild(headEl);

    (bg.by_session || []).forEach(group => {
      const row = document.createElement('button');
      row.type = 'button';
      row.className = 'queue-row';

      const main = document.createElement('span');
      main.className = 'queue-row-main';
      const name = document.createElement('span');
      name.className = 'queue-row-name';
      name.textContent = sessionLabel(group.session_id);
      const detail = document.createElement('span');
      detail.className = 'queue-row-detail';
      const parts = [];
      if (group.tags) parts.push(plural(group.tags, 'command to tag', 'commands to tag'));
      if (group.report) parts.push('incident report');
      detail.textContent = parts.join(' · ');
      main.append(name, detail);

      const state = document.createElement('span');
      state.className = `queue-row-state${group.running ? ' running' : ''}`;
      if (group.running) {
        const spinner = document.createElement('span');
        spinner.className = 'activity-spinner';
        state.append(spinner, document.createTextNode(ACTIVITY_LABEL[group.running] || 'Analyzing'));
      } else {
        state.textContent = 'Waiting';
      }

      row.append(main, state);
      row.addEventListener('click', () => {
        setQueuePopOpen(false);
        selectSession(group.session_id);
      });
      queuePop.appendChild(row);
    });

    if (!bg.running && !bg.forced) {
      const foot = document.createElement('div');
      foot.className = 'queue-pop-foot';
      const runNow = document.createElement('button');
      runNow.type = 'button';
      runNow.className = 'queue-run-now';
      runNow.textContent = 'Run now';
      runNow.title = 'Start without waiting for the terminal to be idle';
      runNow.addEventListener('click', (e) => {
        e.stopPropagation();
        runQueueNow(runNow);
      });
      foot.appendChild(runNow);
      queuePop.appendChild(foot);
    }
  }

  async function runQueueNow(button) {
    button.disabled = true;
    try {
      const res = await fetch('/api/background/run-now', { method: 'POST' });
      const data = await res.json();
      renderBackgroundQueue(data.background);
    } catch (e) {
      console.error('Error starting queued analysis:', e);
      button.disabled = false;
    }
  }

  if (navBadgeQueue) {
    navBadgeQueue.addEventListener('click', (e) => {
      e.stopPropagation();
      setQueuePopOpen(queuePop.classList.contains('hidden'));
    });
    navBadgeQueue.addEventListener('keydown', (e) => {
      if (e.target !== navBadgeQueue) return;
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        setQueuePopOpen(queuePop.classList.contains('hidden'));
      }
    });
    document.addEventListener('click', (e) => {
      if (queuePop && !queuePop.classList.contains('hidden') && !e.target.closest('.queue-wrap')) setQueuePopOpen(false);
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && queuePop && !queuePop.classList.contains('hidden')) {
        setQueuePopOpen(false);
        navBadgeQueue.focus();
      }
    });
  }

  function queuedReportState(sessionId) {
    const bg = lastBackground;
    if (!bg || !sessionId) return null;
    if (bg.running === 'report' && bg.running_session === sessionId) return 'running';
    return (bg.report_sessions || []).includes(sessionId) ? 'queued' : null;
  }

  // Report panel of the selected session, while its report waits in the queue
  function renderQueuedReportStatus() {
    if (!activeSessionId || activeReportAbortController) return;
    if (reportContent && !reportContent.classList.contains('hidden')) return;
    const state = queuedReportState(activeSessionId);
    if (state === 'running') {
      setReportStatus('compiling', 'Compiling incident report...');
    } else if (state === 'queued') {
      setReportStatus('queued', lastBackground.forced
        ? 'Report queued. Starting shortly.'
        : 'Report queued. It runs when the model is idle, or select Run now in the queue panel.');
    }
  }

  function renderBackgroundQueue(bg) {
    lastBackground = bg || null;
    renderQueuedReportStatus();
    applyQueueIndicators();
    if (!navBadgeQueue) return;
    const count = bg ? bg.queued || 0 : 0;
    navBadgeQueue.classList.toggle('hidden', count === 0);
    if (count === 0) {
      setQueuePopOpen(false);
      return;
    }
    renderQueuePop();
    const active = Boolean(bg.running) || Boolean(bg.forced);
    const parts = [];
    if (bg.reports) parts.push(plural(bg.reports, 'report', 'reports'));
    if (bg.tagging) parts.push(plural(bg.tagging, 'tag', 'tags'));
    textNavQueue.textContent = active ? `Analyzing · ${count}` : `${count} queued`;
    navBadgeQueue.title = `Analysis queue: ${parts.join(', ')}`;
    dotNavQueue.className = `subsystem-dot ${active ? 'neutral' : 'warning'}`;
  }

  function setReportStatus(status, text) {
    if (!reportStatusBadge) return;
    reportStatusBadge.className = 'report-status-badge';
    const statusMap = {
      reasoning: { label: 'Reasoning', cls: 'reasoning', defText: 'Model is reasoning...' },
      queued: { label: 'Queued', cls: 'neutral', defText: 'Report queued. It runs when the model is idle.' },
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
    const queued = queuedReportState(sessionId);
    if (reportEmpty) {
      reportEmpty.textContent = queued
        ? 'The incident report is queued and will appear here when it is ready.'
        : isLive
          ? 'Report will be compiled automatically when the session terminates. You can also generate now using the Regenerate button.'
          : 'No report has been compiled for this session yet. Click Regenerate to compile an incident report.';
    }
    renderQueuedReportStatus();
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

  const THREAT_LEVEL = { low: 'Low', medium: 'Medium', high: 'High' };

  // Highest-scoring tagged command: what the threat score is based on
  function renderTopTechnique(commands) {
    const el = document.getElementById('detail-threat-top');
    if (!el) return;
    let top = null;
    (commands || []).forEach(cmd => {
      if (cmd.technique_id && (!top || (cmd.threat_score || 0) > (top.threat_score || 0))) top = cmd;
    });
    el.textContent = top ? `${top.technique_id} ${top.technique_name || ''}`.trim() : '';
    el.title = top ? `Highest-scoring command: ${top.command}` : '';
  }

  function setThreatDisplay(score) {
    const value = Math.max(0, Math.min(100, Number(score) || 0));
    const level = document.getElementById('detail-threat-level');
    if (level) level.textContent = THREAT_LEVEL[threatClass(value)];
    detailThreatScore.textContent = String(value);
    detailThreatScore.className = `stat-value threat-${threatClass(value)}`;
    if (detailThreatBar) {
      detailThreatBar.style.width = `${value}%`;
      detailThreatBar.className = `threat-bar-fill ${threatClass(value)}`;
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
    detailUser.textContent = String(session.session_id || '').startsWith('http_') ? 'web' : (session.username || 'user');
    detailSessionId.textContent = session.session_id;
    setThreatDisplay(session.max_threat_score || 0);
    const timing = sessionTiming(session);
    if (detailStarted) {
      detailStarted.textContent = timing.started
        ? `Started ${timing.started}${timing.duration ? ` · ${isLive ? 'connected' : 'lasted'} ${timing.duration}` : ''}`
        : '';
    }
    setCommandCount(Math.max((session.commands || []).length, parseInt(detailCmdCount.textContent, 10) || 0));
    detailCwd.textContent = session.cwd || '/home/ubuntu';
    renderTopTechnique(session.commands);
    renderIOCPanel(session.iocs);

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
          cmd.prompt_user || session.username,
          cmd.duration_ms
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
    const cwdBase = (shownCwd === '~' || shownCwd === '/') ? shownCwd : shownCwd.replace(/\/+$/, '').split('/').pop();
    return fmt
      .replace(/\{user\}/g, name)
      .replace(/\{hostname\}/g, promptConfig.hostname || '')
      .replace(/\{cwd_base\}/g, cwdBase)
      .replace(/\{cwd\}/g, shownCwd);
  }

  const ROUTE_TAGS = {
    sandbox: { cls: 'sandbox', label: 'Sandbox' },
    grounded_deception: { cls: 'grounded', label: 'Grounded' },
    builtin: { cls: 'builtin', label: 'Builtin' },
  };

  function formatResponseTime(ms) {
    if (ms === null || ms === undefined || ms === '' || isNaN(ms)) return '';
    return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`;
  }

  function buildTerminalLine({ cwd, user, command, output = null, decision, reasoning = null, durationMs = null }) {
    const line = document.createElement('div');
    line.className = 'terminal-line';
    const route = ROUTE_TAGS[decision] || { cls: 'deception', label: 'Deception' };

    // Markup is built without inter-tag whitespace so layout never depends on
    // template indentation.
    const reasoningHtml = reasoning
      ? '<details class="terminal-reasoning-details">'
        + '<summary class="terminal-reasoning-summary">Model Reasoning</summary>'
        + `<div class="terminal-reasoning-content">${escapeHtml(reasoning)}</div>`
        + '</details>'
      : '';

    line.innerHTML = '<div class="terminal-head">'
      + '<span class="terminal-entry">'
      + `<span class="terminal-prompt">${escapeHtml(formatPrompt(user, cwd))}</span>`
      + `<span class="terminal-cmd">${escapeHtml(command)}</span>`
      + '</span>'
      + (formatResponseTime(durationMs)
        ? `<span class="terminal-duration" title="Time until the reply was shown">${formatResponseTime(durationMs)}</span>`
        : '')
      + `<span class="terminal-route-tag ${route.cls}">${route.label}</span>`
      + '</div>'
      + reasoningHtml;
    setTerminalLineOutput(line, output);
    return line;
  }

  function setTerminalLineOutput(line, output) {
    if (!output) return;
    const block = document.createElement('div');
    block.className = 'terminal-output-block';
    block.innerHTML = escapeHtml(String(output).replace(/\r\n/g, '\n').replace(/\n+$/, ''));
    line.appendChild(block);
  }

  function appendTerminalCommand(cwd, command, output, decision, reasoning = null, user = null, durationMs = null) {
    terminalOutput.appendChild(buildTerminalLine({ cwd, user, command, output, decision, reasoning, durationMs }));
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
        durationMs: ev.duration_ms,
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
  // Session actions menu and session ID copy
  function closeSessionMenu() {
    if (!sessionMenu) return;
    sessionMenu.classList.add('hidden');
    if (btnSessionMenu) btnSessionMenu.setAttribute('aria-expanded', 'false');
  }

  if (btnSessionMenu && sessionMenu) {
    btnSessionMenu.addEventListener('click', (e) => {
      e.stopPropagation();
      const open = sessionMenu.classList.contains('hidden');
      sessionMenu.classList.toggle('hidden', !open);
      btnSessionMenu.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    document.addEventListener('click', (e) => {
      if (!sessionMenu.contains(e.target)) closeSessionMenu();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeSessionMenu();
    });
  }

  if (btnCopySessionId) {
    btnCopySessionId.addEventListener('click', async () => {
      if (!activeSessionId) return;
      try {
        await navigator.clipboard.writeText(activeSessionId);
        btnCopySessionId.classList.add('copied');
        btnCopySessionId.title = 'Copied';
        setTimeout(() => {
          btnCopySessionId.classList.remove('copied');
          btnCopySessionId.title = 'Copy session ID';
        }, 1500);
      } catch (err) {
        console.error('Copy failed:', err);
      }
    });
  }

  if (btnDeleteSession) {
    btnDeleteSession.addEventListener('click', async () => {
      closeSessionMenu();
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
    assistantModelSelect.addEventListener('change', () => renderChatReasoningToggle());
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
    document.getElementById('assistant-empty')?.remove();

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
      const payload = { message: text, reasoning: chatReasoningEnabled() };
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

  // The empty state (with suggested prompts) is restored on reset
  const assistantEmptyHtml = document.getElementById('assistant-empty')?.outerHTML || '';

  if (btnResetAssistant) {
    btnResetAssistant.addEventListener('click', () => {
      if (assistantChatBody) {
        assistantChatBody.innerHTML = assistantEmptyHtml;
      }
      if (assistantInput) {
        assistantInput.value = '';
        assistantInput.focus();
      }
    });
  }

  // Suggested prompts are re-created on reset, so listen on the chat body
  if (assistantChatBody) {
    assistantChatBody.addEventListener('click', (e) => {
      const chip = e.target.closest('.assistant-chip');
      if (!chip) return;
      const prompt = chip.getAttribute('data-prompt');
      if (prompt) sendAssistantMessage(prompt);
    });
  }

  if (btnTestModelSpeed) {
    btnTestModelSpeed.addEventListener('click', () => {
      // Run the speed test against the model selected on this card
      const model = selectLlmModel.value || '';
      if (assistantModelSelect && model) {
        const exists = Array.from(assistantModelSelect.options).some(o => o.value === model);
        if (!exists) {
          const opt = document.createElement('option');
          opt.value = model;
          opt.textContent = model;
          assistantModelSelect.appendChild(opt);
        }
        assistantModelSelect.value = model;
      }
      assistantModal.classList.remove('hidden');
      sendAssistantMessage('Run a model speed and throughput benchmark test.');
    });
  }


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

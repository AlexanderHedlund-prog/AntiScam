'use strict';
const $ = (id) => document.getElementById(id);
const setText = (id, value) => { $(id).textContent = String(value ?? ''); };
const reduceMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const ROUTE = {link: '/', file: '/file', about: '/about', agreement: '/agreement'};
const modeForPath = () => location.pathname === '/file' ? 'file' : location.pathname === '/about' ? 'about' : location.pathname === '/agreement' ? 'agreement' : 'link';

function navigate(mode, push = false) {
  if (!(mode in ROUTE)) mode = 'link';
  const info = mode === 'about';
  const agreement = mode === 'agreement';
  $('scan-pages').classList.toggle('hidden', info || agreement);
  $('about-page').classList.toggle('hidden', !info);
  $('agreement-page').classList.toggle('hidden', !agreement);
  $('link-panel').classList.toggle('hidden', mode !== 'link');
  $('file-panel').classList.toggle('hidden', mode !== 'file');
  for (const tab of ['link', 'file']) {
    const current = tab === mode;
    $('tab-' + tab).classList.toggle('active', current);
    $('tab-' + tab).setAttribute('aria-selected', String(current));
    $('tab-' + tab).tabIndex = current ? 0 : -1;
  }
  $('nav-about').classList.toggle('current', info);
  $('nav-file').classList.toggle('current', mode === 'file');
  setText('hero-title', mode === 'file' ? 'Проверь файл до открытия.' : 'Не рискуй. Проверь сначала.');
  // Use text-only updates for the headline to avoid inserting untrusted HTML.
  const headline = $('hero-title');
  headline.replaceChildren();
  if (mode === 'file') {
    headline.append('Файл от незнакомца?');
    headline.append(document.createElement('br'));
    const accent = document.createElement('span'); accent.textContent = 'Проверь сначала.'; headline.append(accent);
    setText('hero-description', 'Тебе прислали PDF, презентацию или архив? Загрузи файл, чтобы увидеть его формат, возможные признаки риска и доступную репутацию.');
  } else {
    headline.append('Не рискуй.');
    headline.append(document.createElement('br'));
    const accent = document.createElement('span'); accent.textContent = 'Проверь сначала.'; headline.append(accent);
    setText('hero-description', 'Получил подозрительную ссылку от незнакомца? Узнай, куда она может вести и есть ли известные угрозы — до того, как нажмёшь.');
  }
  document.title = mode === 'file' ? 'AntiScam — проверка файлов' : mode === 'about' ? 'AntiScam — о проекте' : 'AntiScam — проверка ссылок';
  if (push && location.pathname !== ROUTE[mode]) {
    history.pushState({mode}, '', ROUTE[mode]);
  }
  if (push) window.scrollTo({top: 0, behavior: 'instant'});
}

document.querySelectorAll('a[data-route]').forEach((anchor) => {
  anchor.addEventListener('click', (event) => {
    if (event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    navigate(anchor.dataset.route, true);
  });
});
$('tab-link').parentElement.addEventListener('keydown', (event) => {
  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
  event.preventDefault();
  const active = $('tab-file').getAttribute('aria-selected') === 'true' ? 'file' : 'link';
  const next = event.key === 'Home' ? 'link' : event.key === 'End' ? 'file' : active === 'file' ? 'link' : 'file';
  navigate(next, true);
  $('tab-' + next).focus();
});
window.addEventListener('popstate', () => navigate(modeForPath()));
navigate(modeForPath());

function providerRow(container, provider) {
  const node = document.createElement('div'); node.className = 'provider';
  const dot = document.createElement('span');
  dot.className = 'provider-dot ' + (provider.status === 'checked' && Number(provider.detections) > 0 ? 'hit' : ['checked', 'error', 'skipped', 'no_data'].includes(provider.status) ? provider.status : '');
  const content = document.createElement('div');
  const title = document.createElement('strong'); title.textContent = provider.name;
  const description = document.createElement('p'); description.textContent = provider.message;
  content.append(title, description);
  // Required attribution applies only when a Google Safe Browsing match is shown.
  if (provider.name === 'Google Safe Browsing' && provider.status === 'checked' && Number(provider.detections) > 0) {
    const advisory = document.createElement('a');
    advisory.href = 'https://developers.google.com/safe-browsing/v4/advisory';
    advisory.target = '_blank';
    advisory.rel = 'noopener noreferrer';
    advisory.className = 'google-advisory';
    advisory.textContent = 'Advisory provided by Google — о возможных угрозах';
    content.append(advisory);
  }
  node.append(dot, content); container.appendChild(node);
}

function signalRow(container, signal) {
  const node = document.createElement('div'); node.className = 'signal ' + (signal.severity === 'high' ? 'high' : '');
  const dot = document.createElement('span'); dot.className = 'signal-dot'; dot.textContent = '!';
  const message = document.createElement('span'); message.textContent = signal.text;
  node.append(dot, message); container.appendChild(node);
}

function drawReport(data, ids) {
  const risk = ['low', 'caution', 'danger', 'unknown'].includes(data.risk) ? data.risk : 'unknown';
  if (ids.banner) {
    $(ids.banner).className = 'risk-banner ' + risk;
    setText(ids.symbol, ({low:'✓', caution:'!', danger:'×', unknown:'?'})[risk]);
    setText(ids.title, data.title);
    setText(ids.detail, data.detail);
  }
  const providers = $(ids.providers); providers.replaceChildren();
  const availableProviders = (data.providers || []).filter(provider =>
    !(ids.result === 'file-result' && provider.name?.includes('Собственный'))
  );
  // Skip notices for Google/VirusTotal are identical without URL sharing.
  // Show one transparent combined notice rather than repeating the same sentence twice.
  if (ids.result === 'result' && availableProviders.length === 2 &&
      availableProviders.every(provider => provider.status === 'skipped')) {
    providerRow(providers, {name:'Внешние базы не запускались', status:'skipped',
      message:'Проверка Google Safe Browsing и VirusTotal выключена в настройках. Адрес им не отправлялся.'});
  } else {
    for (const provider of availableProviders) providerRow(providers, provider);
  }
  const signals = $(ids.signals); signals.replaceChildren();
  // Do not repeat "no signs detected" below the short verdict and local summary.
  // If actual signals exist, show them prominently as before.
  for (const signal of data.signals || []) signalRow(signals, signal);
  if (ids.result === 'result') {
    $('url-signal-section').classList.toggle('hidden', !(data.signals || []).length);
  }
  setText(ids.disclaimer, data.disclaimer);
  $(ids.result).classList.remove('hidden');
  $(ids.result).scrollIntoView({behavior: reduceMotion() ? 'auto' : 'smooth', block:'start'});
}

function drawQuickVerdict(data, kind) {
  const prefix = kind === 'file' ? 'file' : 'url';
  const verdict = data.quick_verdict;
  const allowed = ['low', 'caution', 'danger', 'unknown'];
  const state = verdict && allowed.includes(verdict.state) ? verdict.state : 'unknown';
  const container = $(prefix + '-quick-verdict');
  container.className = 'quick-verdict ' + state;
  setText(prefix + '-quick-answer', verdict?.answer || 'Пока невозможно определить');
  setText(prefix + '-quick-note', verdict?.note || 'Недостаточно данных для ответа.');
}

function drawOwnAnalysis(info) {
  if (!info) { $('own-analysis').classList.add('hidden'); return; }
  $('own-analysis').classList.remove('hidden');
  const levels = {none: 'Явных признаков нет', low: 'Слабые признаки', medium: 'Нужна осторожность', high: 'Заметные признаки'};
  const level = ['none', 'low', 'medium', 'high'].includes(info.level) ? info.level : 'none';
  setText('own-risk-label', levels[level]);
  $('own-risk-label').className = 'own-level own-' + level;
  setText('own-summary', info.summary);
  setText('own-limits', info.limitations);
  $('own-checks').replaceChildren();
  for (const text of info.checks || []) {
    const item = document.createElement('li'); item.textContent = text;
    $('own-checks').append(item);
  }
}

function drawPageInspection(info) {
  const section = $('page-inspection');
  section.classList.toggle('hidden', !info || info.status === 'skipped');
  if (!info || info.status === 'skipped') return;
  const statuses = {ok:'Ответ прочитан частично', incomplete:'Не удалось', blocked:'Заблокировано'};
  setText('page-state', info.http_status === 404 ? 'Страница не найдена (404)' : (statuses[info.status] || 'Неизвестно'));
  $('page-state').className = 'own-level ' + (info.status === 'ok' ? 'own-low' : 'own-medium');
  setText('page-message', info.message);
  setText('page-domain', info.final_host || 'Не удалось установить');
  setText('page-redirects', 'HTTP-переадресаций: ' + (info.redirects || 0));
  setText('page-kind', info.kind || 'Неизвестно');
  setText('page-size', 'Прочитано: ' + (info.bytes_read || 0) + ' байт' + (info.truncated ? ' (фрагмент, страница больше)' : ''));
  const htmlResponse = info.status === 'ok' && String(info.kind || '').startsWith('HTML-страница');
  $('page-title').parentElement.classList.toggle('hidden', !htmlResponse);
  $('page-findings').classList.toggle('hidden', !htmlResponse);
  setText('page-title', info.title || 'Не определён');
  setText('page-findings', htmlResponse ? 'HTML-форм: ' + (info.forms || 0) + ' · Скриптов (не запускались): ' + (info.scripts || 0) + ' · Ссылок на исполняемые файлы: ' + (info.suspicious_links || 0) : '');
  const chain = $('redirect-chain'); chain.replaceChildren();
  for (const hop of info.redirect_chain || []) {
    const li = document.createElement('li'); li.textContent = hop.scheme + '://' + hop.host;
    chain.append(li);
  }
  if (!chain.childElementCount) { const li = document.createElement('li'); li.textContent = 'Не удалось установить цепочку'; chain.append(li); }
}

function drawDownloadInspection(info) {
  const card = $('download-inspection');
  card.classList.toggle('hidden', !info || info.status === 'skipped');
  if (!info || info.status === 'skipped') return;
  setText('download-state', info.status === 'ok' ? 'Проанализировано' : info.status === 'not_file' ? 'Это веб-страница, не файл' : info.status === 'blocked' ? 'Заблокировано' : 'Не удалось');
  $('download-meta').classList.toggle('hidden', info.status !== 'ok');
  setText('download-message', info.message || 'Нет данных.');
  setText('download-kind', info.kind || 'Не установлен');
  setText('download-size', Number.isFinite(info.size) ? readableSize(info.size) : '—');
}

// PDF is produced locally by the browser's Print / Save as PDF option.
// No untrusted data is inserted as HTML or sent to a third-party report service.
document.querySelectorAll('.print-report').forEach((button) => {
  button.addEventListener('click', () => {
    document.body.classList.add('printing-' + button.dataset.report);
    window.print();
  });
});
window.addEventListener('afterprint', () => document.body.classList.remove('printing-url', 'printing-file'));

function displayError(id, message) {
  $(id).textContent = message;
  $(id).classList.remove('hidden');
}
async function requestJSON(endpoint, opts, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(endpoint, {...opts, signal: controller.signal, cache: 'no-store'});
    const data = await response.json();
    if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Сервер вернул ошибку. Попробуйте ещё раз.');
    return data;
  } finally { clearTimeout(timer); }
}

$('check-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('error-box').classList.add('hidden'); $('result').classList.add('hidden');
  const url = $('url-input').value.trim();
  if (!url) { displayError('error-box', 'Пожалуйста, вставьте ссылку.'); $('url-input').focus(); return; }
  $('submit-btn').disabled = true; setText('submit-text', 'Проверяем ссылку…');
  try {
    const data = await requestJSON('/api/scan', {
      method:'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({url, share_with_services: $('share-opt').checked, inspect_headers: $('headers-opt').checked, inspect_page: $('inspect-page-opt').checked, inspect_download: $('download-opt').checked})
    }, 30000);
    setText('result-url', data.display_url);
    setText('url-report-date', 'AntiScam · отчёт создан: ' + new Date().toLocaleString('ru-RU')); 
    drawOwnAnalysis(data.local_analysis);
    drawPageInspection(data.page_inspection);
    drawDownloadInspection(data.download_inspection);
    setText('content-label', data.content.label);
    setText('content-basis', data.content.basis);
    setText('content-source-label', data.download_inspection?.status === 'ok'
      ? 'СОДЕРЖИМОЕ ПОЛУЧЕННОГО ФАЙЛА'
      : data.page_inspection?.status === 'ok'
        ? 'СОДЕРЖИМОЕ ПРОСМОТРЕННОЙ СТРАНИЦЫ'
        : 'ПРЕДПОЛАГАЕМОЕ СОДЕРЖИМОЕ');
    const headerNames = {ok:'Получены', skipped:'Не запрашивались', unknown:'Не удалось получить'};
    setText('header-status', data.header_probe.http_status === 404 ? 'HTTP 404 — страница не найдена' : (headerNames[data.header_probe.status] || 'Неизвестно'));
    setText('header-message', data.header_probe.message);
    drawQuickVerdict(data, 'url');
    setText('url-next-step', data.recommendation || 'Не открывайте неожиданные ссылки без дополнительной проверки.');
    drawReport(data, {providers:'provider-list', signals:'signal-list', disclaimer:'disclaimer', result:'result'});
  } catch (error) {
    displayError('error-box', error.name === 'AbortError' ? 'Превышено время ожидания. Попробуйте ещё раз.' : 'Не удалось проверить: ' + error.message);
  } finally { $('submit-btn').disabled = false; setText('submit-text', 'Проверить ссылку'); }
});

let selectedFile = null;
let lastFileReport = null;
let vtAutoCheckTimer = null;
function clearVtAutoCheck() { if (vtAutoCheckTimer) window.clearTimeout(vtAutoCheckTimer); vtAutoCheckTimer = null; }
// The server owns the opt-in upload policy; do not enable a risky action until confirmed.
async function loadFileUploadCapability() {
  try {
    const data = await requestJSON('/api/providers', {}, 9000);
    const active = Boolean(data.virustotal?.configured && data.virustotal?.new_file_upload_enabled);
    $('vt-upload-controls').classList.toggle('hidden', !active);
    $('vt-upload-disabled-note').classList.toggle('hidden', active);
    $('file-vt-upload-opt').disabled = !active;
    if (!active) { $('file-vt-upload-opt').checked = false; $('file-vt-consent-opt').checked = false; }
  } catch (_) {
    $('vt-upload-controls').classList.add('hidden');
    $('vt-upload-disabled-note').classList.remove('hidden');
    $('file-vt-upload-opt').disabled = true;
    $('file-vt-upload-opt').checked = false; $('file-vt-consent-opt').checked = false;
  }
}
loadFileUploadCapability();
$('file-vt-upload-opt').addEventListener('change', () => {
  if ($('file-vt-upload-opt').checked) $('file-share-opt').checked = true;
  else $('file-vt-consent-opt').checked = false;
});
$('file-share-opt').addEventListener('change', () => {
  if (!$('file-share-opt').checked) { $('file-vt-upload-opt').checked = false; $('file-vt-consent-opt').checked = false; }
});
const MAX_SIZE = 8 * 1024 * 1024;
const readableSize = (n) => n < 1024 ? n + ' Б' : n < 1024*1024 ? (n / 1024).toFixed(1) + ' КБ' : (n / (1024*1024)).toFixed(2) + ' МБ';
function chooseFile(file) {
  $('file-error').classList.add('hidden'); $('file-result').classList.add('hidden');
  lastFileReport = null; clearVtAutoCheck();
  $('file-vt-upload-opt').checked = false;
  $('file-vt-consent-opt').checked = false;
  selectedFile = file || null;
  const summary = $('selected-file');
  summary.classList.toggle('hidden', !selectedFile);
  if (selectedFile) {
    summary.textContent = selectedFile.name + ' · ' + readableSize(selectedFile.size);
    if (selectedFile.size > MAX_SIZE) displayError('file-error', 'Файл слишком большой. Максимум 8 МБ.');
    else if (!selectedFile.size) displayError('file-error', 'Невозможно проверить пустой файл.');
  }
}
$('pick-file').addEventListener('click', () => $('file-input').click());
$('file-input').addEventListener('change', (event) => chooseFile(event.target.files?.[0]));
const dz = $('dropzone');
['dragenter','dragover'].forEach(eventType => dz.addEventListener(eventType, (event) => {
  event.preventDefault(); dz.classList.add('drag-over');
}));
['dragleave','drop'].forEach(eventType => dz.addEventListener(eventType, (event) => {
  event.preventDefault(); dz.classList.remove('drag-over');
}));
dz.addEventListener('drop', (event) => chooseFile(event.dataTransfer?.files?.[0]));
function drawVTProgress(data) {
  const token = data?.vt_analysis_token;
  const hasToken = Boolean(token && data.providers?.[0]?.status === 'pending');
  $('vt-scan-progress').classList.toggle('hidden', !hasToken);
  $('vt-status-btn').disabled = !hasToken;
  if (hasToken) setText('vt-scan-progress-note', data.providers[0].message);
}

function redrawFileReport(data) {
  const fileReportWasVisible = !$('file-result').classList.contains('hidden');
  clearVtAutoCheck();
  const stages = data.scan_progress || {};
  setText('file-local-stage', stages.local || 'Собственный анализ завершён.');
  setText('file-antivirus-stage', stages.antivirus || 'Статус неизвестен');
  setText('file-stage-explanation', data.providers?.[0]?.status === 'no_data' || data.providers?.[0]?.status === 'pending' || data.providers?.[0]?.status === 'error' ? (stages.message || '') : '');
  const vtStatus = data.providers?.[0]?.status;
  $('file-vt-indicator').className = 'compact-status-icon ' + (vtStatus === 'checked' ? 'success' : vtStatus === 'pending' ? 'waiting' : 'neutral');
  setText('file-vt-indicator', vtStatus === 'checked' ? '✓' : vtStatus === 'pending' ? '…' : '?');
  setText('file-name', data.filename);
  setText('file-size', readableSize(data.size));
  setText('file-content', data.content.label);
  setText('file-basis', data.content.basis);
  setText('file-sha', data.sha256);
  const coverage = data.inspection_coverage || {};
  const coverageBox = $('file-coverage');
  coverageBox.className = 'coverage-notice compact-coverage ' + (coverage.status === 'partial' ? 'partial' : 'hidden');
  setText('file-coverage-title', coverage.title || 'Объём проверки не определён');
  setText('file-coverage-text', coverage.explanation || 'Неизвестно, какие части файла удалось проверить.');
  $('file-coverage-limits').replaceChildren();
  for (const limitation of coverage.limitations || []) {
    const li = document.createElement('li'); li.textContent = limitation; $('file-coverage-limits').append(li);
  }
  drawFileDetails(data);
  drawQuickVerdict(data, 'file');
  setText('file-next-step', data.recommendation || 'Не открывайте неизвестный файл без дополнительной проверки.');
  const canNewScan = data.providers?.[0]?.status === 'no_data' &&
    !$('vt-upload-controls').classList.contains('hidden') && !data.eicar_test_only;
  $('file-next-check').classList.toggle('hidden', !canNewScan);
  drawVTDetails(data.providers?.[0]);
  drawVTProgress(data);
  drawReport(data, {providers:'file-providers', signals:'file-signals', disclaimer:'file-disclaimer', result:'file-result'});
  $('file-important-signals').classList.toggle('hidden', !(data.signals || []).length);
  if (!fileReportWasVisible) $('file-advanced').open = false;
}

async function checkNewVTReport() {
  if (!lastFileReport?.vt_analysis_token) return;
  $('vt-status-btn').disabled = true;
  setText('vt-scan-progress-note', 'Запрашиваем результат VirusTotal…');
  try {
    const latest = await requestJSON('/api/vt-file-status', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({token: lastFileReport.vt_analysis_token})
    }, 20000);
    lastFileReport.providers[0] = latest;
    if (latest.status === 'pending') {
      lastFileReport.scan_progress.antivirus = 'Новое сканирование VirusTotal ещё выполняется';
      lastFileReport.scan_progress.message = 'Попробуйте снова позднее. Лимиты VirusTotal ограничивают число запросов.';
    } else if (latest.status === 'checked') {
      lastFileReport.scan_progress.antivirus = 'Новый отчёт VirusTotal получен';
      lastFileReport.scan_progress.message = 'Результат антивирусных движков получен; стопроцентной гарантии безопасности нет.';
    } else {
      lastFileReport.scan_progress.antivirus = 'Новый отчёт VirusTotal не получен';
      lastFileReport.scan_progress.message = latest.message || 'Повторите попытку позже.';
    }
    const vtCheck = (lastFileReport.checks || []).find(check => check.label?.includes('VirusTotal'));
    if (vtCheck) { vtCheck.result = latest.message; vtCheck.status = latest.status; }
    lastFileReport.vt_analysis_token = latest.analysis_token || null;
    if (latest.status === 'checked') {
      const malicious = Number(latest.detections || 0);
      const suspicious = Number(latest.suspicious || 0);
      const total = Number(latest.total || 0);
      const hasSignals = (lastFileReport.signals || []).length > 0;
      const partial = lastFileReport.inspection_coverage?.status === 'partial';
      let state, answer, note, recommendation;
      if (lastFileReport.eicar_test_only) {
        state = 'caution'; answer = 'Это тест EICAR, а не настоящий вирус';
        note = 'Антивирусы специально обнаруживают безвредный тест EICAR; реальные вредоносные программы этим не подтверждены.';
        recommendation = 'Тест пройден. Для проверки реальной угрозы выберите другой файл, полученный из достоверного источника.';
      } else if (malicious >= 2) {
        state = 'danger'; answer = 'Обнаружена вредоносная активность по данным антивирусов';
        note = `VirusTotal: ${malicious} обнаружений из ${total} ответивших систем. Ложные срабатывания возможны, но риск высок.`;
        recommendation = 'Не открывайте файл. При необходимости удалите его и проверьте устройство антивирусом.';
      } else if (malicious || suspicious || hasSignals) {
        state = 'caution'; answer = 'Есть риск — открывать не рекомендуется';
        note = `VirusTotal: ${malicious} вредоносных, ${suspicious} подозрительных из ${total} ответивших систем. Есть признаки, требующие внимания.`;
        recommendation = 'Не запускайте файл и не включайте макросы. Проверьте источник и файл антивирусом на устройстве.';
      } else if (partial) {
        state = 'unknown'; answer = 'Антивирусы не сообщили об угрозе, но проверка неполная';
        note = 'Отчёт VirusTotal содержит ноль обнаружений, но отдельные вложения или форматы не были исследованы AntiScam.';
        recommendation = 'Не открывайте неожиданный файл без дополнительной проверки содержимого антивирусом.';
      } else {
        state = 'low'; answer = 'По проверке VirusTotal угроз не обнаружено';
        note = `0 опасных и 0 подозрительных из ${total} ответивших систем. Это не гарантия безопасности.`;
        recommendation = 'Проверьте отправителя; не включайте неизвестные макросы и не запускайте незнакомые программы.';
      }
      const titles = {caution: 'Найдены подозрительные признаки', danger: 'Есть обнаружения вредоносности',
                      unknown: 'Часть содержимого не проверена', low: 'Известных угроз не обнаружено'};
      lastFileReport.risk = state;
      lastFileReport.title = lastFileReport.eicar_test_only ? 'Обнаружен тестовый образец EICAR' : titles[state];
      lastFileReport.detail = note;
      lastFileReport.quick_verdict = {state, answer, note};
      lastFileReport.recommendation = recommendation;
    }
    redrawFileReport(lastFileReport);
  } catch (error) {
    setText('vt-scan-progress-note', 'Не удалось получить отчёт: ' + error.message);
    $('vt-status-btn').disabled = false;
  }
}
$('vt-status-btn').addEventListener('click', checkNewVTReport);
$('file-next-check').addEventListener('click', () => {
  // Scroll only. The user must separately check the upload and privacy-consent
  // boxes and submit the form; never send the whole file on this action.
  $('vt-upload-controls').scrollIntoView({behavior: reduceMotion() ? 'auto' : 'smooth', block:'center'});
  $('file-vt-upload-opt').focus();
});
function drawVTDetails(provider) {
  const evidence = $('vt-evidence');
  const findings = Array.isArray(provider?.engine_findings) ? provider.engine_findings.slice(0, 5) : [];
  const date = Number(provider?.last_analysis_date) || 0;
  evidence.classList.toggle('hidden', !findings.length && !date);
  const when = date > 0 ? new Date(date * 1000) : null;
  setText('vt-evidence-date', when && !Number.isNaN(when.getTime()) ?
    'Дата отчёта VirusTotal: ' + when.toLocaleDateString('ru-RU', {timeZone:'UTC'}) + ' (UTC)' : '');
  const list = $('vt-engine-findings'); list.replaceChildren();
  for (const f of findings) {
    const li = document.createElement('li');
    li.textContent = String(f.engine || 'Антивирус') + ': ' + String(f.detection || 'Срабатывание');
    list.append(li);
  }
}

function drawFileDetails(data) {
  const checks = $('file-checks'); checks.replaceChildren();
  for (const check of data.checks || []) {
    const item = document.createElement('div'); item.className = 'file-check-item';
    const dot = document.createElement('span');
    const status = check.status || 'checked';
    dot.textContent = status === 'checked' ? '✓' : status === 'error' ? '!' : '?';
    dot.className = 'file-check-mark ' + (status === 'checked' ? '' : 'not-complete');
    const body = document.createElement('div');
    const name = document.createElement('strong'); name.textContent = check.label;
    const detail = document.createElement('p'); detail.textContent = check.result;
    body.append(name, detail); item.append(dot, body); checks.append(item);
  }
  const archive = $('archive-info'); archive.classList.toggle('hidden', !data.archive);
  $('archive-items').replaceChildren();
  if (data.archive) {
    setText('archive-count', data.archive.count + ' элементов');
    setText('archive-note', data.archive.note);
    for (const member of data.archive.preview || []) {
      const row = document.createElement('div'); row.className = 'archive-item';
      const name = document.createElement('span'); name.className = 'archive-item-name'; name.textContent = member.name;
      const ext = document.createElement('span'); ext.className = 'archive-item-kind'; ext.textContent = member.kind;
      row.append(name, ext); $('archive-items').append(row);
    }
  }
}

$('file-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('file-error').classList.add('hidden'); $('file-result').classList.add('hidden');
  if (!selectedFile) { displayError('file-error', 'Сначала выберите файл.'); $('pick-file').focus(); return; }
  if (!selectedFile.size || selectedFile.size > MAX_SIZE) { displayError('file-error', 'Поддерживаются непустые файлы до 8 МБ.'); return; }
  if ($('file-vt-upload-opt').checked && !$('file-vt-consent-opt').checked) {
    displayError('file-error', 'Для отправки целого файла в VirusTotal необходимо прочитать соглашение и поставить отдельную галочку согласия.');
    $('file-vt-consent-opt').focus(); return;
  }
  const form = new FormData();
  form.append('file', selectedFile, selectedFile.name);
  form.append('check_hash', String($('file-share-opt').checked));
  form.append('submit_to_vt', String($('file-vt-upload-opt').checked && !$('file-vt-upload-opt').disabled));
  form.append('vt_public_consent', String($('file-vt-consent-opt').checked && $('file-vt-upload-opt').checked));
  $('file-submit-btn').disabled = true; setText('file-submit-text', 'Анализируем файл…');
  try {
    const data = await requestJSON('/api/scan-file', {method:'POST', body:form}, 50000);
    lastFileReport = data;
    setText('file-report-date', 'AntiScam · отчёт создан: ' + new Date().toLocaleString('ru-RU'));
    redrawFileReport(data);
    if (data.vt_analysis_token) {
      // One delayed status check: avoid exhausting the free public VirusTotal quota.
      vtAutoCheckTimer = window.setTimeout(() => { vtAutoCheckTimer = null; if (lastFileReport?.vt_analysis_token === data.vt_analysis_token) checkNewVTReport(); }, 45000);
    }
  } catch (error) {
    displayError('file-error', error.name === 'AbortError' ? 'Превышено время ожидания. Попробуйте ещё раз.' : 'Не удалось проверить: ' + error.message);
  } finally { $('file-submit-btn').disabled = false; setText('file-submit-text', 'Проверить файл'); }
});

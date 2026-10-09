'use strict';
const $ = (id) => document.getElementById(id);
const setText = (id, value) => { $(id).textContent = String(value ?? ''); };
const reduceMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const ROUTE = {link: '/', file: '/file', about: '/about'};
const modeForPath = () => location.pathname === '/file' ? 'file' : location.pathname === '/about' ? 'about' : 'link';

function navigate(mode, push = false) {
  if (!(mode in ROUTE)) mode = 'link';
  const info = mode === 'about';
  $('scan-pages').classList.toggle('hidden', info);
  $('about-page').classList.toggle('hidden', !info);
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
  $(ids.banner).className = 'risk-banner ' + risk;
  setText(ids.symbol, ({low:'✓', caution:'!', danger:'×', unknown:'?'})[risk]);
  setText(ids.title, data.title);
  setText(ids.detail, data.detail);
  const providers = $(ids.providers); providers.replaceChildren();
  for (const provider of data.providers || []) providerRow(providers, provider);
  const signals = $(ids.signals); signals.replaceChildren();
  if (!data.signals || data.signals.length === 0) {
    const node = document.createElement('div'); node.className = 'signal passive';
    const dot = document.createElement('span'); dot.className = 'signal-dot'; dot.textContent = '✓';
    const description = document.createElement('span'); description.textContent = 'Явных признаков риска в доступных данных не выявлено. Это не доказывает безопасность.';
    node.append(dot, description); signals.append(node);
  } else {
    for (const signal of data.signals) signalRow(signals, signal);
  }
  setText(ids.disclaimer, data.disclaimer);
  $(ids.result).classList.remove('hidden');
  $(ids.result).scrollIntoView({behavior: reduceMotion() ? 'auto' : 'smooth', block:'start'});
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
      body: JSON.stringify({url, share_with_services: $('share-opt').checked, inspect_headers: $('headers-opt').checked})
    }, 22000);
    setText('result-url', data.display_url);
    drawOwnAnalysis(data.local_analysis);
    setText('content-label', data.content.label);
    setText('content-basis', data.content.basis);
    const headerNames = {ok:'Получены', skipped:'Не запрашивались', unknown:'Не удалось получить'};
    setText('header-status', headerNames[data.header_probe.status] || 'Неизвестно');
    setText('header-message', data.header_probe.message);
    drawReport(data, {banner:'risk-banner', symbol:'risk-symbol', title:'risk-title', detail:'risk-text', providers:'provider-list', signals:'signal-list', disclaimer:'disclaimer', result:'result'});
  } catch (error) {
    displayError('error-box', error.name === 'AbortError' ? 'Превышено время ожидания. Попробуйте ещё раз.' : 'Не удалось проверить: ' + error.message);
  } finally { $('submit-btn').disabled = false; setText('submit-text', 'Проверить ссылку'); }
});

let selectedFile = null;
const MAX_SIZE = 8 * 1024 * 1024;
const readableSize = (n) => n < 1024 ? n + ' Б' : n < 1024*1024 ? (n / 1024).toFixed(1) + ' КБ' : (n / (1024*1024)).toFixed(2) + ' МБ';
function chooseFile(file) {
  $('file-error').classList.add('hidden'); $('file-result').classList.add('hidden');
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
function drawFileDetails(data) {
  const checks = $('file-checks'); checks.replaceChildren();
  for (const check of data.checks || []) {
    const item = document.createElement('div'); item.className = 'file-check-item';
    const dot = document.createElement('span'); dot.textContent = '✓'; dot.className = 'file-check-mark';
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
  const form = new FormData();
  form.append('file', selectedFile, selectedFile.name);
  form.append('check_hash', String($('file-share-opt').checked));
  $('file-submit-btn').disabled = true; setText('file-submit-text', 'Анализируем файл…');
  try {
    const data = await requestJSON('/api/scan-file', {method:'POST', body:form}, 30000);
    setText('file-name', data.filename);
    setText('file-size', readableSize(data.size));
    setText('file-content', data.content.label);
    setText('file-basis', data.content.basis);
    setText('file-sha', data.sha256);
    drawFileDetails(data);
    drawReport(data, {banner:'file-risk-banner', symbol:'file-risk-symbol', title:'file-risk-title', detail:'file-risk-text', providers:'file-providers', signals:'file-signals', disclaimer:'file-disclaimer', result:'file-result'});
  } catch (error) {
    displayError('file-error', error.name === 'AbortError' ? 'Превышено время ожидания. Попробуйте ещё раз.' : 'Не удалось проверить: ' + error.message);
  } finally { $('file-submit-btn').disabled = false; setText('file-submit-text', 'Проверить файл'); }
});

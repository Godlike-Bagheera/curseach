'use strict';

// ---------- Guest detection ----------
const appEl = document.getElementById('app');
const isGuest = document.body.dataset.guest === 'true';

// ---------- DOM helpers ----------
function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) {
        for (const [k, v] of Object.entries(attrs)) {
            if (k === 'text') node.textContent = v;
            else if (k === 'className') node.className = v;
            else if (k === 'dataset') Object.assign(node.dataset, v);
            else if (k.startsWith('on') && typeof v === 'function') {
                node.addEventListener(k.slice(2).toLowerCase(), v);
            } else if (k === 'disabled') node.disabled = !!v;
            else node.setAttribute(k, v);
        }
    }
    if (children) {
        for (const c of children) {
            if (c == null) continue;
            if (typeof c === 'string') node.appendChild(document.createTextNode(c));
            else node.appendChild(c);
        }
    }
    return node;
}

function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
}

// =============================================================
//   ЭКРАН ЗАГРУЗКИ — CRT-эффект
//   Класс is-loading стоит на <html> сразу из шаблона.
//   Снимаем его ТОЛЬКО после того, как экран полностью погас,
//   чтобы layout не дёргался на глазах пользователя.
// =============================================================


function showToast(message) {
    let toast = document.getElementById('crt-toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'crt-toast';
        toast.className = 'toast-notification';
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.classList.add('show');
    setTimeout(() => { toast.classList.remove('show'); }, 5000);
}

function initLoadingScreen() {
    const screen = document.getElementById('loading-screen');
    const fill = document.getElementById('loading-bar-fill');
    const status = document.getElementById('loading-status');

    // Если экрана нет — просто снимаем блокировку прокрутки
    if (!screen || !fill || !status) {
        document.documentElement.classList.remove('is-loading');
        return;
    }

    const phrases = [
        'ПРОВЕРКА СИСТЕМ...',
        'ЗАГРУЗКА МОДУЛЕЙ...',
        'ИНИЦИАЛИЗАЦИЯ...',
        'ПОЧТИ ГОТОВО...',
        'ДОБРО ПОЖАЛОВАТЬ',
    ];

    let progress = 0;
    let phraseIndex = -1;

    const FADE_MS = 550;

    const finish = () => {
        // Небольшая пауза, чтобы пользователь увидел 100% и "ДОБРО ПОЖАЛОВАТЬ"
        setTimeout(() => {
            // Запускаем fade-out
            screen.classList.add('is-hidden');

            // И только когда экран уже полностью прозрачный —
            // снимаем блокировку прокрутки и удаляем DOM.
            // Никаких сдвигов на глазах пользователя.
            setTimeout(() => {
                document.documentElement.classList.remove('is-loading');
                if (screen.parentNode) screen.parentNode.removeChild(screen);
            }, FADE_MS + 50);
        }, 420);
    };

    const updateProgress = () => {
        progress += Math.random() * 16 + 6;
        if (progress > 100) progress = 100;

        fill.style.width = progress + '%';

        const idx = Math.min(
            phrases.length - 1,
            Math.floor((progress / 100) * phrases.length)
        );
        if (idx !== phraseIndex) {
            phraseIndex = idx;
            status.textContent = phrases[idx];
        }

        if (progress < 100) {
            setTimeout(updateProgress, Math.random() * 180 + 90);
        } else {
            finish();
        }
    };

    // Ждём, пока CRT-эффект отыграет "включение",
    // и только потом начинаем рост прогресс-бара
    setTimeout(updateProgress, 1200);
}

// ---------- State ----------
let taskId = null;
let ws = null;
let availableChecks = [];
let historyChart = null;
let cachedScans = [];

const $ = id => document.getElementById(id);
const urlInput = $('urlInput');
const scanBtn = $('scanBtn');
const progressBar = $('progressBar');
const cancelBtn = $('cancelBtn');
const critCount = $('critCount');
const highCount = $('highCount');
const medCount = $('medCount');
const lowCount = $('lowCount');
const statusValue = $('statusValue');
const terminal = $('terminal');
const htmlBtn = $('htmlBtn');
const jsonBtn = $('jsonBtn');
const csvBtn = $('csvBtn');
const xlsxBtn = $('xlsxBtn');
const customBlock = $('customBlock');
const checksList = $('checksList');
const checksCountEl = $('checksCount');

// ---------- Auth fields ----------
const acc1User = $('acc1User');
const acc1Pass = $('acc1Pass');
const acc2User = $('acc2User');
const acc2Pass = $('acc2Pass');


// ---------- Tabs ----------
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        if (btn.disabled) return;
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        document.getElementById(btn.dataset.tab).classList.add('active');
        if (btn.dataset.tab === 'history' && !isGuest) { loadHistory(); loadHistoryChart(); }
        
    });
});

// ---------- Mode ----------
document.querySelectorAll('input[name="scanMode"]').forEach(radio => {
    radio.addEventListener('change', () => {
        if (isGuest) return;
        document.querySelectorAll('.mode-item').forEach(m => {
            m.classList.toggle('active', m.dataset.mode === radio.value);
        });
        if (radio.value === 'custom') {
            customBlock.classList.remove('hidden');
            if (availableChecks.length === 0) loadAvailableChecks();
        } else {
            customBlock.classList.add('hidden');
        }
    });
});

function getMode() {
    const checked = document.querySelector('input[name="scanMode"]:checked');
    return checked ? checked.value : 'full';
}

function getSelectedChecks() {
    return Array.from(checksList.querySelectorAll('input[type="checkbox"]:checked'))
        .map(cb => cb.dataset.id);
}

// ---------- Auth ----------
function buildAccount(userEl, passEl, prefix) {
    const u = (userEl.value || '').trim();
    const p = (passEl.value || '').trim();
    if (!u || !p) return null;
    return { auth_type: 'bearer', username: u, password: p };
};
    const typeEl = $(prefix + 'Type');
    const authType = typeEl ? typeEl.value : 'bearer';
    if (authType === 'apikey') {
        const h = ($(prefix + 'KeyHeader').value || '').trim();
        const v = $(prefix + 'KeyValue').value || '';
        if (!h || !v) return null;
        return { auth_type: 'apikey', api_key_header: h, api_key_value: v };
    }
    const u = (userEl.value || '').trim();
    const p = passEl.value || '';
    if (!u || !p) return null;
    const acc = { username: u, password: p, auth_type: authType };
    if (authType === 'form') {
        const lp = ($(prefix + 'LoginPath').value || '').trim();
        if (lp) acc.login_path = lp;
        const ff = ($(prefix + 'FormFields').value || '').trim();
        if (ff) { try { acc.form_fields = JSON.parse(ff); } catch (e) { /* невалидный JSON — пропускаем */ } }
    }
    return acc;
}

async function loadAuthProfiles() {
    if (isGuest) return;
    try {
        const resp = await fetch('/auth-profiles');
        if (!resp.ok) return;
        const profiles = await resp.json();
        for (const prefix of ['acc1', 'acc2']) {
            const sel = $(prefix + 'Profile');
            if (!sel) continue;
            const cur = sel.value;
            clear(sel);
            sel.appendChild(el('option', { value: '', text: '— вручную —' }));
            for (const p of profiles) sel.appendChild(el('option', { value: String(p.id), text: p.name + ' (' + p.auth_type + ')' }));
            sel.value = cur;
        }
    } catch (e) { /* профили не критичны */ }
}

function saveAuthProfile(prefix) {
    if (isGuest) return;
    const name = prompt('Имя профиля:');
    if (!name) return;
    const acc = buildAccount($(prefix + 'User'), $(prefix + 'Pass'), prefix);
    if (!acc || acc.profile_id) { alert('Заполните данные аккаунта вручную (не выбирая профиль)'); return; }
    const body = { name, auth_type: acc.auth_type || 'bearer', username: acc.username || '', password: acc.password || '', api_key_header: acc.api_key_header || '', api_key_value: acc.api_key_value || '', form_fields: acc.form_fields || null, login_path: acc.login_path || '' };
    fetch('/auth-profiles', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
        .then(r => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
        .then(() => { appendTerminal('[SYS] Профиль сохранён: ' + name); loadAuthProfiles(); })
        .catch(e => alert('Ошибка сохранения: ' + e.message));
}

function initAuthUI() {
    for (const prefix of ['acc1', 'acc2']) {
        const typeEl = $(prefix + 'Type');
        const extra = $(prefix + 'Extra');
        if (typeEl && extra) typeEl.addEventListener('change', () => extra.classList.toggle('hidden', typeEl.value === 'bearer'));
        const saveBtn = $(prefix + 'SaveProfile');
        if (saveBtn) saveBtn.addEventListener('click', () => saveAuthProfile(prefix));
    }
    loadAuthProfiles();
}

// ---------- Available checks ----------
async function loadAvailableChecks() {
    if (isGuest) return;
    try {
        const resp = await fetch('/available-checks');
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        availableChecks = await resp.json();
        renderChecks();
    } catch (e) {
        clear(checksList);
        checksList.appendChild(el('div', { className: 'empty-history', text: 'Не удалось загрузить проверки' }));
    }
}

function renderChecks() {
    clear(checksList);
    const sorted = [...availableChecks].sort((a, b) => {
        if (a.quick !== b.quick) return a.quick ? -1 : 1;
        return a.name.localeCompare(b.name, 'ru');
    });
    for (const c of sorted) {
        const cb = el('input', { type: 'checkbox', dataset: { id: c.id } });
        const help = document.createElement('button');
        help.type = 'button';
        help.className = 'help-q';
        help.dataset.help = 'check:' + c.id;
        help.setAttribute('aria-label', 'Что это?');
        help.textContent = '?';
        const label = el('label', { className: 'check-item' }, [
            cb,
            el('span', { className: 'name', text: c.name }),
            el('span', { className: 'check-level ' + c.level, text: c.level }),
            help,
        ]);
        cb.addEventListener('change', () => {
            label.classList.toggle('checked', cb.checked);
            updateCounter();
        });
        checksList.appendChild(label);
    }
    updateCounter();
}

function updateCounter() {
    const total = checksList.querySelectorAll('input[type="checkbox"]').length;
    const selected = checksList.querySelectorAll('input[type="checkbox"]:checked').length;
    checksCountEl.textContent = `${selected} / ${total}`;
}

$('selectAll').addEventListener('click', () => {
    if (isGuest) return;
    checksList.querySelectorAll('input[type="checkbox"]').forEach(cb => {
        cb.checked = true;
        cb.closest('.check-item').classList.add('checked');
    });
    updateCounter();
});
$('selectNone').addEventListener('click', () => {
    if (isGuest) return;
    checksList.querySelectorAll('input[type="checkbox"]').forEach(cb => {
        cb.checked = false;
        cb.closest('.check-item').classList.remove('checked');
    });
    updateCounter();
});

// ---------- Terminal ----------
function classifyLine(msg) {
    if (msg.startsWith('[!]') || msg.includes('КРИТИЧНО') || msg.includes('CRITICAL')) return 'terminal-crit';
    if (msg.startsWith('[ОШИБКА]') || msg.startsWith('[ERROR]') || msg.startsWith('[-]')) return 'terminal-error';
    if (msg.startsWith('[ВНИМАНИЕ]') || msg.startsWith('[WARN]') || msg.startsWith('[?]')) return 'terminal-warn';
    if (msg.startsWith('[OK]') || msg.startsWith('[+]')) return 'terminal-ok';
    if (msg.startsWith('===')) return 'terminal-sys';
    if (msg.startsWith('[ИНФО]') || msg.startsWith('[INFO]')) return 'terminal-info';
    return 'terminal-info';
}

function appendTerminal(msg) {
    const line = el('div', { className: 'terminal-line ' + classifyLine(msg), text: msg });
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

function clearTerminal() {
    clear(terminal);
}

// ---------- Status ----------
const STATUS_MAP = {
    pending:   'ОЖИДАНИЕ',
    running:   'СКАНИРОВАНИЕ',
    completed: 'ГОТОВО',
    failed:    'ОШИБКА',
    cancelled: 'ОТМЕНЕНО',
};

function applyScoreStyle(score) {
    const box = document.getElementById('scoreBox');
    const val = document.getElementById('scoreValue');
    if (!box || !val) return;

    val.textContent = score;
    box.classList.remove('score-safe', 'score-medium', 'score-high', 'score-critical');

    if (score >= 80) box.classList.add('score-safe');
    else if (score >= 50) box.classList.add('score-medium');
    else if (score >= 20) box.classList.add('score-high');
    else box.classList.add('score-critical');
}

function setStatus(data) {
    if (typeof data.critical_count === 'number' && critCount) critCount.textContent = data.critical_count;
    if (typeof data.high_count === 'number' && highCount) highCount.textContent = data.high_count;
    if (typeof data.medium_count === 'number' && medCount) medCount.textContent = data.medium_count;
    if (typeof data.low_count === 'number' && lowCount) lowCount.textContent = data.low_count;
    if (typeof data.score === 'number') applyScoreStyle(data.score);
    if (typeof data.progress === 'number' && progressBar) { progressBar.style.width = (data.progress * 100) + '%'; progressBar.setAttribute('aria-valuenow', String(Math.round(data.progress * 100))); }
    const reqEl = $('progressRequests');
    if (reqEl && typeof data.requests_used === 'number') {
        reqEl.textContent = 'ЗАПРОСОВ ' + data.requests_used + ' / ' + (data.requests_max || '—');
    }
    if (data.status && statusValue) {
        statusValue.textContent = STATUS_MAP[data.status] || data.status.toUpperCase();
    }
}

// ---------- WebSocket ----------
function openWebSocket(id) {
    closeWebSocket();
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(`${proto}://${location.host}/ws/scan/${id}`);

    ws.onmessage = (event) => {
        let data;
        try { data = JSON.parse(event.data); } catch (e) { return; }
        handleWsEvent(data);
    };
    ws.onerror = () => appendTerminal('[ОШИБКА] Ошибка WebSocket');
    ws.onclose = () => { ws = null; };
}

function closeWebSocket() {
    if (ws) {
        try { ws.close(); } catch (e) { /* ignore */ }
        ws = null;
    }
}

function handleWsEvent(data) {
    switch (data.type) {
        case 'init':
            clearTerminal();
    showToast('Сканирование запущено…');
            (data.logs || []).forEach(appendTerminal);
            setStatus(data);
            break;
        case 'log':
            appendTerminal(data.message);
            break;
        case 'status':
            setStatus(data);
            break;
        case 'complete':
            setStatus({ status: data.status });
            scanBtn.disabled = false;
            scanBtn.textContent = 'ЗАПУСТИТЬ';
            if (cancelBtn) cancelBtn.classList.add('hidden');
            htmlBtn.disabled = false;
            jsonBtn.disabled = false;
            csvBtn.disabled = false;
            xlsxBtn.disabled = false;
            closeWebSocket();
            break;
        case 'error':
            appendTerminal('[ОШИБКА] ' + (data.message || 'неизвестно'));
            break;
    }
}

// ---------- Scan ----------
async function startScan() {
    if (isGuest) {
        appendTerminal('[ОШИБКА] Гостевой режим — действие недоступно');
        return;
    }
    const url = urlInput.value.trim();
    if (!url) { alert('Введите целевой URL'); return; }

    if (!/^https?:\/\//i.test(url)) {
        alert('URL должен начинаться с http:// или https://');
        urlInput.focus();
        return;
    }
    if (/\s/.test(url)) {
        alert('URL не должен содержать пробелов');
        urlInput.focus();
        return;
    }

    const mode = getMode();
    let checks_ = null;
    if (mode === 'custom') {
        checks_ = getSelectedChecks();
        if (checks_.length === 0) { alert('Выберите хотя бы одну проверку'); return; }
    }

    clearTerminal();
    showToast('Сканирование запущено…');
    appendTerminal('[SYS] Инициализация сканирования...');
    progressBar.style.width = '0%'; progressBar.setAttribute('aria-valuenow', '0');
    critCount.textContent = '0';
    if (highCount) highCount.textContent = '0';
    medCount.textContent = '0';
    lowCount.textContent = '0';
    applyScoreStyle(100);
    statusValue.textContent = 'ОЖИДАНИЕ';
    htmlBtn.disabled = true;
    jsonBtn.disabled = true;
    csvBtn.disabled = true;
    xlsxBtn.disabled = true;
    scanBtn.disabled = true;
    scanBtn.textContent = 'ВЫПОЛНЯЕТСЯ';
    if (cancelBtn) { cancelBtn.classList.remove('hidden'); cancelBtn.disabled = false; }

    try {
        const body = { url, mode };
        
        
        if (checks_) body.checks = checks_;

        const a1 = buildAccount(acc1User, acc1Pass, 'acc1');
        if (a1) { if (a1.profile_id) body.account1_profile_id = a1.profile_id; else body.account1 = a1; }

        const a2 = buildAccount(acc2User, acc2Pass, 'acc2');
        if (a2) { if (a2.profile_id) body.account2_profile_id = a2.profile_id; else body.account2 = a2; }

        
        

        if (a1) appendTerminal(`[SYS] Аккаунт 1: ${a1.username || ('профиль #' + a1.profile_id)}`);
        else appendTerminal('[SYS] Аккаунт 1: не задан (анонимно)');
        if (a2) appendTerminal(`[SYS] Аккаунт 2: ${a2.username || ('профиль #' + a2.profile_id)}`);
        else appendTerminal('[SYS] Аккаунт 2: не задан (без cross-user проверок)');

        const resp = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.detail || ('HTTP ' + resp.status));
        }
        const data = await resp.json();
        taskId = data.task_id;
        openWebSocket(taskId);
    } catch (e) {
        appendTerminal('[ОШИБКА] ' + e.message);
        scanBtn.disabled = false;
        scanBtn.textContent = 'ЗАПУСТИТЬ';
        if (cancelBtn) cancelBtn.classList.add('hidden');
        statusValue.textContent = 'ОШИБКА';
    }
}

async function cancelScan() {
    if (!taskId || !cancelBtn) return;
    cancelBtn.disabled = true;
    appendTerminal('[SYS] Отмена скана...');
    try {
        const resp = await fetch(`/scan/${taskId}/cancel`, { method: 'POST' });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            appendTerminal('[ОШИБКА] Отмена: ' + (err.detail || ('HTTP ' + resp.status)));
            cancelBtn.disabled = false;
        }
    } catch (e) {
        appendTerminal('[ОШИБКА] Отмена: ' + e.message);
        cancelBtn.disabled = false;
    }
}

async function exportReport(type) {
    if (isGuest) return;
    if (!taskId) return;
    try {
        if (type === 'html') {
            window.open(`/report/html/${taskId}`, '_blank');
        } else if (type === 'json') {
            const resp = await fetch(`/report/json/${taskId}`);
            if (!resp.ok) throw new Error('Ошибка экспорта');
            const data = await resp.json();
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'ci_cd_report.json';
            a.click();
            URL.revokeObjectURL(a.href);
        } else if (type === 'csv') {
            window.location.href = `/report/csv/${taskId}`;
        } else if (type === 'xlsx') {
            window.location.href = `/report/xlsx/${taskId}`;
        }
    } catch (e) {
        appendTerminal('[ОШИБКА] Экспорт: ' + e.message);
    }
}

// ---------- График динамики ----------
function renderHistoryChart(scans) {
    const canvas = document.getElementById('historyChart');
    const emptyEl = document.getElementById('chartEmpty');
    if (!canvas) return;

    if (typeof Chart === 'undefined') {
        canvas.style.display = 'none';
        if (emptyEl) {
            emptyEl.style.display = 'block';
            emptyEl.innerHTML = 'Библиотека графиков не загружена.<br>Проверьте соединение с интернетом.';
        }
        return;
    }

    if (!scans || scans.length < 2) {
        canvas.style.display = 'none';
        if (emptyEl) {
            emptyEl.style.display = 'block';
            emptyEl.innerHTML = 'Недостаточно данных для построения графика.<br>Выполните минимум 2 сканирования.';
        }
        if (historyChart) { historyChart.destroy(); historyChart = null; }
        return;
    }

    canvas.style.display = 'block';
    if (emptyEl) emptyEl.style.display = 'none';

    const ordered = [...scans].reverse().slice(-20);

    const labels = ordered.map(s => {
        const raw = s.scan_date.replace('T', ' ');
        return raw.slice(5, 16);
    });

    const crit  = ordered.map(s => s.critical ?? 0);
    const high  = ordered.map(s => s.high ?? 0);
    const med   = ordered.map(s => s.medium ?? 0);
    const low   = ordered.map(s => s.low ?? 0);
    const score = ordered.map(s => {
        const p = (s.critical ?? 0) * 20 + (s.high ?? 0) * 10 + (s.medium ?? 0) * 5 + (s.low ?? 0) * 2;
        return Math.max(0, 100 - p);
    });

    if (historyChart) historyChart.destroy();

    const mono = 'JetBrains Mono, monospace';

    historyChart = new Chart(canvas, {
        type: 'line',
        data: {
            labels,
            datasets: [
                { label: 'КРИТИЧНО', data: crit,  borderColor: '#ff0044', backgroundColor: 'rgba(255, 0, 68, 0.15)',  pointBackgroundColor: '#ff0044', pointBorderColor: '#ff0044', borderWidth: 2, tension: 0.25, pointRadius: 4, yAxisID: 'y', order: 1 },
                { label: 'ВЫСОКО',   data: high,  borderColor: '#d500f9', backgroundColor: 'rgba(213, 0, 249, 0.15)', pointBackgroundColor: '#d500f9', pointBorderColor: '#d500f9', borderWidth: 2, tension: 0.25, pointRadius: 4, yAxisID: 'y', order: 2 },
                { label: 'СРЕДНЕ',   data: med,   borderColor: '#ffb300', backgroundColor: 'rgba(255, 179, 0, 0.15)', pointBackgroundColor: '#ffb300', pointBorderColor: '#ffb300', borderWidth: 2, tension: 0.25, pointRadius: 4, yAxisID: 'y', order: 3 },
                { label: 'НИЗКО',    data: low,   borderColor: '#00ff41', backgroundColor: 'rgba(0, 255, 65, 0.15)',  pointBackgroundColor: '#00ff41', pointBorderColor: '#00ff41', borderWidth: 2, tension: 0.25, pointRadius: 4, yAxisID: 'y', order: 4 },
                { label: 'ОЦЕНКА',   data: score, borderColor: '#00bfff', backgroundColor: 'rgba(0, 191, 255, 0.12)', pointBackgroundColor: '#00bfff', pointBorderColor: '#00bfff', borderWidth: 3, tension: 0.3,  pointRadius: 5, yAxisID: 'yScore', order: 0 },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: {
                    labels: {
                        color: '#00ff41',
                        font: { family: mono, size: 14, weight: '800' },
                        boxWidth: 22,
                        padding: 18,
                    }
                },
                tooltip: {
                    backgroundColor: '#0a1f0a',
                    borderColor: '#00ff41',
                    borderWidth: 2,
                    titleColor: '#00ff41',
                    bodyColor: '#7fbf80',
                    titleFont: { family: mono, size: 13, weight: '800' },
                    bodyFont: { family: mono, size: 13 },
                    padding: 12,
                    callbacks: {
                        label: function (context) {
                            const label = context.dataset.label || '';
                            const value = context.parsed.y;
                            if (context.dataset.yAxisID === 'yScore') {
                                return `${label}: ${value} / 100`;
                            }
                            return `${label}: ${value} шт.`;
                        },
                        afterBody: function (items) {
                            let total = 0;
                            for (const item of items) {
                                if (item.dataset.yAxisID === 'y') {
                                    total += item.parsed.y;
                                }
                            }
                            return ['', `─ Всего уязвимостей: ${total}`];
                        },
                    },
                },
            },
            scales: {
                x: {
                    ticks: { color: '#7fbf80', font: { family: mono, size: 12 }, maxRotation: 0 },
                    grid: { color: 'rgba(31, 95, 31, 0.4)' },
                },
                y: {
                    beginAtZero: true,
                    position: 'left',
                    title: {
                        display: true,
                        text: 'УЯЗВИМОСТИ (шт.)',
                        color: '#7fbf80',
                        font: { family: mono, size: 11, weight: '800' },
                    },
                    ticks: { color: '#7fbf80', font: { family: mono, size: 12 }, stepSize: 1, precision: 0 },
                    grid: { color: 'rgba(31, 95, 31, 0.4)' },
                },
                yScore: {
                    beginAtZero: true,
                    max: 100,
                    position: 'right',
                    title: {
                        display: true,
                        text: 'ОЦЕНКА (0-100)',
                        color: '#00bfff',
                        font: { family: mono, size: 11, weight: '800' },
                    },
                    ticks: { color: '#00bfff', font: { family: mono, size: 12 }, stepSize: 20 },
                    grid: { display: false },
                },
            },
        },
    });
}

// ---------- History ----------
let historyPage = 0;
const HISTORY_PAGE_SIZE = 25;

function historyFilterState() {
    try { return JSON.parse(localStorage.getItem('curseach.historyRange') || '{}'); } catch (e) { return {}; }
}

async function loadHistory(page) {
    if (isGuest) return;
    if (typeof page === 'number') historyPage = Math.max(0, page);
    const container = $('historyList');
    clear(container);
    container.appendChild(el('div', { className: 'empty-history', text: 'Загрузка...' }));

    const f = historyFilterState();
    const targetInput = $('historyTargetFilter');
    const target = targetInput ? targetInput.value.trim() : '';
    const p = new URLSearchParams();
    if (f.from) p.set('from', f.from);
    if (f.to) p.set('to', f.to);
    if (target) p.set('target', target);
    p.set('limit', String(HISTORY_PAGE_SIZE));
    p.set('offset', String(historyPage * HISTORY_PAGE_SIZE));

    try {
        const resp = await fetch('/history?' + p.toString());
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const scans = await resp.json();
        const total = parseInt(resp.headers.get('X-Total-Count') || String(scans.length), 10);
        cachedScans = scans;

        clear(container);
        if (!scans.length) {
            const filtered = !!(f.from || f.to || target);
            container.appendChild(el('div', { className: 'empty-history',
                text: filtered ? 'За выбранный период проверок нет' : 'История пуста' }));
        } else {
            const table = el('table', { className: 'history-table' });
            const thead = el('thead', null, [
                el('tr', null, [
                    el('th', { className: 'col-diff', text: 'DIFF', title: 'Отметьте два скана одной цели и нажмите «Сравнить»' }),
                    el('th', { className: 'col-id', text: 'ID', title: 'Номер скана в истории' }),
                    el('th', { className: 'col-date', text: 'ДАТА (UTC)', title: 'Когда выполнялось сканирование (всемирное время)' }),
                    el('th', { className: 'col-target', text: 'ЦЕЛЬ', title: 'Адрес просканированного API' }),
                    el('th', { className: 'col-sev th-crit', text: 'КРИТ', title: 'Критические находки: возможен полный взлом — чинить немедленно' }),
                    el('th', { className: 'col-sev th-high', text: 'ВЫС', title: 'Высокий риск: реальная утечка данных или доступ к чужим аккаунтам' }),
                    el('th', { className: 'col-sev th-med', text: 'СРЕД', title: 'Средний риск: опасно при определённых условиях' }),
                    el('th', { className: 'col-sev th-low', text: 'НИЗК', title: 'Низкий риск: мелкие недочёты и «гигиена» безопасности' }),
                    el('th', { className: 'col-actions', text: 'ДЕЙСТВИЯ' }),
                ]),
            ]);
            const sevBadge = (cls, n) => el('span', {
                className: 'badge ' + cls + ((n ?? 0) > 0 ? '' : ' badge-zero'),
                text: String(n ?? 0),
            });
            const tbody = el('tbody');
            for (const s of scans) {
                const viewBtn = el('button', { className: 'btn-view', text: 'ПРОСМОТР', title: 'Открыть полный отчёт по скану',
                    onclick: () => window.open(`/history/${s.id}/view`, '_blank') });
                const chartBtn = el('button', { className: 'btn-chart', text: 'ДИАГРАММА', title: 'Диаграмма найденных уязвимостей',
                    onclick: () => window.open(`/history/${s.id}/chart`, '_blank', 'width=1200,height=800') });
                const bundleBtn = el('button', { className: 'btn-bundle', text: 'ZIP', title: 'Скачать все форматы отчёта одним архивом',
                    onclick: () => window.location.href = `/history/${s.id}/bundle` });
                const delBtn = el('button', { className: 'btn-delete', text: 'УДАЛИТЬ', title: 'Удалить этот скан из истории',
                    onclick: async () => {
                        if (!confirm('Удалить скан #' + s.id + '?')) return;
                        try {
                            const r = await fetch(`/history/${s.id}`, { method: 'DELETE' });
                            if (r.ok) { loadHistory(); loadHistoryChart(); } else alert('Ошибка удаления');
                        } catch (e) { alert('Ошибка: ' + e.message); }
                    } });
                const row = el('tr', null, [
                    el('td', { className: 'col-diff diff-cell' }, [el('input', { type: 'checkbox', className: 'diff-check',
                        dataset: { id: String(s.id), target: s.target_url }, title: 'Выбрать для сравнения' })]),
                    el('td', { className: 'col-id', text: String(s.id) }),
                    el('td', { className: 'col-date', text: s.scan_date.replace('T', ' ').slice(0, 19) }),
                    el('td', { className: 'col-target url-cell', text: s.target_url, title: s.target_url }),
                    el('td', { className: 'col-sev' }, [sevBadge('badge-crit', s.critical)]),
                    el('td', { className: 'col-sev' }, [sevBadge('badge-high', s.high)]),
                    el('td', { className: 'col-sev' }, [sevBadge('badge-med', s.medium)]),
                    el('td', { className: 'col-sev' }, [sevBadge('badge-low', s.low)]),
                    el('td', { className: 'col-actions actions-cell' }, [
                        el('div', { className: 'row-actions' }, [viewBtn, chartBtn, bundleBtn, delBtn]),
                    ]),
                ]);
                tbody.appendChild(row);
            }
            table.appendChild(thead);
            table.appendChild(tbody);
            container.appendChild(table);
        }
        renderHistoryPager(total);
        updateDiffButton();
        const cnt = document.querySelector('.hf-count');
        if (cnt) cnt.textContent = `Показано ${scans.length} из ${total}`;
    } catch (e) {
        clear(container);
        container.appendChild(el('div', { className: 'empty-history', text: 'Ошибка: ' + e.message }));
    }
}

async function loadHistoryChart() {
    if (isGuest) return;
    const f = historyFilterState();
    const targetInput = $('historyTargetFilter');
    const target = targetInput ? targetInput.value.trim() : '';
    const p = new URLSearchParams();
    if (f.from) p.set('from', f.from);
    if (f.to) p.set('to', f.to);
    if (target) p.set('target', target);
    p.set('limit', '60');
    p.set('offset', '0');
    try {
        const resp = await fetch('/history?' + p.toString());
        if (!resp.ok) return;
        renderHistoryChart(await resp.json());
    } catch (e) { /* график не критичен — молча пропускаем */ }
}

function updateDiffButton() {
    const btn = $('diffHistoryBtn');
    if (!btn) return;
    const checked = document.querySelectorAll('.diff-check:checked');
    btn.textContent = `СРАВНИТЬ (${checked.length}/2)`;
    btn.disabled = checked.length !== 2;
}

function openDiff() {
    const checked = [...document.querySelectorAll('.diff-check:checked')];
    if (checked.length !== 2) return;
    const targets = new Set(checked.map(c => c.dataset.target));
    if (targets.size > 1) { alert('Выберите два скана одной цели'); return; }
    const ids = checked.map(c => parseInt(c.dataset.id, 10)).sort((x, y) => x - y);
    window.open(`/history/diff/view?a=${ids[0]}&b=${ids[1]}`, '_blank');
}

function renderHistoryPager(total) {
    let pager = $('historyPager');
    if (!pager) {
        pager = el('div', { className: 'history-pager', id: 'historyPager' });
        const actions = document.querySelector('.history-actions');
        if (actions && actions.parentNode) actions.parentNode.insertBefore(pager, actions);
        else return;
    }
    clear(pager);
    const pages = Math.max(1, Math.ceil(total / HISTORY_PAGE_SIZE));
    if (historyPage >= pages) historyPage = pages - 1;
    const prev = el('button', { className: 'action-btn', text: '← НАЗАД', disabled: historyPage <= 0,
        onclick: () => loadHistory(historyPage - 1) });
    const next = el('button', { className: 'action-btn', text: 'ВПЕРЁД →', disabled: historyPage >= pages - 1,
        onclick: () => loadHistory(historyPage + 1) });
    const info = el('span', { className: 'history-pager-info', text: `СТРАНИЦА ${historyPage + 1} / ${pages} · ВСЕГО ${total}` });
    pager.appendChild(prev); pager.appendChild(info); pager.appendChild(next);
}

window.__curseachHistoryReload = () => { loadHistory(0); loadHistoryChart(); };

// ---------- Clear all history ----------
async function clearAllHistory() {
    if (isGuest) return;

    if (!confirm('Удалить ВСЮ историю сканирований?')) return;
    if (!confirm('Это действие НЕОБРАТИМО. Продолжить?')) return;

    try {
        const resp = await fetch('/history', { method: 'DELETE' });
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const data = await resp.json();
        alert(`Удалено записей: ${data.count}`);
        loadHistory();
        loadHistoryChart();
    } catch (e) {
        alert('Ошибка: ' + e.message);
    }
}

// ---------- Export history ----------
function exportHistory() {
    if (isGuest) return;
    let url = '/history/export.xlsx';
    try {
        const r = JSON.parse(localStorage.getItem('curseach.historyRange') || '{}');
        const p = new URLSearchParams();
        if (r.from) p.set('from', r.from);
        if (r.to) p.set('to', r.to);
        if (p.toString()) url += '?' + p.toString();
    } catch (e) { /* фильтр не задан — экспортируем всё */ }
    window.location.href = url;
}

// ---------- Wire up ----------
if (!isGuest) {
    initAuthUI();
    initPlanningUI();
    scanBtn.addEventListener('click', startScan);
    if (cancelBtn) cancelBtn.addEventListener('click', cancelScan);
    urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });
    htmlBtn.addEventListener('click', () => exportReport('html'));
    jsonBtn.addEventListener('click', () => exportReport('json'));
    csvBtn.addEventListener('click', () => exportReport('csv'));
    xlsxBtn.addEventListener('click', () => exportReport('xlsx'));
    $('refreshHistoryBtn').addEventListener('click', () => { loadHistory(historyPage); loadHistoryChart(); });
    const historyTargetFilter = $('historyTargetFilter');
    if (historyTargetFilter) {
        historyTargetFilter.addEventListener('change', () => { loadHistory(0); loadHistoryChart(); });
        historyTargetFilter.addEventListener('keydown', e => { if (e.key === 'Enter') { loadHistory(0); loadHistoryChart(); } });
    }
    $('clearAllHistoryBtn').addEventListener('click', clearAllHistory);
    $('historyList').addEventListener('change', e => { if (e.target.classList.contains('diff-check')) updateDiffButton(); });
    const diffBtn = $('diffHistoryBtn');
    if (diffBtn) diffBtn.addEventListener('click', openDiff);
    const exportBtn = $('exportHistoryBtn');
    if (exportBtn) exportBtn.addEventListener('click', exportHistory);
} else {
    scanBtn.disabled = true;
    htmlBtn.disabled = true;
    jsonBtn.disabled = true;
    csvBtn.disabled = true;
    xlsxBtn.disabled = true;
    urlInput.disabled = true;
    document.querySelectorAll('input[name="scanMode"]').forEach(r => r.disabled = true);
    if ($('refreshHistoryBtn')) $('refreshHistoryBtn').disabled = true;
    if ($('clearAllHistoryBtn')) $('clearAllHistoryBtn').disabled = true;
    if ($('exportHistoryBtn')) $('exportHistoryBtn').disabled = true;
}


// ---------- Планировщик: проекты / расписания / тренд ----------
let trendChart = null;

async function loadProjects() {
    if (isGuest) return;
    try {
        const resp = await fetch('/projects');
        if (!resp.ok) return;
        const projects = await resp.json();
        for (const selId of ['trendProject']) {
            const sel = $(selId);
            if (!sel) continue;
            const cur = sel.value;
            clear(sel);
            sel.appendChild(el('option', { value: '', text: selId === 'trendProject' ? 'все проекты' : '— без проекта —' }));
            for (const p of projects) sel.appendChild(el('option', { value: String(p.id), text: p.name }));
            sel.value = cur;
        }
        const list = $('projectsList');
        if (list) {
            clear(list);
            for (const p of projects) {
                list.appendChild(el('div', { className: 'check-item' }, [
                    el('span', { className: 'name', text: p.name }),
                    el('button', { className: 'mini-btn', text: 'УДАЛИТЬ', onclick: async () => { await fetch('/projects/' + p.id, { method: 'DELETE' }); loadProjects(); } }),
                ]));
            }
        }
    } catch (e) { /* проекты не критичны */ }
}

async function addProject() {
    const inp = $('projectName');
    const name = (inp.value || '').trim();
    if (!name) return;
    await fetch('/projects', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) });
    inp.value = '';
    loadProjects();
}

async function loadSchedProfiles() {
    const sel = $('schedProfile');
    if (!sel) return;
    try {
        const resp = await fetch('/auth-profiles');
        if (!resp.ok) return;
        const profiles = await resp.json();
        const cur = sel.value;
        clear(sel);
        sel.appendChild(el('option', { value: '', text: '— без авторизации —' }));
        for (const p of profiles) sel.appendChild(el('option', { value: String(p.id), text: p.name }));
        sel.value = cur;
    } catch (e) { /* ignore */ }
}

async function loadSchedules() {
    if (isGuest) return;
    const list = $('schedulesList');
    if (!list) return;
    try {
        const resp = await fetch('/schedules');
        if (!resp.ok) return;
        const schedules = await resp.json();
        clear(list);
        if (!schedules.length) { list.appendChild(el('div', { className: 'empty-history', text: 'Расписаний нет' })); return; }
        for (const s of schedules) {
            const last = s.last_run ? new Date(s.last_run * 1000).toISOString().slice(0, 16).replace('T', ' ') : '—';
            list.appendChild(el('div', { className: 'check-item' }, [
                el('span', { className: 'name', text: s.target_url + ' · ' + s.mode + ' · каждые ' + s.interval + ' мин · ' + (s.enabled ? 'вкл' : 'выкл') + ' · посл: ' + last }),
                el('button', { className: 'mini-btn', text: 'УДАЛИТЬ', onclick: async () => { await fetch('/schedules/' + s.id, { method: 'DELETE' }); loadSchedules(); } }),
            ]));
        }
    } catch (e) { /* ignore */ }
}

async function addSchedule() {
    const url = ($('schedUrl').value || '').trim();
    if (!url) { alert('Укажите URL'); return; }
    const body = { target_url: url, mode: $('schedMode').value, interval: parseInt($('schedInterval').value, 10) || 60, profile_id: $('schedProfile').value ? parseInt($('schedProfile').value, 10) : null };
    const resp = await fetch('/schedules', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!resp.ok) { const e = await resp.json().catch(() => ({})); alert('Ошибка: ' + (e.detail || resp.status)); return; }
    loadSchedules();
}

async function loadTrend() {
    if (isGuest) return;
    const sel = $('trendProject');
    const pid = sel && sel.value ? sel.value : '';
    try {
        const resp = await fetch('/history/trend' + (pid ? '?project_id=' + pid : ''));
        if (!resp.ok) return;
        renderTrendChart(await resp.json());
    } catch (e) { /* ignore */ }
}

function renderTrendChart(data) {
    const canvas = $('trendChart');
    const emptyEl = $('trendEmpty');
    if (!canvas) return;
    if (typeof Chart === 'undefined' || !data || data.length < 2) {
        canvas.style.display = 'none';
        if (emptyEl) emptyEl.style.display = 'block';
        if (trendChart) { trendChart.destroy(); trendChart = null; }
        return;
    }
    canvas.style.display = 'block';
    if (emptyEl) emptyEl.style.display = 'none';
    const labels = data.map(d => d.date);
    const mono = 'JetBrains Mono, monospace';
    if (trendChart) trendChart.destroy();
    trendChart = new Chart(canvas, {
        type: 'line',
        data: { labels, datasets: [
            { label: 'ОЦЕНКА', data: data.map(d => d.score), borderColor: '#00bfff', backgroundColor: 'rgba(0,191,255,0.12)', borderWidth: 3, tension: 0.3, pointRadius: 4, yAxisID: 'yScore' },
            { label: 'КРИТИЧНО', data: data.map(d => d.critical), borderColor: '#ff0044', backgroundColor: 'rgba(255,0,68,0.15)', borderWidth: 2, tension: 0.25, pointRadius: 4, yAxisID: 'y' },
        ] },
        options: { responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
            plugins: { legend: { labels: { color: '#00ff41', font: { family: mono, size: 13, weight: '800' } } } },
            scales: {
                x: { ticks: { color: '#7fbf80', font: { family: mono, size: 11 } }, grid: { color: 'rgba(31,95,31,0.4)' } },
                y: { beginAtZero: true, position: 'left', ticks: { color: '#7fbf80', stepSize: 1 }, grid: { color: 'rgba(31,95,31,0.4)' } },
                yScore: { beginAtZero: true, max: 100, position: 'right', ticks: { color: '#00bfff', stepSize: 20 }, grid: { display: false } },
            } },
    });
}

function initPlanningUI() {
    const ap = $('addProjectBtn'); if (ap) ap.addEventListener('click', addProject);
    const as = $('addScheduleBtn'); if (as) as.addEventListener('click', addSchedule);
    const rt = $('refreshTrendBtn'); if (rt) rt.addEventListener('click', loadTrend);
    const tp = $('trendProject'); if (tp) tp.addEventListener('change', loadTrend);
    loadProjects(); loadSchedules(); loadSchedProfiles(); loadTrend();
}

// ---------- Старт при загрузке страницы ----------
window.addEventListener('load', initLoadingScreen);

// ---------- Cleanup ----------
window.addEventListener('beforeunload', closeWebSocket);
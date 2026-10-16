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
        if (btn.dataset.tab === 'history' && !isGuest) loadHistory();
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
function buildAccount(userEl, passEl) {
    if (isGuest) return null;
    const u = (userEl.value || '').trim();
    const p = passEl.value || '';
    if (!u || !p) return null;
    return { username: u, password: p };
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
        const label = el('label', { className: 'check-item' }, [
            cb,
            el('span', { className: 'name', text: c.name }),
            el('span', { className: 'check-level ' + c.level, text: c.level }),
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
    if (typeof data.progress === 'number' && progressBar) progressBar.style.width = (data.progress * 100) + '%';
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
    appendTerminal('[SYS] Инициализация сканирования...');
    progressBar.style.width = '0%';
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

    try {
        const body = { url, mode };
        if (checks_) body.checks = checks_;

        const a1 = buildAccount(acc1User, acc1Pass);
        if (a1) body.account1 = a1;

        const a2 = buildAccount(acc2User, acc2Pass);
        if (a2) body.account2 = a2;

        if (a1) appendTerminal(`[SYS] Аккаунт 1: ${a1.username}`);
        else appendTerminal('[SYS] Аккаунт 1: не задан (анонимно)');
        if (a2) appendTerminal(`[SYS] Аккаунт 2: ${a2.username}`);
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
        statusValue.textContent = 'ОШИБКА';
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
async function loadHistory() {
    if (isGuest) return;
    const container = $('historyList');
    clear(container);
    container.appendChild(el('div', { className: 'empty-history', text: 'Загрузка...' }));

    try {
        const resp = await fetch('/history');
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const scans = await resp.json();
        cachedScans = scans;

        renderHistoryChart(scans);

        clear(container);
        if (!scans.length) {
            container.appendChild(el('div', { className: 'empty-history', text: 'История пуста' }));
            return;
        }
        const table = el('table', { className: 'history-table' });
        const thead = el('thead', null, [
            el('tr', null, [
                el('th', { text: 'ID' }),
                el('th', { text: 'ДАТА' }),
                el('th', { text: 'ЦЕЛЬ' }),
                el('th', { text: 'КРИТ' }),
                el('th', { text: 'ВЫС' }),
                el('th', { text: 'СРЕД' }),
                el('th', { text: 'НИЗК' }),
                el('th', { text: 'ДЕЙСТВИЯ' }),
            ]),
        ]);
        const tbody = el('tbody');
        for (const s of scans) {
            const viewBtn = el('button', {
                className: 'btn-view',
                text: 'ПРОСМОТР',
                onclick: () => window.open(`/history/${s.id}/view`, '_blank'),
            });
            const chartBtn = el('button', {
                className: 'btn-chart',
                text: 'ДИАГРАММА',
                onclick: () => window.open(`/history/${s.id}/chart`, '_blank', 'width=1200,height=800'),
            });
            const bundleBtn = el('button', {
                className: 'btn-bundle',
                text: 'ZIP',
                title: 'Скачать все форматы одним архивом',
                onclick: () => window.location.href = `/history/${s.id}/bundle`,
            });
            const delBtn = el('button', {
                className: 'btn-delete',
                text: 'УДАЛИТЬ',
                onclick: async () => {
                    if (!confirm('Удалить скан #' + s.id + '?')) return;
                    try {
                        const r = await fetch(`/history/${s.id}`, { method: 'DELETE' });
                        if (r.ok) loadHistory();
                        else alert('Ошибка удаления');
                    } catch (e) { alert('Ошибка: ' + e.message); }
                },
            });
            const row = el('tr', null, [
                el('td', { text: String(s.id) }),
                el('td', { text: s.scan_date.replace('T', ' ').slice(0, 19) }),
                el('td', { className: 'url-cell', text: s.target_url, title: s.target_url }),
                el('td', null, [el('span', { className: 'badge badge-crit', text: String(s.critical ?? 0) })]),
                el('td', null, [el('span', { className: 'badge badge-high', text: String(s.high ?? 0) })]),
                el('td', null, [el('span', { className: 'badge badge-med', text: String(s.medium ?? 0) })]),
                el('td', null, [el('span', { className: 'badge badge-low', text: String(s.low ?? 0) })]),
                el('td', { className: 'actions-cell' }, [viewBtn, chartBtn, bundleBtn, delBtn]),
            ]);
            tbody.appendChild(row);
        }
        table.appendChild(thead);
        table.appendChild(tbody);
        container.appendChild(table);
    } catch (e) {
        clear(container);
        container.appendChild(el('div', { className: 'empty-history', text: 'Ошибка: ' + e.message }));
    }
}

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
    } catch (e) {
        alert('Ошибка: ' + e.message);
    }
}

// ---------- Export history ----------
function exportHistory() {
    if (isGuest) return;
    window.location.href = '/history/export.xlsx';
}

// ---------- Wire up ----------
if (!isGuest) {
    scanBtn.addEventListener('click', startScan);
    urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });
    htmlBtn.addEventListener('click', () => exportReport('html'));
    jsonBtn.addEventListener('click', () => exportReport('json'));
    csvBtn.addEventListener('click', () => exportReport('csv'));
    xlsxBtn.addEventListener('click', () => exportReport('xlsx'));
    $('refreshHistoryBtn').addEventListener('click', loadHistory);
    $('clearAllHistoryBtn').addEventListener('click', clearAllHistory);
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

// ---------- Старт при загрузке страницы ----------
window.addEventListener('load', initLoadingScreen);

// ---------- Cleanup ----------
window.addEventListener('beforeunload', closeWebSocket);
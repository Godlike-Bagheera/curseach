'use strict';
/* Панель фильтра истории по датам. Фильтрация выполняется на сервере
   (/history?from=&to=), панель лишь хранит выбор в localStorage и
   запускает перезагрузку списка через window.__curseachHistoryReload. */
(function () {
  const LS = 'curseach.historyRange';
  let state = {};
  try { state = JSON.parse(localStorage.getItem(LS)) || {}; } catch (e) { state = {}; }
  let panel = null, host = null;

  const iso = d => d.toISOString().slice(0, 10);
  const daysAgo = n => { const d = new Date(); d.setDate(d.getDate() - n + 1); return d; };
  const save = () => localStorage.setItem(LS, JSON.stringify(state));
  const reload = () => { if (typeof window.__curseachHistoryReload === 'function') window.__curseachHistoryReload(); };

  function exportHint() {
    const b = document.getElementById('exportHistoryBtn');
    if (!b) return;
    const active = !!(state.from || state.to);
    b.title = active ? 'Экспорт только за выбранный период' : 'Экспорт всей истории';
    b.textContent = active ? 'ЭКСПОРТ ИСТОРИИ (XLSX) · ПЕРИОД' : 'ЭКСПОРТ ИСТОРИИ (XLSX)';
  }

  function setRange(from, to, chip) {
    state = {};
    if (from) state.from = from;
    if (to) state.to = to;
    save();
    panel.querySelectorAll('input[type=date]').forEach(i => { i.value = state[i.dataset.k] || ''; });
    panel.querySelectorAll('.hf-chip').forEach(c => c.classList.toggle('active', c === chip));
    exportHint();
    reload();
  }

  function mount(h) {
    host = h;
    panel = document.createElement('div');
    panel.className = 'hf-panel';
    panel.setAttribute('role', 'group');
    panel.setAttribute('aria-label', 'Фильтр истории по датам');
    panel.innerHTML =
      '<label>С<input type="date" data-k="from" aria-label="Дата начала"></label>' +
      '<label>По<input type="date" data-k="to" aria-label="Дата конца"></label>' +
      '<span class="hf-chips">' +
      '<button type="button" class="hf-chip" data-d="1">Сегодня</button>' +
      '<button type="button" class="hf-chip" data-d="7">7 дней</button>' +
      '<button type="button" class="hf-chip" data-d="30">30 дней</button>' +
      '<button type="button" class="hf-chip" data-d="0">Всё время</button>' +
      '</span><button type="button" class="hf-reset">Сброс</button>' +
      '<span class="hf-count"></span>';
    h.parentNode.insertBefore(panel, h);
    panel.querySelectorAll('input[type=date]').forEach(i => {
      i.value = state[i.dataset.k] || '';
      i.addEventListener('change', () => {
        state[i.dataset.k] = i.value || undefined; save();
        panel.querySelectorAll('.hf-chip').forEach(c => c.classList.remove('active'));
        exportHint(); reload();
      });
    });
    panel.querySelectorAll('.hf-chip').forEach(c => c.addEventListener('click', () => {
      const n = +c.dataset.d;
      setRange(n ? iso(daysAgo(n)) : null, n ? iso(new Date()) : null, c);
    }));
    panel.querySelector('.hf-reset').addEventListener('click', () => setRange(null, null, null));
    exportHint();
  }

  function findHost() {
    const list = document.getElementById('historyList');
    if (list) return list;
    const c = document.querySelectorAll('[id*="history" i], [class*="history" i]');
    for (const el of c) if (el !== document.body && el !== document.documentElement) return el;
    return null;
  }
  function init() {
    const h = findHost();
    if (h) return mount(h);
    const mo = new MutationObserver(() => {
      const hh = findHost();
      if (hh) { mo.disconnect(); mount(hh); }
    });
    mo.observe(document.body, { childList: true, subtree: true });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();

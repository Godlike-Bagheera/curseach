'use strict';
(function () {
  const LS = 'curseach.historyRange';
  let state = {};
  try { state = JSON.parse(localStorage.getItem(LS)) || {}; } catch (e) { state = {}; }
  let total = null, panel = null, empty = null, host = null;

  const iso = d => d.toISOString().slice(0, 10);
  const daysAgo = n => { const d = new Date(); d.setDate(d.getDate() - n + 1); return d; };
  const save = () => localStorage.setItem(LS, JSON.stringify(state));
  const inRange = s => {
    const d = (s || '').slice(0, 10);
    if (!d || (!state.from && !state.to)) return true;
    if (state.from && d < state.from) return false;
    if (state.to && d > state.to) return false;
    return true;
  };

  // 1) фильтруем JSON /history до того, как его отрендерит существующий код
  const origFetch = window.fetch.bind(window);
  window.fetch = async function (input, init) {
    const url = typeof input === 'string' ? input : (input && input.url) || '';
    const resp = await origFetch(input, init);
    if (url.split('?')[0].endsWith('/history')) {
      try {
        const data = await resp.clone().json();
        if (Array.isArray(data)) {
          total = data.length;
          const filtered = data.filter(s => inRange(s.scan_date));
          const h = new Headers(resp.headers); h.delete('content-length');
          count(filtered.length, total);
          return new Response(JSON.stringify(filtered),
            { status: resp.status, statusText: resp.statusText, headers: h });
        }
      } catch (e) { /* не JSON — пропускаем как есть */ }
    }
    return resp;
  };

  function count(shown, tot) {
    const el = panel && panel.querySelector('.hf-count');
    if (el) el.textContent = `Показано ${shown} из ${tot == null ? shown : tot}`;
  }
  function rowDate(row) {
    const m = (row.textContent || '').match(/\d{4}-\d{2}-\d{2}/);
    return m ? m[0] : null;
  }
  function applyToDom() {
    if (!host) return;
    const rows = host.querySelectorAll('tr, li, .history-item, .history-row, [data-scan-id]');
    let shown = 0, seen = 0;
    rows.forEach(r => {
      if (r.querySelector('tr, li')) return;
      const d = rowDate(r);
      if (d === null) return;
      seen++;
      const ok = inRange(d);
      r.style.display = ok ? '' : 'none';
      if (ok) shown++;
    });
    if (seen) count(shown, total == null ? seen : total);
    if (seen && !shown) {
      if (!empty) {
        empty = document.createElement('div');
        empty.className = 'hf-empty';
        empty.textContent = 'За выбранный период проверок нет';
        host.parentNode.insertBefore(empty, host.nextSibling);
      }
    } else if (empty) { empty.remove(); empty = null; }
  }

  function setRange(from, to, chip) {
    state = {};
    if (from) state.from = from;
    if (to) state.to = to;
    save();
    panel.querySelectorAll('input[type=date]').forEach(i => { i.value = state[i.dataset.k] || ''; });
    panel.querySelectorAll('.hf-chip').forEach(c => c.classList.toggle('active', c === chip));
    applyToDom();
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
        applyToDom();
      });
    });
    panel.querySelectorAll('.hf-chip').forEach(c => c.addEventListener('click', () => {
      const n = +c.dataset.d;
      setRange(n ? iso(daysAgo(n)) : null, n ? iso(new Date()) : null, c);
    }));
    panel.querySelector('.hf-reset').addEventListener('click', () => setRange(null, null, null));
    new MutationObserver(() => requestAnimationFrame(applyToDom))
      .observe(h, { childList: true, subtree: true });
    applyToDom();
  }

  function findHost() {
    // Реальный контейнер списка истории в index.html — #historyList (div.history-list):
    // панель встаёт прямо над таблицей, внутри вкладки «История».
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

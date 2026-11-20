'use strict';
/* Поиск по справочнику /vulns: фильтрует и «популярные» карточки, и реестр проверок. */
(function () {
  var q = document.getElementById('vg-q');
  if (!q) return;
  var cards = [].slice.call(document.querySelectorAll('.vg-card, .vr-card'));
  var total = cards.length;
  var countEl = document.getElementById('vg-count');
  var sections = [
    { grid: document.getElementById('vg-grid'), empty: document.getElementById('vg-none') },
    { grid: document.getElementById('vr-grid'), empty: document.getElementById('vr-none') }
  ];
  function apply() {
    var s = q.value.trim().toLowerCase();
    var shown = 0;
    cards.forEach(function (c) {
      var ok = !s || (c.getAttribute('data-search') || '').indexOf(s) !== -1;
      c.style.display = ok ? '' : 'none';
      if (ok) shown++;
    });
    sections.forEach(function (sec) {
      if (!sec.grid || !sec.empty) return;
      var visible = [].some.call(sec.grid.children, function (c) { return c.style.display !== 'none'; });
      sec.empty.style.display = visible ? 'none' : 'block';
    });
    if (countEl) {
      countEl.textContent = s ? ('Найдено ' + shown + ' из ' + total) : ('Всего карточек: ' + total);
    }
  }
  q.addEventListener('input', apply);
  apply();
  var current = null, timer = null;
  function highlight() {
    var id = (location.hash || '').slice(1);
    if (!id) return;
    var el = document.getElementById(id);
    if (!el || !(el.classList.contains('vg-card') || el.classList.contains('vr-card'))) return;
    if (current) current.classList.remove('vg-target');
    if (timer) clearTimeout(timer);
    current = el;
    el.classList.add('vg-target');
    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    timer = setTimeout(function () { el.classList.remove('vg-target'); current = null; }, 6000);
  }
  window.addEventListener('hashchange', highlight);
  document.addEventListener('click', function (e) {
    var a = e.target instanceof Element ? e.target.closest('a.vr-link') : null;
    if (a) setTimeout(highlight, 60);
  });
  highlight();
})();

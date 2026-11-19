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
  function highlight() {
    var id = (location.hash || '').slice(1);
    if (!id) return;
    var el = document.getElementById(id);
    if (el && el.classList.contains('vg-card')) {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      el.classList.add('vg-target');
      setTimeout(function () { el.classList.remove('vg-target'); }, 2400);
    }
  }
  window.addEventListener('hashchange', highlight);
  highlight();
})();

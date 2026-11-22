'use strict';
/* Поиск по справочнику /vulns: фильтрует и «популярные» карточки, и реестр проверок. */
(function () {
  var q = document.getElementById('vg-q');
  if (!q) return;
  var cards = [].slice.call(document.querySelectorAll('.vg-card, .vr-card'));
  var total = cards.length;
  var countEl = document.getElementById('vg-count');
  var sections = [
    { grid: document.getElementById('vg-grid'), empty: document.getElementById('vg-none'), cls: 'vg-card' },
    { grid: document.getElementById('vr-grid'), empty: document.getElementById('vr-none'), cls: 'vr-card' }
  ];
  /* Толерантность к раскладке: йцукен ↔ qwerty (опечатки в другой раскладке). */
  var RU2EN = {й:'q',ц:'w',у:'e',к:'r',е:'t',н:'y',г:'u',ш:'i',щ:'o',з:'p',ф:'a',ы:'s',в:'d',а:'f',п:'g',р:'h',о:'j',л:'k',д:'l',ж:';',э:"'",я:'z',ч:'x',с:'c',м:'v',и:'b',т:'n',ь:'m',б:',',ю:'.'};
  var EN2RU = {}; Object.keys(RU2EN).forEach(function (k) { EN2RU[RU2EN[k]] = k; });
  function convert(s, map) { return s.split('').map(function (ch) { return map[ch] || ch; }).join(''); }
  function apply() {
    var s = q.value.trim().toLowerCase();
    var alt = convert(s, /[а-яё]/.test(s) ? RU2EN : EN2RU);
    var shown = 0;
    var shownGuide = 0;
    cards.forEach(function (c) {
      var hay = c.getAttribute('data-search') || '';
      var ok = !s || hay.indexOf(s) !== -1 || (alt !== s && hay.indexOf(alt) !== -1);
      c.style.display = ok ? '' : 'none';
      if (ok) {
        shown++;
        if (c.classList.contains('vg-card')) shownGuide++;
      }
    });
    sections.forEach(function (sec) {
      if (!sec.grid || !sec.empty) return;
      /* Якоря .vg-anchor — не карточки: пустоту раздела считаем только по карточкам. */
      var visible = [].some.call(sec.grid.querySelectorAll('.' + sec.cls), function (c) {
        return c.style.display !== 'none';
      });
      sec.empty.style.display = visible ? 'none' : 'block';
    });
    if (countEl) {
      var parts = shownGuide + ' уязвимостей + ' + (shown - shownGuide) + ' проверок';
      countEl.textContent = (s ? 'Найдено ' + shown + ' из ' + total : 'Карточек: ' + total) + ' · ' + parts;
    }
  }
  q.addEventListener('input', apply);
  apply();
  var current = null, timer = null;
  function highlight() {
    var id = (location.hash || '').slice(1);
    if (!id) return;
    var el = document.getElementById(id);
    /* Якорь отчёта — невидимая метка перед карточкой (их может быть несколько подряд):
       перешагиваем через все метки и подсвечиваем саму карточку. */
    while (el && el.classList.contains('vg-anchor')) el = el.nextElementSibling;
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

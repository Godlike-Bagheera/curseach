'use strict';
/* Общие обработчики кнопок отчётов и документных страниц (about/diff).
   Вынесено из inline onclick ради строгой CSP (script-src без 'unsafe-inline').
   Кнопки несут data-action: navigate | open | print | close и data-url. */
(function () {
  document.addEventListener('click', function (e) {
    var b = e.target.closest ? e.target.closest('[data-action]') : null;
    if (!b) return;
    var a = b.getAttribute('data-action');
    var url = b.getAttribute('data-url');
    if (a === 'navigate' && url) window.location.href = url;
    else if (a === 'open' && url) window.open(url, '_blank');
    else if (a === 'print') window.print();
    else if (a === 'close') window.close();
  });
})();

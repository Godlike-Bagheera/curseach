'use strict';
/* Страница сравнения сканов: печать. Вынесено из inline ради строгой CSP. */
(function () {
  var b = document.getElementById('diffPrint');
  if (b) b.addEventListener('click', function () { window.print(); });
})();

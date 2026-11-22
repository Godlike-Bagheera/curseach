'use strict';
// Интерфейс только на русском: переключатель языка удалён, RU-тексты зашиты в шаблоны.
// Атрибуты data-i18n оставлены как стабильные селекторы для подсказок и тестов.
(function () {
    function apply() {
        document.documentElement.lang = 'ru';
    }
    window.I18N = {
        t: function () { return null; },
        getLang: function () { return 'ru'; },
        setLang: function () { /* только RU */ },
        apply: apply,
    };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', apply);
    else apply();
})();

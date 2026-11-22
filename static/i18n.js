'use strict';
(function () {
    function apply() { document.documentElement.lang = 'ru'; }
    window.I18N = { t: function(key) { return null; }, getLang: function() { return 'ru'; }, setLang: function() {}, apply: apply };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', apply);
    else apply();
})();

'use strict';
// Каркас i18n (RU-first): переключатель EN в шапке, выбор в localStorage.
// data-i18n="key" на элементах; RU — исходный текст, EN — словарь ниже.
(function () {
    const EN = {
        'app.title': 'DEVSECOPS // REST API SCANNER',
        'btn.about': 'ABOUT',
        'btn.vulns': 'VULNERABILITY GUIDE',
        'btn.logout': 'LOG OUT',
        'tab.scanner': '[ SCANNER ]',
        'tab.history': '[ HISTORY ]',
        'tab.planning': '[ OPERATIONS ]',
        'btn.scan': 'RUN',
        'btn.cancel': 'STOP',
        'panel.url': '> TARGET URL',
        'panel.mode': '> SCAN MODE',
        'panel.auth': '> AUTHORIZATION',
        'panel.notify': '> NOTIFICATIONS',
        'panel.project': '> PROJECT (OPTIONAL)',
        'mode.quick': 'QUICK',
        'mode.full': 'FULL',
        'mode.custom': 'CUSTOM',
        'stat.critical': 'CRITICAL',
        'stat.high': 'HIGH',
        'stat.medium': 'MEDIUM',
        'stat.low': 'LOW',
        'stat.score': 'SCORE',
        'stat.status': 'STATUS',
        'btn.html': 'GENERATE REPORT (HTML / PDF)',
        'btn.json': 'EXPORT JSON',
        'btn.csv': 'EXPORT CSV',
        'btn.xlsx': 'EXPORT EXCEL',
    };
    const KEY = 'curseach.lang';

    function getLang() {
        try { return localStorage.getItem(KEY) || 'ru'; } catch (e) { return 'ru'; }
    }
    function setLang(l) {
        try { localStorage.setItem(KEY, l); } catch (e) { /* ignore */ }
    }
    function apply(lang) {
        document.querySelectorAll('[data-i18n]').forEach(function (node) {
            const k = node.getAttribute('data-i18n');
            if (!node.dataset.i18nRu) node.dataset.i18nRu = node.textContent;
            node.textContent = (lang === 'en' && EN[k]) ? EN[k] : node.dataset.i18nRu;
        });
        const t = document.getElementById('langToggle');
        if (t) t.textContent = lang === 'en' ? 'RU' : 'EN';
        document.documentElement.lang = lang;
    }
    function init() {
        apply(getLang());
        const t = document.getElementById('langToggle');
        if (t) t.addEventListener('click', function () {
            const next = getLang() === 'en' ? 'ru' : 'en';
            setLang(next);
            apply(next);
        });
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();

'use strict';
// i18n (RU-first): переключатель EN в шапке, выбор в localStorage.
// data-i18n="key" — текст; data-i18n-placeholder="key" — placeholder input.
// RU — исходный текст, EN — словарь ниже. window.I18N.t(key) — для будущих динамических строк.
(function () {
    const EN = {
        'app.title': 'DEVSECOPS // REST API SCANNER',
        'btn.about': 'ABOUT', 'btn.vulns': 'VULNERABILITY GUIDE', 'btn.logout': 'LOG OUT',
        'tab.scanner': '[ SCANNER ]', 'tab.history': '[ HISTORY ]', 'tab.planning': '[ OPERATIONS ]',
        'btn.scan': 'RUN', 'btn.cancel': 'STOP',
        'panel.url': '> TARGET URL', 'panel.mode': '> SCAN MODE', 'panel.auth': '> AUTHORIZATION',
        'panel.notify': '> NOTIFICATIONS', 'panel.project': '> PROJECT (OPTIONAL)',
        'mode.quick': 'QUICK', 'mode.full': 'FULL', 'mode.custom': 'CUSTOM',
        'stat.critical': 'CRITICAL', 'stat.high': 'HIGH', 'stat.medium': 'MEDIUM', 'stat.low': 'LOW',
        'stat.score': 'SCORE', 'stat.status': 'STATUS',
        'btn.html': 'GENERATE REPORT (HTML / PDF)', 'btn.json': 'EXPORT JSON', 'btn.csv': 'EXPORT CSV', 'btn.xlsx': 'EXPORT EXCEL',
        'auth.acc1': 'ACCOUNT 1 — PRIMARY ("ALICE")', 'auth.acc2': 'ACCOUNT 2 — OTHER ("BOB")',
        'auth.profile': 'PROFILE', 'auth.type': 'AUTH TYPE', 'auth.save': 'SAVE PROFILE',
        'auth.notify': 'After the scan finishes, the scanner sends a short JSON summary to this address (webhook). Optional.',
        'history.dynamics': '> VULNERABILITY DYNAMICS', 'history.list': '> SCAN HISTORY', 'history.target': '> TARGET',
        'planning.projects': '> PROJECTS (MULTI-TARGET)', 'planning.schedules': '> SCHEDULES (REPEAT SCANS)', 'planning.trend': '> HISTORY TREND',
        'login.title': 'DEVSECOPS // LOGIN', 'login.subtitle': 'REST API SCANNER',
        'login.username': 'USERNAME', 'login.password': 'PASSWORD', 'login.submit': 'SIGN IN', 'login.guest': '— view only',
        'vulns.back': '← Back to scanner', 'vulns.title': 'VULNERABILITY GUIDE', 'vulns.help': 'How to read this guide',
        'vulns.h2.popular': '> Popular vulnerabilities',
        'vulns.search': 'Search: name (EN/RU), meaning, CWE/OWASP code or check name…',
    };
    const KEY = 'curseach.lang';
    function getLang() { try { return localStorage.getItem(KEY) || 'ru'; } catch (e) { return 'ru'; } }
    function setLang(l) { try { localStorage.setItem(KEY, l); } catch (e) { /* ignore */ } }
    function t(key) { return (getLang() === 'en' && EN[key]) ? EN[key] : null; }
    function apply(lang) {
        document.querySelectorAll('[data-i18n]').forEach(function (node) {
            const k = node.getAttribute('data-i18n');
            if (!node.dataset.i18nRu) node.dataset.i18nRu = node.textContent;
            node.textContent = (lang === 'en' && EN[k]) ? EN[k] : node.dataset.i18nRu;
        });
        document.querySelectorAll('[data-i18n-placeholder]').forEach(function (node) {
            const k = node.getAttribute('data-i18n-placeholder');
            if (!node.dataset.i18nPhRu) node.dataset.i18nPhRu = node.getAttribute('placeholder') || '';
            node.setAttribute('placeholder', (lang === 'en' && EN[k]) ? EN[k] : node.dataset.i18nPhRu);
        });
        const btn = document.getElementById('langToggle');
        if (btn) btn.textContent = lang === 'en' ? 'RU' : 'EN';
        document.documentElement.lang = lang;
    }
    function init() {
        apply(getLang());
        const btn = document.getElementById('langToggle');
        if (btn) btn.addEventListener('click', function () {
            const next = getLang() === 'en' ? 'ru' : 'en';
            setLang(next); apply(next);
        });
    }
    window.I18N = { t: t, getLang: getLang, setLang: setLang, apply: apply, EN: EN };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();

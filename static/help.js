'use strict';
// «?»-подсказки: простые объяснения каждого пункта главной страницы.
// Цель — чтобы сайтом мог пользоваться человек, который вообще не разбирается в ПК/безопасности.
// Тексты RU/EN; язык берётся из i18n. Тултип: наведение + фокус (клавиатура) + тап (телефон), Esc закрывает.
(function () {
    const CHECKS = {
        check_sqli: { ru: "Проверяет, можно ли через поля ввода (логин, поиск, id) вставить вредоносный SQL-код и залезть в базу данных. Если да — могут украсть или изменить все данные.", en: "Tests whether input fields (login, search, id) let an attacker inject SQL into the database. If so, all data can be stolen or altered." },
        check_xss: { ru: "Проверяет, можно ли внедрить на страницу чужой JavaScript (например, через параметр в ссылке), который выполнится в браузере жертвы и украдёт сессию/данные.", en: "Checks if attacker JavaScript can be injected (e.g. via a URL parameter) and run in a victim's browser, stealing sessions/data." },
        check_hidden_paths: { ru: "Ищет непубличные адреса (/admin, /.env, /backup и т.п.), которые не должны быть доступны снаружи, но открываются.", en: "Looks for non-public paths (/admin, /.env, /backup...) that should not be reachable from outside but are." },
        check_idor: { ru: "Проверяет, отдаёт ли сервис данные по разным ID без проверки прав (например, чужой заказ по номеру). Это доступ к чужим данным.", en: "Checks whether the service returns data for different IDs without permission checks (e.g. another user's order by number)." },
        check_idor_auth: { ru: "Сравнивает ответ с входом и без: если защищённый эндпоинт отдаёт одно и то же анониму — проверка прав не работает.", en: "Compares responses with and without login: if a protected endpoint returns the same to anonymous users, access control is broken." },
        check_cross_user_idor: { ru: "Под двумя аккаунтами проверяет, может ли один пользователь открыть данные другого (чужой заказ/профиль). Требует два аккаунта.", en: "Using two accounts, checks whether one user can open another user's data (order/profile). Requires two accounts." },
        check_bfla: { ru: "Проверяет, может ли обычный пользователь вызывать админские функции без роли админа. Это повышение привилегий.", en: "Checks whether a regular user can call admin functions without the admin role - privilege escalation." },
        check_jwt_none: { ru: "Пробует подделать токен входа (алгоритм none). Если сервис принимает подделку — можно войти кем угодно без пароля.", en: "Tries to forge a login token (alg none). If accepted, anyone can log in as anyone without a password." },
        check_security_headers: { ru: "Проверяет наличие защитных HTTP-заголовков (CSP, HSTS, X-Frame-Options и др.), которые снижают риск атак в браузере.", en: "Checks for protective HTTP headers (CSP, HSTS, X-Frame-Options...) that reduce browser-side attacks." },
        check_sensitive_data: { ru: "Ищет в ответах секреты: пароли, API-ключи, приватные ключи. Они не должны попадать в ответы сервиса.", en: "Looks for secrets in responses: passwords, API keys, private keys. They must not leak from the service." },
        check_cors: { ru: "Проверяет, разрешает ли сервис запросы с любых сайтов (CORS *). Это может позволить чужому сайту читать данные от имени пользователя.", en: "Checks whether the service allows requests from any site (CORS *), letting foreign sites read data as the user." },
        check_rate_limiting: { ru: "Проверяет, есть ли лимит частоты запросов (защита от перебора/флуда). Без лимита возможен брутфорс. Эвристика: реальный лимит может быть на nginx/WAF.", en: "Checks for request-rate limiting (anti-brute-force/flood). Without it, brute force is possible. Heuristic: the real limit may live on nginx/WAF." },
        check_command_injection: { ru: "Проверяет, можно ли через поля ввода выполнить команду на сервере (например, id). Если да — это полный захват сервера.", en: "Checks whether input can run an OS command on the server (e.g. id). If so, full server compromise." },
        check_error_leak: { ru: "Проверяет, показывают ли ошибки сервера внутренние детали (пути, стек вызовов, SQL). Это помогает атакующему.", en: "Checks whether server errors reveal internals (paths, stack traces, SQL), aiding attackers." },
        check_http_only: { ru: "Проверяет, работает ли сервис по HTTP без шифрования (TLS). Трафик можно перехватить. Для localhost риск ниже.", en: "Checks whether the service uses HTTP without TLS encryption; traffic can be intercepted. Lower risk on localhost." },
        check_csrf: { ru: "Проверяет защиту от подделки межсайтовых запросов (CSRF) для cookie-сессий: может ли чужой сайт выполнить действие от имени пользователя.", en: "Checks CSRF protection for cookie sessions: whether a foreign site can perform actions as the user." },
        check_unsafe_methods: { ru: "Проверяет, включены ли опасные HTTP-методы (TRACE, WebDAV/PUT/DELETE и т.п.), которые могут помочь атаке.", en: "Checks whether dangerous HTTP methods (TRACE, WebDAV/PUT/DELETE...) are enabled." },
        check_content_type_validation: { ru: "Проверяет, принимает ли сервис неожиданный тип тела запроса (например, text/plain вместо JSON). Это может обойти проверки.", en: "Checks whether the service accepts unexpected request body types (text/plain instead of JSON), possibly bypassing checks." },
        check_sca: { ru: "Ищет доступные файлы зависимостей (requirements.txt, package.json). Они раскрывают версии библиотек для подбора эксплойтов.", en: "Looks for exposed dependency manifests (requirements.txt, package.json) that reveal library versions for exploit matching." },
        check_captcha: { ru: "Проверяет, блокируются ли повторные неверные попытки входа (капча/лимит). Без защиты возможен перебор пароля.", en: "Checks whether repeated failed logins are blocked (captcha/limit). Without it, password guessing is possible." },
        check_business_logic: { ru: "Проверяет некорректные значения (отрицательные id/цена/количество), которые сервис принимает вместо ошибки. Это логические дыры.", en: "Checks invalid values (negative id/price/quantity) the service accepts instead of rejecting - logic flaws." },
        check_pagination: { ru: "Проверяет, можно ли запросить сразу огромную страницу данных (limit=10000). Это нагрузка и утечка всего списка.", en: "Checks whether a huge page of data can be requested at once (limit=10000) - load and full-list leak." },
        check_tls_version: { ru: "Проверяет версию TLS и срок сертификата. Старый TLS или просроченный сертификат — небезопасное соединение.", en: "Checks TLS version and certificate expiry. Old TLS or an expired cert means an insecure connection." },
        check_mass_assignment: { ru: "Проверяет, можно ли при создании объекта подставить лишние поля (is_admin, role) и получить права. Подтверждается чтением обратно.", en: "Checks whether extra fields (is_admin, role) can be injected when creating an object to gain rights; confirmed by reading back." },
        check_graphql_introspection: { ru: "Проверяет, открыта ли схема GraphQL (интроспекция). Она раскрывает атакующему все поля и запросы.", en: "Checks whether the GraphQL schema (introspection) is exposed, revealing all fields and queries." },
        check_osv_sca: { ru: "Сверяет версии библиотек с базой известных уязвимостей OSV. Находит компоненты с CVE.", en: "Matches library versions against the OSV vulnerability database to find components with CVEs." },
        check_ssrf: { ru: "Проверяет, может ли сервер по нашей ссылке сходить во внутреннюю сеть или метаданные облака (169.254.169.254). Это доступ к внутренностям.", en: "Checks whether the server can be made to request the internal network or cloud metadata (169.254.169.254) - access to internals." },
        check_path_traversal: { ru: "Проверяет, можно ли через параметр файла прочитать системные файлы (/etc/passwd). Это выход за пределы нужной папки.", en: "Checks whether a file parameter can read system files (/etc/passwd) - escaping the intended folder." },
        check_open_redirect: { ru: "Проверяет, можно ли через параметр увести пользователя на чужой сайт (фишинг).", en: "Checks whether a parameter can redirect users to a foreign site (phishing)." },
        check_cookie_flags: { ru: "Проверяет флаги cookie (Secure, HttpOnly, SameSite), защищающие сессию от кражи и подделки.", en: "Checks cookie flags (Secure, HttpOnly, SameSite) that protect the session from theft and forgery." },
        check_stored_xss: { ru: "Проверяет, сохраняется ли внедрённый JavaScript (например, в комментарии) и выполняется ли он у других пользователей.", en: "Checks whether injected JavaScript (e.g. in a comment) is stored and runs for other users." },
        check_jwt_exp: { ru: "Проверяет, принимает ли сервис просроченный токен. Если да — старый токен действует вечно.", en: "Checks whether an expired token is still accepted; if so, old tokens never expire." },
        check_security_txt: { ru: "Проверяет наличие security.txt (контакт для сообщений об уязвимостях). Рекомендуется, но не критично.", en: "Checks for security.txt (a contact for reporting vulnerabilities). Recommended, not critical." },
        check_jwt_weak_secret: { ru: "Подбирает слабый секрет подписи JWT из списка. Если найден — токены можно подделывать.", en: "Cracks a weak JWT signing secret from a wordlist; if found, tokens can be forged." }
    };
    const UI = {
        "panel.url": { ru: "Адрес проверяемого сервиса (API), например http://127.0.0.1:8000. Сюда сканер отправляет запросы. Обычно это адрес вашего приложения.", en: "Address of the service (API) to test, e.g. http://127.0.0.1:8000. The scanner sends requests here - usually your app's address." },
        "panel.project": { ru: "Необязательно. Имя проекта, чтобы объединять сканы одного сервиса в истории и трендах.", en: "Optional. A project name to group scans of one service in history and trends." },
        "panel.mode": { ru: "Набор проверок: БЫСТРЫЙ — основные, ПОЛНЫЙ — все, СВОЙ — выбрать вручную галочками.", en: "Check set: QUICK - core checks, FULL - all, CUSTOM - pick manually." },
        "mode.quick": { ru: "Быстрый режим: только самые важные проверки. Быстрее, подходит для первой оценки.", en: "Quick mode: only the most important checks. Faster, good for a first assessment." },
        "mode.full": { ru: "Полный режим: все проверки. Дольше, но максимально подробно.", en: "Full mode: all checks. Slower but most thorough." },
        "mode.custom": { ru: "Свой режим: отметьте галочками нужные проверки ниже.", en: "Custom mode: tick the checks you want below." },
        "panel.auth": { ru: "Логин/пароль тестируемого сервиса. С ними сканер входит и проверяет, что доступно после входа (утечки, чужие данные, админ-функции). Без них — только то, что открыто без входа.", en: "Login/password of the tested service. With them the scanner logs in and checks what is reachable after login (leaks, other users' data, admin functions). Without - only what is public." },
        "auth.acc1": { ru: "Основной аккаунт («Алиса»). Сканер смотрит на сервис глазами вошедшего пользователя.", en: "Primary account (Alice). The scanner views the service as a logged-in user." },
        "auth.acc2": { ru: "Второй аккаунт («Боб»). Нужен, чтобы проверить, может ли Боб открыть данные Алисы (cross-user IDOR). Без него это сравнение пропускается.", en: "Second account (Bob). Used to check whether Bob can open Alice's data (cross-user IDOR). Without it, that comparison is skipped." },
        "panel.notify": { ru: "Необязательно. Адрес (webhook), куда сканер отправит краткий JSON-результат после завершения.", en: "Optional. A webhook URL where the scanner sends a short JSON result after finishing." },
        "stat.critical": { ru: "Критично: прямая угроза (взлом/утечка всех данных). Требует немедленного исправления.", en: "Critical: direct threat (breach/full data leak). Fix immediately." },
        "stat.high": { ru: "Высокий риск: серьёзная уязвимость, исправить в ближайшее время.", en: "High risk: serious vulnerability, fix soon." },
        "stat.medium": { ru: "Средний риск: заметная проблема, стоит исправить.", en: "Medium risk: notable issue, should be fixed." },
        "stat.low": { ru: "Низкий риск: незначительное замечание/рекомендация.", en: "Low risk: minor note/recommendation." },
        "stat.score": { ru: "Итоговая оценка безопасности 0–100. Чем выше, тем лучше.", en: "Overall security score 0-100. Higher is better." },
        "stat.status": { ru: "Текущее состояние сканирования.", en: "Current scan state." }
    };
    function lang() { return (window.I18N && window.I18N.getLang) ? window.I18N.getLang() : "ru"; }
    function textFor(key) {
        const i = key.indexOf(":");
        const kind = key.slice(0, i), id = key.slice(i + 1);
        const rec = kind === "check" ? CHECKS[id] : UI[id];
        if (!rec) return "";
        return (lang() === "en" && rec.en) ? rec.en : rec.ru;
    }
    let tip = null, pinned = null;
    function ensureTip() {
        if (!tip) {
            tip = document.createElement("div");
            tip.className = "help-tip"; tip.id = "helpTip";
            tip.setAttribute("role", "tooltip");
            document.body.appendChild(tip);
        }
        return tip;
    }
    function show(btn) {
        const txt = textFor(btn.dataset.help || "");
        if (!txt) return;
        const t = ensureTip();
        t.textContent = txt; t.classList.add("show");
        const r = btn.getBoundingClientRect();
        const tw = t.offsetWidth, th = t.offsetHeight;
        const left = Math.min(Math.max(8, r.left), Math.max(8, window.innerWidth - tw - 8));
        let top = r.bottom + 8;
        if (top + th > window.innerHeight - 8) top = Math.max(8, r.top - th - 8);
        t.style.left = left + "px"; t.style.top = top + "px";
        btn.setAttribute("aria-describedby", "helpTip");
    }
    function hide() {
        if (tip) tip.classList.remove("show");
        if (pinned) { pinned.removeAttribute("aria-describedby"); pinned = null; }
    }
    function makeBtn(key) {
        const b = document.createElement("button");
        b.type = "button"; b.className = "help-q"; b.dataset.help = key;
        b.setAttribute("aria-label", "Что это?"); b.textContent = "?";
        return b;
    }
    function attach(node, key) {
        if (!node || node.dataset.helpDone) return;
        node.dataset.helpDone = "1";
        const b = makeBtn(key);
        if (node.hasAttribute("data-i18n")) {
            const w = document.createElement("span");
            w.className = "help-row";
            node.parentNode.insertBefore(w, node);
            w.appendChild(node); w.appendChild(b);
        } else {
            node.appendChild(b);
        }
    }
    const MAP = [
        ['.panel-label[data-i18n="panel.url"]', "ui:panel.url"],
        ['.panel-label[data-i18n="panel.project"]', "ui:panel.project"],
        ['.panel-label[data-i18n="panel.mode"]', "ui:panel.mode"],
        ['.panel-label[data-i18n="panel.auth"]', "ui:panel.auth"],
        ['.panel-label[data-i18n="panel.notify"]', "ui:panel.notify"],
        ['.mode-item[data-mode="quick"]', "ui:mode.quick"],
        ['.mode-item[data-mode="full"]', "ui:mode.full"],
        ['.mode-item[data-mode="custom"]', "ui:mode.custom"],
        ['.auth-section-title[data-i18n="auth.acc1"]', "ui:auth.acc1"],
        ['.auth-section-title[data-i18n="auth.acc2"]', "ui:auth.acc2"],
        ['.stat-label[data-i18n="stat.critical"]', "ui:stat.critical"],
        ['.stat-label[data-i18n="stat.high"]', "ui:stat.high"],
        ['.stat-label[data-i18n="stat.medium"]', "ui:stat.medium"],
        ['.stat-label[data-i18n="stat.low"]', "ui:stat.low"],
        ['.stat-label[data-i18n="stat.score"]', "ui:stat.score"],
        ['.stat-label[data-i18n="stat.status"]', "ui:stat.status"]
    ];
    function init() { MAP.forEach(function (pair) { document.querySelectorAll(pair[0]).forEach(function (n) { attach(n, pair[1]); }); }); }
    document.addEventListener("mouseover", function (e) { const b = e.target.closest(".help-q"); if (b && !pinned) show(b); });
    document.addEventListener("mouseout", function (e) { const b = e.target.closest(".help-q"); if (b && !pinned) hide(); });
    document.addEventListener("focusin", function (e) { const b = e.target.closest(".help-q"); if (b) show(b); });
    document.addEventListener("focusout", function (e) { const b = e.target.closest(".help-q"); if (b && !pinned) hide(); });
    document.addEventListener("click", function (e) {
        const b = e.target.closest(".help-q");
        if (b) { e.preventDefault(); e.stopPropagation(); if (pinned === b) { hide(); } else { hide(); pinned = b; show(b); } return; }
        if (pinned && !e.target.closest(".help-tip")) hide();
    }, true);
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") hide(); });
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
    window.HELP = { checks: CHECKS, ui: UI, textFor: textFor };
})();

'use strict';
// «?»-подсказки: простые объяснения каждого пункта главной страницы.
// Цель — чтобы сайтом мог пользоваться человек, который вообще не разбирается в ПК/безопасности.
// Тексты RU/EN; язык берётся из i18n. Тултип: наведение + фокус (клавиатура) + тап (телефон), Esc закрывает.
(function () {
    const CHECKS = {
        check_sqli: { ru: "Проверяет, можно ли через поля ввода (логин, поиск, id) вставить вредоносный SQL-код и залезть в базу данных. Если да — могут украсть или изменить все данные." },
        check_xss: { ru: "Проверяет, можно ли внедрить на страницу чужой JavaScript (например, через параметр в ссылке), который выполнится в браузере жертвы и украдёт сессию/данные." },
        check_hidden_paths: { ru: "Ищет непубличные адреса (/admin, /.env, /backup и т.п.), которые не должны быть доступны снаружи, но открываются." },
        check_idor: { ru: "Проверяет, отдаёт ли сервис данные по разным ID без проверки прав (например, чужой заказ по номеру). Это доступ к чужим данным." },
        check_idor_auth: { ru: "Сравнивает ответ с входом и без: если защищённый эндпоинт отдаёт одно и то же анониму — проверка прав не работает." },
        check_cross_user_idor: { ru: "Под двумя аккаунтами проверяет, может ли один пользователь открыть данные другого (чужой заказ/профиль). Требует два аккаунта." },
        check_bfla: { ru: "Проверяет, может ли обычный пользователь вызывать админские функции без роли админа. Это повышение привилегий." },
        check_jwt_none: { ru: "Пробует подделать токен входа (алгоритм none). Если сервис принимает подделку — можно войти кем угодно без пароля." },
        check_security_headers: { ru: "Проверяет наличие защитных HTTP-заголовков (CSP, HSTS, X-Frame-Options и др.), которые снижают риск атак в браузере." },
        check_sensitive_data: { ru: "Ищет в ответах секреты: пароли, API-ключи, приватные ключи. Они не должны попадать в ответы сервиса." },
        check_cors: { ru: "Проверяет, разрешает ли сервис запросы с любых сайтов (CORS *). Это может позволить чужому сайту читать данные от имени пользователя." },
        check_rate_limiting: { ru: "Проверяет, есть ли лимит частоты запросов (защита от перебора/флуда). Без лимита возможен брутфорс. Эвристика: реальный лимит может быть на nginx/WAF." },
        check_command_injection: { ru: "Проверяет, можно ли через поля ввода выполнить команду на сервере (например, id). Если да — это полный захват сервера." },
        check_error_leak: { ru: "Проверяет, показывают ли ошибки сервера внутренние детали (пути, стек вызовов, SQL). Это помогает атакующему." },
        check_http_only: { ru: "Проверяет, работает ли сервис по HTTP без шифрования (TLS). Трафик можно перехватить. Для localhost риск ниже." },
        check_csrf: { ru: "Проверяет защиту от подделки межсайтовых запросов (CSRF) для cookie-сессий: может ли чужой сайт выполнить действие от имени пользователя." },
        check_unsafe_methods: { ru: "Проверяет, включены ли опасные HTTP-методы (TRACE, WebDAV/PUT/DELETE и т.п.), которые могут помочь атаке." },
        check_content_type_validation: { ru: "Проверяет, принимает ли сервис неожиданный тип тела запроса (например, text/plain вместо JSON). Это может обойти проверки." },
        check_sca: { ru: "Ищет доступные файлы зависимостей (requirements.txt, package.json). Они раскрывают версии библиотек для подбора эксплойтов." },
        check_captcha: { ru: "Проверяет, блокируются ли повторные неверные попытки входа (капча/лимит). Без защиты возможен перебор пароля." },
        check_business_logic: { ru: "Проверяет некорректные значения (отрицательные id/цена/количество), которые сервис принимает вместо ошибки. Это логические дыры." },
        check_pagination: { ru: "Проверяет, можно ли запросить сразу огромную страницу данных (limit=10000). Это нагрузка и утечка всего списка." },
        check_tls_version: { ru: "Проверяет версию TLS и срок сертификата. Старый TLS или просроченный сертификат — небезопасное соединение." },
        check_mass_assignment: { ru: "Проверяет, можно ли при создании объекта подставить лишние поля (is_admin, role) и получить права. Подтверждается чтением обратно." },
        check_graphql_introspection: { ru: "Проверяет, открыта ли схема GraphQL (интроспекция). Она раскрывает атакующему все поля и запросы." },
        check_osv_sca: { ru: "Сверяет версии библиотек с базой известных уязвимостей OSV. Находит компоненты с CVE." },
        check_ssrf: { ru: "Проверяет, может ли сервер по нашей ссылке сходить во внутреннюю сеть или метаданные облака (169.254.169.254). Это доступ к внутренностям." },
        check_path_traversal: { ru: "Проверяет, можно ли через параметр файла прочитать системные файлы (/etc/passwd). Это выход за пределы нужной папки." },
        check_open_redirect: { ru: "Проверяет, можно ли через параметр увести пользователя на чужой сайт (фишинг)." },
        check_cookie_flags: { ru: "Проверяет флаги cookie (Secure, HttpOnly, SameSite), защищающие сессию от кражи и подделки." },
        check_stored_xss: { ru: "Проверяет, сохраняется ли внедрённый JavaScript (например, в комментарии) и выполняется ли он у других пользователей." },
        check_jwt_exp: { ru: "Проверяет, принимает ли сервис просроченный токен. Если да — старый токен действует вечно." },
        check_security_txt: { ru: "Проверяет наличие security.txt (контакт для сообщений об уязвимостях). Рекомендуется, но не критично." },
        check_jwt_weak_secret: { ru: "Подбирает слабый секрет подписи JWT из списка. Если найден — токены можно подделывать." }
    };
    const UI = {
        "panel.url": { ru: "Адрес проверяемого сервиса (API), например http://127.0.0.1:8000. Сюда сканер отправляет запросы. Обычно это адрес вашего приложения." },
        "panel.project": { ru: "Необязательно. Имя проекта, чтобы объединять сканы одного сервиса в истории и трендах." },
        "panel.mode": { ru: "Набор проверок: БЫСТРЫЙ — основные, ПОЛНЫЙ — все, СВОЙ — выбрать вручную галочками." },
        "mode.quick": { ru: "Быстрый режим: только самые важные проверки. Быстрее, подходит для первой оценки." },
        "mode.full": { ru: "Полный режим: все проверки. Дольше, но максимально подробно." },
        "mode.custom": { ru: "Свой режим: отметьте галочками нужные проверки ниже." },
        "panel.auth": { ru: "Логин/пароль тестируемого сервиса. С ними сканер входит и проверяет, что доступно после входа (утечки, чужие данные, админ-функции). Без них — только то, что открыто без входа." },
        "auth.acc1": { ru: "Основной аккаунт («Алиса»). Сканер смотрит на сервис глазами вошедшего пользователя." },
        "auth.acc2": { ru: "Второй аккаунт («Боб»). Нужен, чтобы проверить, может ли Боб открыть данные Алисы (cross-user IDOR). Без него это сравнение пропускается." },
        "panel.notify": { ru: "Необязательно. Адрес (webhook), куда сканер отправит краткий JSON-результат после завершения." },
        "stat.critical": { ru: "Критично: прямая угроза (взлом/утечка всех данных). Требует немедленного исправления." },
        "stat.high": { ru: "Высокий риск: серьёзная уязвимость, исправить в ближайшее время." },
        "stat.medium": { ru: "Средний риск: заметная проблема, стоит исправить." },
        "stat.low": { ru: "Низкий риск: незначительное замечание/рекомендация." },
        "stat.score": { ru: "Итоговая оценка безопасности 0–100. Чем выше, тем лучше." },
        "stat.status": { ru: "Текущее состояние сканирования." }
    };
    function lang() { return (window.I18N && window.I18N.getLang) ? window.I18N.getLang() : "ru"; }
    function textFor(key) {
        const i = key.indexOf(":");
        const kind = key.slice(0, i), id = key.slice(i + 1);
        const rec = kind === "check" ? CHECKS[id] : UI[id];
        if (!rec) return "";
        return rec.ru;
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
        if (node.classList.contains("panel-label")) w.classList.add("help-row--panel");
        node.parentNode.insertBefore(w, node);
        w.appendChild(node); w.appendChild(b);
    }
        } else {
            node.appendChild(b);
        }
    }
    const MAP = [
        ['.panel-label[data-i18n="panel.url"]', "ui:panel.url"],
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

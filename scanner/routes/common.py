"""Общие зависимости для роутеров (JinjaTemplates инжектится из scanner.app)."""

from fastapi.templating import Jinja2Templates

templates: Jinja2Templates = None  # type: ignore[assignment]


def init_templates(tmpl: Jinja2Templates) -> None:
    global templates
    templates = tmpl
    # Синхронизируем модуль reporting (рендер вне контекста запроса: ZIP)
    from .. import reporting
    reporting.init_templates(tmpl)

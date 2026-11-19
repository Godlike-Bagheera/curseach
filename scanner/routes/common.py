"""Общие зависимости для роутеров (JinjaTemplates инжектится из scanner.app)."""

from fastapi.templating import Jinja2Templates


class NonceTemplates(Jinja2Templates):
    """Jinja2Templates с авто-инжектом CSP-nonce в контекст каждого TemplateResponse."""

    def TemplateResponse(self, request, name, context=None, *args, **kwargs):
        ctx = dict(context or {})
        ctx.setdefault("csp_nonce", getattr(getattr(request, "state", None), "csp_nonce", ""))
        return super().TemplateResponse(request, name, ctx, *args, **kwargs)


templates: Jinja2Templates = None  # type: ignore[assignment]


def init_templates(tmpl: Jinja2Templates) -> None:
    global templates
    templates = tmpl
    # Синхронизируем модуль reporting (рендер вне контекста запроса: ZIP)
    from .. import reporting

    reporting.init_templates(tmpl)

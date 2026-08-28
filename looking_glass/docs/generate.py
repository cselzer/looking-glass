"""Build a self-contained HTML manual from the HTTP catalog and Click tree."""

from __future__ import annotations

import html
import os
from typing import Any, Dict, List, Optional

import click

from .catalog import GUI_TOOLS, HTTP_ROUTES
from ..utility import atomic_write, get_data_dir

_CSS = """
:root {
  color-scheme: dark;
  --bg:#0b0d10; --fg:#e8edf2; --muted:#8b98a5; --line:#243040;
  --panel:#141920; --panel-2:#1a212b; --accent:#7eb8ff; --accent-2:#9d8cff;
  --ok:#8ee29a; --bad:#ff8d8d; --warn:#ffd37a; --radius:14px;
}
* { box-sizing: border-box; }
html { background: var(--bg); }
body {
  margin: 0;
  color: var(--fg);
  font: 15px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  display: grid;
  grid-template-columns: 15.5rem 1fr;
  min-height: 100vh;
  background:
    radial-gradient(1200px 600px at 10% -10%, rgb(126 184 255 / 14%), transparent 55%),
    radial-gradient(900px 500px at 110% 0%, rgb(157 140 255 / 12%), transparent 50%),
    var(--bg);
}
body, pre, code, kbd { font-variant-ligatures: none; }
a { color: var(--accent); }
nav {
  position: sticky; top: 0; height: 100vh; overflow: auto;
  padding: 1.15rem 1rem 4.5rem;
  border-right: 1px solid var(--line);
  background: color-mix(in oklab, var(--panel) 88%, transparent);
}
nav a { display: block; color: var(--muted); text-decoration: none; font-size: 0.82rem; padding: 0.18rem 0; }
nav a:hover { color: var(--accent); }
nav .brand {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-weight: 650; letter-spacing: -0.03em; color: var(--fg); font-size: 1.05rem;
  margin: 0 0 0.35rem; text-decoration: none;
}
nav .nav-exit { color: var(--accent); margin-bottom: 1rem; font-size: 0.82rem; }
nav .nav-h {
  color: var(--fg); font-weight: 650; margin: 0.95rem 0 0.25rem;
  font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.12em;
}
main { padding: 2rem 1.75rem 5.5rem; max-width: 54rem; min-width: 0; }
.lede { color: var(--muted); max-width: 42rem; }
h1 {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  letter-spacing: -0.03em; font-size: 1.7rem; margin: 0 0 0.65rem;
}
h2 { margin-top: 2.4rem; font-size: 1.15rem; }
h3 { font-size: 0.95rem; margin: 0 0 0.4rem; }
.muted { color: var(--muted); }
code, pre, kbd { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
code:not(pre code) {
  font-size: 0.88em;
  background: rgb(255 255 255 / 4%);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 0.05em 0.35em;
}
.card {
  border: 1px solid var(--line);
  background: color-mix(in oklab, var(--panel) 92%, transparent);
  border-radius: var(--radius);
  padding: 1rem 1.1rem;
  margin: 0.85rem 0;
  box-shadow: 0 18px 50px rgb(0 0 0 / 18%);
}
.card:hover { border-color: color-mix(in oklab, var(--accent) 28%, var(--line)); }
.verb {
  display: inline-block;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  padding: 0.18rem 0.45rem;
  border-radius: 999px;
  margin-right: 0.45rem;
  vertical-align: 0.08em;
}
.verb.get, .verb.head { color: #071018; background: var(--accent); }
.verb.delete { color: #180808; background: var(--bad); }
.verb.post, .verb.put, .verb.patch { color: #180e00; background: var(--warn); }
.path {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.95rem;
}
dl { margin: 0.65rem 0 0; }
dt { color: var(--muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.1em; }
dd { margin: 0 0 0.55rem; }
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th, td { text-align: left; padding: 0.45rem 0.55rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 650; }
.group-h { margin: 1.4rem 0 0.4rem; color: var(--muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.12em; }
.status-bar {
  position: fixed; bottom: 0; left: 0; right: 0; z-index: 10000;
  display: grid; grid-template-columns: 1fr auto 1fr; align-items: center;
  gap: 0.35rem 0.65rem; padding: 0.4rem 1.25rem;
  border-top: 1px solid var(--line);
  background: color-mix(in oklab, var(--panel) 92%, var(--bg));
  color: var(--muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.78rem;
}
.status-start {
  justify-self: start;
  display: inline-flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.45rem 0.55rem;
  min-width: 0;
}
.status-start button, .status-end button {
  appearance: none; border: 0; background: transparent;
  color: var(--accent); cursor: pointer; font: inherit; padding: 0;
}
.status-start button:hover, .status-end button:hover { color: var(--fg); }
.status-start [hidden], .status-end [hidden] { display: none !important; }
.status-wins {
  position: absolute; left: 1.25rem; right: 1.25rem; bottom: 100%;
  display: flex; flex-wrap: nowrap; align-items: flex-end; gap: 0.4rem;
  pointer-events: none; min-width: 0;
}
.status-wins:empty { display: none; }
.status-win-stack { pointer-events: auto; position: relative; flex: 0 1 auto; min-width: 0; }
.status-win {
  display: flex; align-items: center; gap: 0.05rem; width: 100%; max-width: 16rem;
  border: 1px solid var(--line); border-bottom: 0; border-radius: 8px 8px 0 0;
  background: var(--panel); color: var(--muted); font: inherit; font-size: 0.75rem;
  padding: 0.12rem 0.2rem 0.16rem 0.4rem; box-shadow: 0 -8px 18px rgb(0 0 0 / 16%);
}
.status-win-title {
  appearance: none; flex: 1 1 auto; min-width: 0; overflow: hidden; text-overflow: ellipsis;
  white-space: nowrap; border: 0; background: transparent; color: inherit; cursor: pointer;
  font: inherit; text-align: left; padding: 0.12rem 0.25rem;
}
.status-win-max, .status-win-close {
  appearance: none; flex: 0 0 auto; border: 0; background: transparent; color: var(--muted);
  cursor: pointer; font: 0.82rem/1 ui-sans-serif, system-ui, sans-serif; padding: 0.12rem 0.28rem;
}
.status-win:hover,
.status-win-stack:hover > .status-win-face,
.status-win-stack:focus-within > .status-win-face { color: var(--fg); }
.status-win-max:hover, .status-win-close:hover { color: var(--fg); }
.status-win-stack.is-many > .status-win-face {
  box-shadow:
    3px -3px 0 0 var(--panel), 3px -3px 0 1px var(--line),
    6px -6px 0 0 var(--panel), 6px -6px 0 1px var(--line),
    0 -8px 18px rgb(0 0 0 / 16%);
}
.status-win-menu {
  display: none; position: absolute; left: 0; bottom: calc(100% - 1px);
  min-width: 100%; flex-direction: column; gap: 0.2rem; padding: 0 0 0.3rem; z-index: 1;
}
.status-win-stack:hover .status-win-menu,
.status-win-stack:focus-within .status-win-menu { display: flex; }
.status-win-menu .status-win {
  border-radius: 8px; border-bottom: 1px solid var(--line); box-shadow: none; max-width: 16rem;
}
.status-cluster {
  display: flex; flex-wrap: wrap; align-items: center; justify-content: center; gap: 0.35rem 0.65rem;
}
.status-end {
  justify-self: end;
  display: inline-flex;
  align-items: center;
  gap: 0.75rem;
}
.status-docs { color: var(--accent); text-decoration: none; }
.status-docs:hover { color: var(--fg); }
.status-locale { color: var(--fg); letter-spacing: 0.04em; }
.status-sep { opacity: 0.55; }
.status-id { display: inline-flex; flex-wrap: wrap; gap: 0.45rem; color: var(--fg); }
#status-ip { color: var(--muted); }
#status-time { font-variant-numeric: tabular-nums; }
.asn-pop {
  position: absolute; z-index: 80; min-width: 22rem;
  width: min(36rem, calc(100vw - 1.5rem)); height: min(70vh, 36rem);
  overflow: hidden; padding: 0; border-radius: 12px;
  border: 1px solid var(--line); background: var(--panel);
  box-shadow: 0 18px 50px rgb(0 0 0 / 18%);
  display: flex; flex-direction: column; font-size: 0.85rem;
}
.inspect-pop { resize: both; overflow: hidden; min-width: 18rem; min-height: 12rem; max-height: none; }
.asn-pop.loading { color: var(--muted); }
.inspect-pop-bar {
  display: flex; align-items: center; justify-content: space-between; gap: 0.5rem;
  cursor: grab; user-select: none; flex: 0 0 auto; padding: 0.45rem 0.75rem;
  border-bottom: 1px solid var(--line);
  background: color-mix(in oklab, var(--panel-2) 92%, transparent);
}
.inspect-pop-bar:active { cursor: grabbing; }
.inspect-pop-title {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.82rem; min-width: 0; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.inspect-pop-actions {
  display: inline-flex; align-items: center; gap: 0.1rem; flex: 0 0 auto;
}
.inspect-pop-close, .inspect-pop-min, .inspect-pop-refresh {
  appearance: none; border: 0; background: transparent; color: var(--muted);
  cursor: pointer; font: 1.1rem/1 ui-sans-serif, system-ui, sans-serif; padding: 0 0.15rem;
}
.inspect-pop-close:hover, .inspect-pop-min:hover, .inspect-pop-refresh:hover { color: var(--fg); }
.asn-pop.is-minimized, .inspect-pop.is-minimized { display: none !important; }
.inspect-pop .ghost {
  appearance: none; border: 1px solid var(--line); background: transparent;
  color: var(--fg); border-radius: 999px; padding: 0.2rem 0.55rem;
  cursor: pointer; font: inherit; font-size: 0.75rem;
}
.inspect-pop-body { overflow: auto; min-height: 0; padding: 0.65rem 1rem 1rem; }
.cache-pop .hint { margin: 0 0 0.65rem; color: var(--muted); font-size: 0.85rem; word-break: break-all; }
.log-pop { width: min(96vw, 110rem); height: min(85vh, 56rem); max-height: none; }
.cache-pop { width: min(42rem, calc(100vw - 1.5rem)); height: min(80vh, 40rem); max-height: none; }
.history-pop { width: min(52rem, calc(100vw - 1.5rem)); height: min(80vh, 42rem); }
.history-pop .hist-search {
  width: 100%; appearance: none; background: var(--panel); color: var(--fg);
  border: 1px solid var(--line); border-radius: 8px; font: inherit; font-size: 0.85rem;
  padding: 0.4rem 0.6rem; margin: 0 0 0.65rem;
}
.history-pop .hist-empty { color: var(--muted); padding: 0.75rem 0.2rem; }
.history-pop .hist-query a, .history-pop td.hist-query { color: var(--accent); }
.history-pop .hist-kind { color: var(--accent); }
.history-pop .hist-who, .history-pop .hist-when { color: var(--muted); }
.history-pop .hist-actions { display: flex; align-items: center; gap: 0.3rem; flex: 0 0 auto; }
.history-pop .hist-link {
  color: var(--accent); text-decoration: none;
  font: 0.75rem/1 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  padding: 0.2rem 0.4rem; border-radius: 8px; border: 1px solid var(--line);
}
.history-pop .hist-info {
  appearance: none; width: 1.5rem; height: 1.5rem; border: 1px solid var(--line);
  background: transparent; color: var(--fg); border-radius: 999px; cursor: pointer;
  font: 0.85rem/1 ui-sans-serif, system-ui, sans-serif; padding: 0;
}
.log-inner { overflow: auto; min-height: 0; }
.log-tabs, .log-filters { display: flex; flex-wrap: wrap; gap: 0.25rem 0.45rem; margin: 0 0 0.65rem; }
.log-tab, .log-filter {
  appearance: none; border: 1px solid var(--line); background: transparent;
  color: var(--muted); cursor: pointer; font: inherit; font-size: 0.75rem;
  padding: 0.2rem 0.5rem; border-radius: 999px;
}
.log-tab.on, .log-filter.on, .log-tab:hover, .log-filter:hover { color: var(--fg); border-color: var(--accent); }
.log-table { width: max-content; min-width: 100%; border-collapse: collapse; font-size: 0.75rem; }
.log-table th, .log-table td { text-align: left; padding: 0.28rem 0.35rem; border-bottom: 1px solid var(--line); vertical-align: top; white-space: nowrap; }
.log-table th { color: var(--muted); font-weight: 650; }
.log-table td.ok { color: var(--ok); }
.log-table td.bad { color: var(--bad); }
.log-intel { display: inline-flex; flex-wrap: wrap; align-items: center; gap: 0.3rem 0.45rem; }
.log-table img.looking-glass-flag { height: 1.05em; width: auto; max-height: 1.2em; max-width: 1.8em; vertical-align: -0.15em; border-radius: 2px; }
.log-table a { color: var(--accent); text-decoration: none; }
.log-table a:hover { text-decoration: underline; }
.log-chart { margin: 0 0 1rem; }
.log-chart-title { margin: 0 0 0.25rem; font-size: 0.78rem; color: var(--fg); }
.log-chart-svg { width: 100%; height: auto; display: block; color: var(--muted); }
.log-chart-legend { margin: 0.25rem 0 0; color: var(--muted); font-size: 0.72rem; }
.log-swatch { display: inline-block; width: 0.65rem; height: 0.65rem; border-radius: 2px; vertical-align: -0.1rem; margin-right: 0.15rem; }
.log-swatch.ok { background: var(--ok); }
.log-swatch.bad { background: var(--bad); }
.login-layer {
  position: fixed; inset: 0; z-index: 10050; display: grid; place-items: center;
  padding: 1rem; background: color-mix(in oklab, var(--bg) 72%, transparent);
}
.login-layer[hidden] { display: none; }
.login-card {
  width: min(22rem, 100%); display: grid; gap: 0.75rem;
  padding: 1rem 1.1rem 1.1rem; border: 1px solid var(--line);
  border-radius: var(--radius); background: var(--panel);
}
.login-card label { display: grid; gap: 0.25rem; color: var(--muted); font-size: 0.85rem; }
.login-card input {
  font: inherit; color: var(--fg); background: var(--panel-2);
  border: 1px solid var(--line); border-radius: 8px; padding: 0.45rem 0.6rem;
}
.login-card .go {
  appearance: none; border: 0; background: var(--accent); color: #0b0d10;
  border-radius: 8px; padding: 0.45rem 0.8rem; cursor: pointer; font: inherit; font-weight: 600;
}
.login-error { margin: 0; color: var(--bad); font-size: 0.85rem; }
.login-error[hidden] { display: none; }
@media (max-width: 720px) {
  body { grid-template-columns: 1fr; }
  nav { position: static; height: auto; }
}
"""

_STATUS_OPEN = "<!--looking-glass-status-bar-->"
_STATUS_CLOSE = "<!--/looking-glass-status-bar-->"


def default_docs_path() -> str:
    return os.path.join(get_data_dir(), "docs.html")


def write_docs(path: Optional[str] = None) -> str:
    dest = os.path.abspath(path or default_docs_path())
    parent = os.path.dirname(dest)
    if parent:
        os.makedirs(parent, exist_ok=True)
    atomic_write(dest, generate_docs_html())
    return dest


def ensure_docs_on_serve() -> Optional[str]:
    """Rebuild docs.html on HTTP start when docs.enabled, even if the file exists."""
    from ..config import docs_enabled

    if not docs_enabled():
        return None
    try:
        return write_docs()
    except OSError:
        return None


def generate_docs_html() -> str:
    from ..cli.entry import cli
    from ..i18n import active_locale, overlay_click, t

    overlay_click(cli)
    commands = _walk_click(cli, ["looking-glass"])
    locale = html.escape(active_locale())
    parts: List[str] = [
        "<!DOCTYPE html>",
        f'<html lang="{locale}">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{html.escape(t('docs.title'))}</title>",
        f"<style>{_gui_css()}\n{_CSS}</style>",
        f'<script src="/i18n/{locale}.js"></script>',
        "<script>",
        "window.t = function (id, vars) { var text = (window.__i18n && window.__i18n[id]) || id; if (vars) { Object.keys(vars).forEach(function (key) { text = String(text).split('{' + key + '}').join(String(vars[key])); }); } return text; };",
        "</script>",
        "</head>",
        '<body class="docs-page">',
        "<nav>",
        '<a class="brand" href="/">looking-glass</a>',
        f'<a class="nav-exit" href="/">{html.escape(t("status.exit"))}</a>',
        f'<p class="nav-h">{html.escape(t("docs.on_this_page"))}</p>',
        f'<a href="#http">{html.escape(t("docs.nav_http"))}</a>',
        f'<a href="#cli">{html.escape(t("docs.nav_cli"))}</a>',
        f'<a href="#gui">{html.escape(t("docs.nav_gui"))}</a>',
        f'<p class="nav-h">{html.escape(t("docs.col.http"))}</p>',
    ]
    for route in HTTP_ROUTES:
        parts.append(
            f'<a href="#http-{html.escape(route["id"])}">{html.escape(route["path"])}</a>'
        )
    parts.append(f'<p class="nav-h">{html.escape(t("docs.col.cli"))}</p>')
    for row in commands:
        parts.append(
            f'<a href="#cli-{html.escape(row["anchor"])}">{html.escape(row["label"])}</a>'
        )
    parts.extend(
        [
            "</nav>",
            "<main>",
            f"<h1>{html.escape(t('docs.title'))}</h1>",
            f'<p class="lede">{t("docs.lede", cmd="<code>looking-glass docs</code>")}</p>',
            f'<p class="lede">{html.escape(t("docs.open_lookup"))}</p>',
            f'<h2 id="http">{html.escape(t("docs.nav_http"))}</h2>',
            f"<p>{html.escape(t('docs.http_intro'))}</p>",
        ]
    )
    for route in HTTP_ROUTES:
        parts.append(_http_card(route))
    parts.append(f'<h2 id="cli">{html.escape(t("docs.nav_cli"))}</h2>')
    parts.append(f"<p>{html.escape(t('docs.cli_intro'))}</p>")
    for row in commands:
        parts.append(_cli_card(row))
    parts.append(f'<h2 id="gui">{html.escape(t("docs.nav_gui"))}</h2>')
    parts.append(f"<p>{html.escape(t('docs.gui_intro'))}</p>")
    groups: Dict[str, List[Dict[str, str]]] = {}
    for tool in GUI_TOOLS:
        groups.setdefault(tool["group"], []).append(tool)
    group_ids = {
        "Look up": "gui.group.lookup",
        "DNS": "gui.group.dns",
        "Web": "gui.group.web",
        "Mail": "gui.group.mail",
        "Path": "gui.group.path",
    }
    for group, tools in groups.items():
        heading = t(group_ids.get(group, group))
        if heading == group_ids.get(group, group):
            heading = group
        parts.append(f'<p class="group-h">{html.escape(heading)}</p>')
        parts.append(
            '<div class="card"><table><thead><tr>'
            f"<th>{html.escape(t('docs.col.tab'))}</th>"
            f"<th>{html.escape(t('docs.col.form'))}</th>"
            f"<th>{html.escape(t('docs.col.http'))}</th>"
            f"<th>{html.escape(t('docs.col.cli'))}</th>"
            "</tr></thead><tbody>"
        )
        for tool in tools:
            label = t(f"gui.{tool['id']}.tab")
            if label == f"gui.{tool['id']}.tab":
                label = tool["label"]
            parts.append(
                "<tr>"
                f"<td>{html.escape(label)}</td>"
                f"<td><code>{html.escape(tool['form'])}</code></td>"
                f"<td><code>{html.escape(tool['path'])}</code></td>"
                f"<td><code>{html.escape(tool['cli'])}</code></td>"
                "</tr>"
            )
        parts.extend(["</tbody></table></div>"])
    parts.extend(
        [
            "</main>",
            _STATUS_OPEN,
            _status_bar_html(),
            _STATUS_CLOSE,
            "<script>",
            _gui_js(),
            "</script>",
            "</body>",
            "</html>",
        ]
    )
    return "\n".join(parts)


def _gui_css() -> str:
    from ..http.static_files import read_static

    return read_static("gui.css")


def _gui_js() -> str:
    from ..http.static_files import read_static

    return read_static("gui.js")


def _status_bar_html(user: Optional[str] = None, *, live: bool = False) -> str:
    from ..http.render import environment
    from ..i18n import active_locale, available_locales, t

    if live:
        from ..config import docs_enabled, docs_generated

        enabled = docs_enabled()
        generated = docs_generated()
    else:
        enabled = True
        generated = True
    env = environment()
    env.globals["t"] = t
    env.globals["locale"] = active_locale()
    return env.get_template("_status_bar.html").render(
        locale=active_locale(),
        locales=available_locales(),
        user=user,
        docs_enabled=enabled,
        docs_generated=generated,
    )


def inject_live_status_bar(page: str, user: Optional[str] = None) -> str:
    """Swap the baked-in status bar for one that reflects the current session."""
    live = _STATUS_OPEN + _status_bar_html(user=user, live=True) + _STATUS_CLOSE
    start = page.find(_STATUS_OPEN)
    end = page.rfind(_STATUS_CLOSE)
    if start >= 0 and end > start:
        page = page[:start] + live + page[end + len(_STATUS_CLOSE) :]
    else:
        footer = page.find('<footer class="status-bar"')
        if footer >= 0:
            copy = page.rfind("</body>")
            if copy > footer:
                page = page[:footer] + live + page[copy:]
            else:
                page = page[:footer] + live
        else:
            body_end = page.rfind("</body>")
            if body_end >= 0:
                page = page[:body_end] + live + page[body_end:]
            else:
                page = page + live
    if user and "static/admin.js" not in page:
        from ..http.static_files import static_url

        tag = f'<script src="{static_url("admin.js")}"></script>\n'
        body_end = page.rfind("</body>")
        if body_end >= 0:
            page = page[:body_end] + tag + page[body_end:]
        else:
            page += tag
    return page


def _route_text(route: Dict[str, Any], field: str) -> str:
    from ..i18n import t

    key = f"docs.http.{route['id']}.{field}"
    text = t(key)
    if text == key:
        return str(route.get(field) or "")
    return text


def _http_card(route: Dict[str, Any]) -> str:
    from ..i18n import t

    qs = route.get("query") or []
    qhtml = ", ".join(f"<code>{html.escape(q)}</code>" for q in qs) if qs else "—"
    cli = route.get("cli")
    verb = html.escape(str(route["method"]))
    verb_class = html.escape(str(route["method"]).lower())
    term = ""
    if cli:
        term = (
            '<div class="term">'
            '<div class="term-bar">'
            f'<span class="term-title">{html.escape(str(cli))}</span></div>'
            f"<pre><code>$ {html.escape(str(cli))}</code></pre>"
            "</div>"
        )
    route_line = f"{route['method']} {route['path']}"
    return (
        f'<article class="card" id="http-{html.escape(route["id"])}" '
        f'data-route="{html.escape(route_line)}">'
        f'<h3><span class="verb {verb_class}">{verb}</span> '
        f'<span class="path">{html.escape(route["path"])}</span></h3>'
        f"<p>{html.escape(_route_text(route, 'summary'))}</p>"
        "<dl>"
        f"<div><dt>{html.escape(t('docs.query'))}</dt><dd>{qhtml}</dd></div>"
        f"<div><dt>{html.escape(t('docs.response'))}</dt><dd>{html.escape(_route_text(route, 'accept'))}</dd></div>"
        f"<div><dt>{html.escape(t('docs.notes'))}</dt><dd>{html.escape(_route_text(route, 'notes'))}</dd></div>"
        "</dl>"
        f"{term}"
        "</article>"
    )


def _cli_card(row: Dict[str, Any]) -> str:
    block = row.get("help_block") or row.get("usage") or ""
    prompt = html.escape(row["invoke"])
    summary = html.escape(row.get("summary") or "")
    summary_html = f'<p class="muted">{summary}</p>' if summary else ""
    return (
        f'<article class="card" id="cli-{html.escape(row["anchor"])}">'
        f"<h3>{html.escape(row['label'])}</h3>"
        f"{summary_html}"
        '<div class="term">'
        '<div class="term-bar">'
        f'<span class="term-title">{prompt} --help</span></div>'
        f"<pre><code>$ {prompt} --help\n\n{html.escape(block)}</code></pre>"
        "</div></article>"
    )


def _walk_click(cmd: click.Command, path: List[str], parent_ctx: Optional[click.Context] = None) -> List[Dict[str, Any]]:
    ctx = click.Context(cmd, info_name=path[-1], parent=parent_ctx, color=False)
    rows: List[Dict[str, Any]] = [_click_row(cmd, path, ctx)]
    if not isinstance(cmd, click.Group):
        return rows
    for name in cmd.list_commands(ctx):
        sub = cmd.get_command(ctx, name)
        if sub is None or sub.hidden:
            continue
        rows.extend(_walk_click(sub, path + [name], ctx))
    return rows


def _click_row(cmd: click.Command, path: List[str], ctx: click.Context) -> Dict[str, Any]:
    invoke = " ".join(path)
    label = " ".join(path[1:]) or "looking-glass"
    help_block = cmd.get_help(ctx).strip()
    summary = (cmd.help or cmd.short_help or "").strip().split("\n\n", 1)[0]
    summary = " ".join(summary.split())
    anchor = "-".join(path[1:] if len(path) > 1 else path)
    return {
        "invoke": invoke,
        "label": label,
        "usage": invoke,
        "help_block": help_block,
        "summary": summary,
        "anchor": anchor or "looking-glass",
    }

#!/usr/bin/env python3
"""
Builds the Rare Cyber AI Security Lab site from the Markdown in docs/.

    pip install -r requirements.txt
    python site_builder/build.py          # writes the site to _site/

GitHub Actions runs this on every push to main and publishes _site/ to Pages.
"""
from __future__ import annotations

import html
import posixpath
import re
import shutil
from pathlib import Path

import markdown

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DOCS = REPO / "docs"
OUT = REPO / "_site"
GITHUB = "https://github.com/frankcenedese-lab/rare-cyber-mcp-security-advisory"
SITE = "Rare Cyber AI Security Lab"

# (output file, nav label, source markdown, audience tag)
PAGES = [
    ("lab.html", "Lab Design", "lab.md", "Section 1"),
    ("results.html", "Results", "evidence/index.md", "Section 2"),
    ("azure.html", "Azure and Limitations", "azure.md", "Section 3"),
]
# Pages from version 1.x, redirected so existing links keep working
REDIRECTS = {
    "method.html": "lab.html", "threat-model.html": "lab.html#threat-model",
    "identity.html": "azure.html", "configuration.html": "lab.html#hardening-changes-before-and-after",
    "testing-guide.html": "azure.html", "limitations.html": "azure.html#limitations",
    "executive-summary.html": "index.html",
}
SOURCE_TO_PAGE = {"index.md": "index.html", **{src: out for out, _, src, _ in PAGES}}

TAKEAWAYS: dict[str, list[str]] = {}

FIGURES = {
    "attack": ("dg-attack.svg", "The same indirect prompt injection against the default and the hardened deployment."),
    "stride": ("dg-stride.svg", "Lab architecture with each STRIDE threat placed where it crosses a trust boundary."),
    "decouple": ("dg-decouple.svg", "One shared credential compared with one scoped identity per tool, using the lab's four tools."),
}


def svg(name: str, prefix: str = "") -> str:
    """Inline an SVG, namespacing its ids so several can share one page."""
    s = (HERE / "diagrams" / name).read_text()
    if prefix:
        s = re.sub(r'id="([^"]+)"', lambda m: f'id="{prefix}{m.group(1)}"', s)
        s = re.sub(r'url\(#([^)]+)\)', lambda m: f'url(#{prefix}{m.group(1)})', s)
        s = re.sub(r'href="#([^"]+)"', lambda m: f'href="#{prefix}{m.group(1)}"', s)
    return s


def preprocess(text: str) -> str:
    text = re.sub(r':material-close-circle:\{[^}]*\}', '<span class="st bad"></span>', text)
    text = re.sub(r':material-check-circle:\{[^}]*\}', '<span class="st ok"></span>', text)
    text = re.sub(r':material-[a-z-]+:\s*', '', text)
    return re.sub(r'<!--.*?-->', '', text, flags=re.S)


def fix_links(body: str, src: str) -> str:
    def rep(m: re.Match) -> str:
        href = m.group(1)
        if href.startswith(("http", "#", "mailto:")):
            return m.group(0)
        path, _, anchor = href.partition("#")
        full = posixpath.normpath(posixpath.join(posixpath.dirname(src), path))
        if full in SOURCE_TO_PAGE:
            return f'href="{SOURCE_TO_PAGE[full]}' + (f'#{anchor}' if anchor else '') + '"'
        if full.endswith(".json"):
            return f'href="{full}"'
        return m.group(0)
    return re.sub(r'href="([^"]+)"', rep, body)


def figure(key: str) -> str:
    name, cap = FIGURES[key]
    return f'<div class="figure">{svg(name, prefix=key + "-")}<div class="figcap">{cap}</div></div>'


def render_page(out: str, label: str, src: str, tag: str) -> tuple[str, str, str]:
    md = markdown.Markdown(extensions=["tables", "attr_list", "md_in_html", "admonition", "fenced_code", "toc"])
    body = fix_links(md.convert(preprocess((DOCS / src).read_text())), src)

    h1 = re.search(r'<h1[^>]*>(.*?)</h1>', body, re.S)
    title = re.sub(r'<[^>]+>', '', h1.group(1)) if h1 else label
    body = body.replace(h1.group(0), "", 1) if h1 else body

    meta = [tag] if tag else []
    lead = re.match(r'\s*<p>((?:<strong>[^<]+</strong>[^<]*(?:<br />)?\s*)+)</p>', body)
    if lead:
        for lab, val in re.findall(r'<strong>([^<]+?):?</strong>\s*([^<]*)', lead.group(1)):
            if not any(x in lab for x in ("Author", "Built by", "Last")):
                meta.append(val.strip())
        body = body[lead.end():]
    body = re.sub(r'^\s*<hr />', '', body)

    body = re.sub(r'<div class="figure-slot" data-figure="([a-z]+)"></div>', lambda m: figure(m.group(1)), body)
    if src in TAKEAWAYS:
        items = "".join(f"<li>{x}</li>" for x in TAKEAWAYS[src])
        body = f'<div class="takeaways"><div class="t">Summary</div><ul>{items}</ul></div>' + body

    tokens = md.toc_tokens[0]["children"] if md.toc_tokens and md.toc_tokens[0]["level"] == 1 else md.toc_tokens
    toc = "".join(f'<li><a href="#{t["id"]}">{t["name"]}</a></li>' for t in tokens)
    pills = "".join(f"<span>{x}</span>" for x in meta[:4])
    page = (f'<div class="phead"><div class="phead-in"><div class="crumb">{SITE.replace("Rare Cyber ", "")} / {label}</div>'
            f'<h1>{title}</h1><div class="meta">{pills}</div></div></div>'
            f'<div class="pbody"><article>{body}</article>'
            f'<aside class="toc"><div class="toch">On this page</div><ul>{toc}</ul></aside></div>')
    first = re.search(r'<p>(.*?)</p>', body, flags=re.S)
    desc = TAKEAWAYS[src][0] if src in TAKEAWAYS else (first.group(1) if first else title)
    desc = re.sub(r'<[^>]+>', '', desc)
    desc = desc if len(desc) <= 200 else desc[:197].rsplit(' ', 1)[0] + '...'
    return page, title, desc


def nav(active: str) -> str:
    items = [("index.html", "Overview")] + [(o, l) for o, l, _, _ in PAGES]
    on = ' class="on"'
    return "".join(f'<a href="{o}"{on if o == active else ""}>{l}</a>' for o, l in items)


def main() -> None:
    template = (HERE / "template.html").read_text()
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir()

    def write(name: str, body: str, title: str, desc: str) -> None:
        doc = (template.replace("{{NAV}}", nav(name)).replace("{{BODY}}", body)
               .replace("{{TITLE}}", html.escape(title)).replace("{{DESC}}", html.escape(desc)))
        (OUT / name).write_text(doc)

    home = (HERE / "home.html").read_text().replace("{{ATTACK}}", svg("dg-attack.svg", "hm-"))
    write("index.html", home, "Securing AI Agents with Privileged Tool Access · Technical Report",
          "Least agency in practice: an AI agent's MCP tool access, threat modelled, hardened and tested on AWS, with the Azure differences.")
    for out, label, src, tag in PAGES:
        body, title, desc = render_page(out, label, src, tag)
        write(out, body, f"{label} · {SITE}", desc)

    (OUT / "evidence").mkdir()
    for f in (DOCS / "evidence").rglob("*.json"):
        dest = OUT / "evidence" / f.relative_to(DOCS / "evidence")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, dest)
    for old, new in REDIRECTS.items():
        (OUT / old).write_text(f'<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0; url={new}">'
                               f'<link rel="canonical" href="{new}"><a href="{new}">This page has moved.</a>')
    (OUT / ".nojekyll").write_text("")
    print(f"Built {len(PAGES) + 1} pages to {OUT.relative_to(REPO)}/")


if __name__ == "__main__":
    main()

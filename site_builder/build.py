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
    ("method.html", "Method", "case-study.md", "Section 1"),
    ("threat-model.html", "Threat Model", "threat-model.md", "Section 2"),
    ("configuration.html", "Configuration", "configuration.md", "Section 3"),
    ("testing-guide.html", "Testing", "advisory/testing-guide.md", "Section 4"),
    ("results.html", "Results", "evidence/index.md", "Section 5"),
    ("limitations.html", "Limitations", "limitations.md", "Section 6"),
    ("executive-summary.html", "Executive Summary", "advisory/executive-brief.md", "Appendix"),
]
SOURCE_TO_PAGE = {"index.md": "index.html", **{src: out for out, _, src, _ in PAGES}}

TAKEAWAYS = {
    "case-study.md": [
        "An MCP agent environment was built with default settings, assessed, hardened with TRIAD and re-assessed.",
        "Three controls failed on the default build; all three passed after hardening.",
        "Every control maps to NIST SP 800-53 and has an AWS and a Microsoft implementation.",
    ],
    "threat-model.md": [
        "Ten threats identified across five trust boundaries using STRIDE.",
        "Four are tested, five have defined tests not yet run, and one is open for review.",
        "STRIDE is the backbone; CSA MAESTRO and the OWASP Agentic Top 10 catch what it misses.",
    ],
    "configuration.md": [
        "Six configuration changes produced the TRIAD results, each shown before and after on AWS and Microsoft.",
        "Eight governance policies changed so the configuration can't quietly drift back.",
        "Every change traces to a threat, a test and an ISO/IEC 27001 or 42001 control.",
    ],
    "advisory/testing-guide.md": [
        "The same eight tests run on AWS and Microsoft, with the same pass conditions.",
        "Enforce each tool's role at the gateway before the call reaches the MCP server.",
        "Every test is automated in the lab harness and writes hashed, timestamped evidence.",
    ],
}

FIGURES = {
    "attack": ("dg-attack.svg", "The same indirect prompt injection against an unhardened and a TRIAD hardened deployment."),
    "stride": ("dg-stride.svg", "Lab architecture with each STRIDE threat placed where it crosses a trust boundary."),
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
    return f'<div class="figure">{svg(name, prefix=key[:2] + "-")}<div class="figcap">{cap}</div></div>'


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
    if src == "advisory/testing-guide.md":
        body = re.sub(r'<pre><code[^>]*>AWS HARDENED STACK.*?</code></pre>',
                      f'<div class="figure">{svg("dg-matrix.svg", "mx-")}<div class="figcap">Each TRIAD control has a direct equivalent on both platforms.</div></div>',
                      body, flags=re.S)
    if src in TAKEAWAYS:
        items = "".join(f"<li>{x}</li>" for x in TAKEAWAYS[src])
        body = f'<div class="takeaways"><div class="t">Summary</div><ul>{items}</ul></div>' + body

    tokens = md.toc_tokens[0]["children"] if md.toc_tokens and md.toc_tokens[0]["level"] == 1 else md.toc_tokens
    toc = "".join(f'<li><a href="#{t["id"]}">{re.sub(r"^[TRIAD]: ", "", t["name"])}</a></li>' for t in tokens)
    pills = "".join(f"<span>{x}</span>" for x in meta[:4])
    page = (f'<div class="phead"><div class="phead-in"><div class="crumb">{SITE.replace("Rare Cyber ", "")} / {label}</div>'
            f'<h1>{title}</h1><div class="meta">{pills}</div></div></div>'
            f'<div class="pbody"><article>{body}</article>'
            f'<aside class="toc"><div class="toch">On this page</div><ul>{toc}</ul></aside></div>')
    desc = re.sub(r'<[^>]+>', '', TAKEAWAYS.get(src, [title])[0])
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
          "A threat-modelled lab on AWS and Microsoft: STRIDE analysis, configuration and policy changes, test cases and evidence for AI agents using MCP.")
    for out, label, src, tag in PAGES:
        body, title, desc = render_page(out, label, src, tag)
        write(out, body, f"{label} · {SITE}", desc)

    (OUT / "evidence").mkdir()
    for f in (DOCS / "evidence").rglob("*.json"):
        dest = OUT / "evidence" / f.relative_to(DOCS / "evidence")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, dest)
    (OUT / ".nojekyll").write_text("")
    print(f"Built {len(PAGES) + 1} pages to {OUT.relative_to(REPO)}/")


if __name__ == "__main__":
    main()

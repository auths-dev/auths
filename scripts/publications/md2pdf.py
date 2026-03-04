#!/usr/bin/env python3
"""Convert a Markdown file with Mermaid diagrams to a styled PDF.

Usage:
python md2pdf.py comment.md output.pdf

Requirements:
pip install playwright weasyprint markdown
playwright install chromium

Pipeline:
    1. Extract ```mermaid``` blocks from the markdown
    2. Render each to SVG in a headless Chromium via mermaid.js (CDN)
    3. Replace the mermaid blocks with inline <svg> elements
    4. Convert the resulting markdown to HTML
    5. Wrap in a clean document template with print-optimized CSS
    6. Render to PDF with weasyprint
"""

import re
import sys
from pathlib import Path
from string import Template

import markdown
from playwright.sync_api import sync_playwright
from weasyprint import HTML

MERMAID_CDN = "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"

MERMAID_PAGE = Template("""<!DOCTYPE html>
<html><head><script src="$cdn"></script></head>
<body>
<pre class="mermaid">$code</pre>
<script>
mermaid.initialize({
  startOnLoad: true,
  theme: 'default',
  themeVariables: { fontSize: '14px' },
  flowchart: { useMaxWidth: true, htmlLabels: true, curve: 'basis' }
});
</script>
</body></html>""")


def render_mermaid_blocks(blocks: list[str], out_dir: Path) -> list[str]:
    """Render mermaid code blocks to PNG images via headless Chromium.

    Returns a list of HTML <img> tags pointing to the generated PNGs.
    We screenshot instead of extracting SVG because weasyprint cannot
    render the <foreignObject> elements mermaid uses for labels.
    """
    if not blocks:
        return []

    out_dir.mkdir(parents=True, exist_ok=True)
    results: list[str] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1400, "height": 900})

        for i, code in enumerate(blocks):
            escaped = code.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            html = MERMAID_PAGE.substitute(cdn=MERMAID_CDN, code=escaped)
            page.set_content(html)
            try:
                page.wait_for_selector("body svg", timeout=15_000)
                svg_el = page.query_selector("body svg")
                png_path = out_dir / f"diagram_{i}.png"
                svg_el.screenshot(path=str(png_path), type="png")
                abs_path = png_path.resolve()
                results.append(
                    f'<img src="file://{abs_path}" '
                    f'style="max-width:100%;height:auto;" />'
                )
                print(f"  [{i+1}/{len(blocks)}] rendered OK → {png_path.name}")
            except Exception as exc:
                print(f"  [{i+1}/{len(blocks)}] FAILED: {exc}")
                results.append(f"<pre><code>{code}</code></pre>")

        browser.close()
    return results


def inject_svgs(md_text: str, out_dir: Path) -> str:
    """Replace ```mermaid``` fences with rendered diagram images."""
    pattern = re.compile(r"```mermaid\s*\n(.*?)```", re.DOTALL)
    raw_blocks = [m.group(1).strip() for m in pattern.finditer(md_text)]
    if not raw_blocks:
        return md_text

    print(f"Found {len(raw_blocks)} mermaid diagram(s)")
    img_tags = render_mermaid_blocks(raw_blocks, out_dir)
    it = iter(img_tags)
    return pattern.sub(lambda _: f'<div class="diagram">{next(it)}</div>', md_text)


CSS = """
@page {
  size: letter;
  margin: 0.9in;
  @bottom-center { content: counter(page); font-size: 9pt; color: #666; }
}
body {
  font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
  font-size: 11pt; line-height: 1.55; color: #1a1a1a;
}
h1 {
  font-size: 20pt; font-weight: 700; color: #111;
  border-bottom: 2px solid #2c3e50; padding-bottom: 6pt; margin-bottom: 6pt;
}
h2 { font-size: 15pt; font-weight: 600; color: #2c3e50; margin-top: 22pt; }
h3 { font-size: 12pt; font-weight: 600; color: #34495e; margin-top: 16pt; }
p  { margin: 0 0 10pt 0; text-align: justify; }
ul, ol { margin: 6pt 0; padding-left: 22pt; }
li { margin-bottom: 3pt; }
code {
  font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
  font-size: 9.5pt; background: #f4f4f4; padding: 1pt 4pt; border-radius: 2pt;
}
pre {
  background: #f8f9fa; border: 1px solid #ddd; border-radius: 4pt;
  padding: 10pt; margin: 10pt 0; overflow-x: auto;
}
pre code { background: none; padding: 0; font-size: 9pt; }
hr { border: none; border-top: 1px solid #ddd; margin: 18pt 0; }
a  { color: #2980b9; text-decoration: none; }
em { font-style: italic; }
strong { font-weight: 600; }
.diagram {
  text-align: center; margin: 14pt 0; page-break-inside: avoid;
}
.diagram svg { max-width: 100%; height: auto; }
"""

HTML_TEMPLATE = Template(
    '<!DOCTYPE html><html><head><meta charset="utf-8">'
    "<style>$css</style></head><body>$body</body></html>"
)


def md_to_pdf(src: str, dst: str) -> None:
    src_path = Path(src)
    dst_path = Path(dst)
    diagram_dir = dst_path.parent / ".diagrams"

    md_text = src_path.read_text(encoding="utf-8")
    md_with_imgs = inject_svgs(md_text, diagram_dir)

    print("Converting markdown → HTML")
    html_body = markdown.markdown(
        md_with_imgs,
        extensions=["extra", "codehilite", "toc"],
        output_format="html5",
    )

    full_html = HTML_TEMPLATE.substitute(css=CSS, body=html_body)

    print("Rendering PDF")
    HTML(string=full_html).write_pdf(dst)
    print(f"Done → {dst}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python {Path(sys.argv[0]).name} input.md output.pdf")
        sys.exit(1)
    md_to_pdf(sys.argv[1], sys.argv[2])

#!/usr/bin/env python3
"""Convert the ModelAudit datasheet markdown to a styled one-page PDF."""

import markdown
from weasyprint import HTML

MD_PATH = "docs/modelaudit-datasheet.md"
PDF_PATH = "docs/modelaudit-datasheet.pdf"

CSS = """
@page {
    size: letter;
    margin: 0.4in 0.55in 0.35in 0.55in;
}

body {
    font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
    font-size: 8.4pt;
    line-height: 1.32;
    color: #1a1a1a;
}

h1 {
    font-size: 16pt;
    font-weight: 700;
    color: #111;
    margin: 0 0 0 0;
    padding-bottom: 0;
    border-bottom: none;
}

h1 + p {
    font-size: 8.6pt;
    color: #444;
    margin-top: 0;
    margin-bottom: 3pt;
}

hr {
    border: none;
    border-top: 2.5px solid #2563eb;
    margin: 5pt 0;
}

h2 {
    font-size: 10pt;
    font-weight: 700;
    color: #1e3a5f;
    margin-top: 7pt;
    margin-bottom: 2pt;
    border-bottom: 1px solid #d0d7de;
    padding-bottom: 1pt;
}

p {
    margin: 2pt 0;
}

ul {
    margin: 2pt 0;
    padding-left: 14pt;
}

li {
    margin-bottom: 1pt;
}

strong {
    color: #111;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 3pt 0;
    font-size: 8.2pt;
}

th {
    background-color: #f0f4f8;
    border: 1px solid #d0d7de;
    padding: 3pt 5pt;
    text-align: left;
    font-weight: 600;
    color: #1e3a5f;
}

td {
    border: 1px solid #d0d7de;
    padding: 2.5pt 5pt;
}

tr:nth-child(even) td {
    background-color: #f8f9fb;
}

code {
    font-family: "SF Mono", "Consolas", "Liberation Mono", monospace;
    font-size: 7.5pt;
    background-color: #f0f4f8;
    padding: 0.5pt 2pt;
    border-radius: 2pt;
}

pre {
    background-color: #f0f4f8;
    border: 1px solid #d0d7de;
    border-radius: 3pt;
    padding: 4pt 7pt;
    font-size: 7.5pt;
    line-height: 1.25;
    margin: 2pt 0;
    overflow: hidden;
}

pre code {
    background: none;
    padding: 0;
}

/* Footer links */
p:last-child {
    font-size: 8pt;
    color: #555;
    margin-top: 2pt;
}

a {
    color: #2563eb;
    text-decoration: none;
}
"""


def main():
    with open(MD_PATH) as f:
        md_text = f.read()

    html_body = markdown.markdown(
        md_text,
        extensions=["tables", "fenced_code"],
    )

    full_html = f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<style>{CSS}</style>
</head><body>{html_body}</body></html>"""

    HTML(string=full_html).write_pdf(PDF_PATH)
    print(f"PDF written to {PDF_PATH}")


if __name__ == "__main__":
    main()

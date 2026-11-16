r"""
Section V (Evaluation) of main.tex on its own, with the same numbering as the full report:
  eval/evaluation.tex / .pdf   the section in IEEE two-column format
  eval/pages/                  each page of it as a PNG
  eval/items/                  each figure and table of the section as its own PNG (with its caption)
Run pdflatex on main.tex first (the numbers of references to other sections come from main.aux).
"""
import re
import shutil
import subprocess
from pathlib import Path

from PIL import Image, ImageChops

HERE = Path(__file__).resolve().parent
OUT = HERE / "eval"
TEX = (HERE / "main.tex").read_text(encoding="utf-8")
AUX = (HERE / "main.aux").read_text(encoding="utf-8")
labels = {m.group(1): re.sub(r"\\mbox\s*\{([^}]*)\}", r"\1", m.group(2))
          for m in re.finditer(r"\\newlabel\{([^}]+)\}\{\{((?:[^{}]|\{[^{}]*\})*)\}", AUX)}
cites = {m.group(1): m.group(2) for m in re.finditer(r"\\bibcite\{([^}]+)\}\{([^}]+)\}", AUX)}
def _roman(n):
    out = ""
    for v, r in ((10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I")):
        while n >= v:
            out, n = out + r, n - v
    return out


ROMAN = {_roman(n): n for n in range(1, 40)}

preamble = TEX.split(r"\begin{document}")[0]
sec = TEX[TEX.index(r"\section{Evaluation}"):TEX.index(r"\section{Discussion and Threats to Validity}")]
# references outside the section become fixed numbers, as in the full report
sec = re.sub(r"\\eqref\{([^}]+)\}", lambda m: f"({labels[m.group(1)]})", sec)
sec = re.sub(r"\\ref\{([^}]+)\}", lambda m: labels[m.group(1)], sec)
sec = re.sub(r"\\cite\{([^}]+)\}", lambda m: ", ".join(f"[{cites[k.strip()]}]" for k in m.group(1).split(",")), sec)

counters = r"""\setcounter{section}{4}
\setcounter{figure}{4}
\setcounter{table}{3}
"""
OUT.mkdir(exist_ok=True)
(OUT / "figs").mkdir(exist_ok=True)
for f in (HERE / "figs").glob("*.png"):
    shutil.copy(f, OUT / "figs" / f.name)
shutil.copy(HERE / "IEEEtran.cls", OUT / "IEEEtran.cls")

head = (r"\twocolumn[{\centering{\footnotesize Excerpt from \textit{Automatic API Security Design Review for Microservices "
        r"Using Threat Graph Analysis}, Section V. Figures, tables and equations are numbered as in the full report.}\par\vspace{10pt}}]" "\n")
# keep page 1 free of floats so the section starts at the top
sec_first = sec.replace(r"\label{sec:eval}", r"\label{sec:eval}\suppressfloats[t]", 1)
doc = preamble + "\\begin{document}\n" + counters + head + sec_first + "\\end{document}\n"
(OUT / "evaluation.tex").write_text(doc, encoding="utf-8")


def latex(name, cwd):
    for _ in range(2):
        r = subprocess.run(["pdflatex", "-interaction=nonstopmode", "-halt-on-error", name], cwd=cwd,
                           capture_output=True, text=True)
        if r.returncode:
            raise SystemExit(r.stdout[-2000:])


latex("evaluation.tex", OUT)
pages = OUT / "pages"
shutil.rmtree(pages, ignore_errors=True)
pages.mkdir()
subprocess.run(["pdftoppm", "-r", "200", "-png", "evaluation.pdf", "pages/evaluation-page"], cwd=OUT, check=True)


# each float on its own page, then cropped to its ink
def crop(png: Path, pad=24):
    im = Image.open(png).convert("RGB")
    bg = Image.new("RGB", im.size, (255, 255, 255))
    box = ImageChops.difference(im, bg).getbbox()
    if box:
        l, t, r, b = box
        im = im.crop((max(0, l - pad), max(0, t - pad), min(im.width, r + pad), min(im.height, b + pad)))
    im.save(png)


items = OUT / "items"
shutil.rmtree(items, ignore_errors=True)
items.mkdir()
work = OUT / "item-build"
shutil.rmtree(work, ignore_errors=True)
(work / "figs").mkdir(parents=True)
for f in (HERE / "figs").glob("*.png"):
    shutil.copy(f, work / "figs" / f.name)
shutil.copy(HERE / "IEEEtran.cls", work / "IEEEtran.cls")
one_col_preamble = preamble.replace(r"\documentclass[conference]{IEEEtran}", r"\documentclass[conference,onecolumn]{IEEEtran}")

for m in re.finditer(r"\\begin\{(figure\*?|table\*?)\}(?:\[[^\]]*\])?(.*?)\\end\{\1\}", sec, re.S):
    env, body = m.group(1), m.group(2)
    lab = re.search(r"\\label\{([^}]+)\}", body).group(1)
    num = labels[lab]
    kind = "figure" if env.startswith("figure") else "table"
    n = int(num) if kind == "figure" else ROMAN[num]
    width = "7.16in" if env.endswith("*") else "3.5in"
    body = body.replace(r"\textwidth", r"\linewidth").replace(r"\columnwidth", r"\linewidth")
    src = (one_col_preamble + "\\begin{document}\n\\pagestyle{empty}\n" + f"\\setcounter{{{kind}}}{{{n - 1}}}\n"
           + f"\\begin{{{kind}}}[!h]\\centering\\begin{{minipage}}{{{width}}}\\centering\n" + body
           + f"\n\\end{{minipage}}\\end{{{kind}}}\n\\end{{document}}\n")
    stem = f"{'Fig' if kind == 'figure' else 'Table'}-{num}-{lab.split(':')[1]}"
    (work / f"{stem}.tex").write_text(src, encoding="utf-8")
    latex(f"{stem}.tex", work)
    subprocess.run(["pdftoppm", "-r", "250", "-png", "-singlefile", f"{stem}.pdf", str(items / stem)], cwd=work, check=True)
    crop(items / f"{stem}.png")
    print("wrote", f"items/{stem}.png")
shutil.rmtree(work)
print("pages:", len(list(pages.glob("*.png"))))

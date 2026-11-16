r"""
Build main.docx (IEEE-style, two columns) from main.tex and the LaTeX build's main.aux.

  1. Rewrite main.tex into something pandoc reads cleanly: numbers for \ref, \eqref and \cite taken
     from main.aux; section, figure and table numbers written into the text (IEEE style); the
     abstract, keywords, authors and references as plain paragraphs; simple tabular column specs;
     marker paragraphs around figure* / table* so they can span both columns.
  2. pandoc -> raw.docx, with a reference document whose styles follow the IEEE template
     (Times New Roman 10 pt, small-caps section headings, 8 pt tables and captions).
  3. Post-process document.xml: US Letter page, IEEE margins, a one-column title section, two
     columns for the body, one-column continuous sections for the wide floats, images scaled to fit.
"""
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEX = (HERE / "main.tex").read_text(encoding="utf-8")
AUX = (HERE / "main.aux").read_text(encoding="utf-8")

labels = {m.group(1): re.sub(r"\\mbox\s*\{([^}]*)\}", r"\1", m.group(2))
          for m in re.finditer(r"\\newlabel\{([^}]+)\}\{\{((?:[^{}]|\{[^{}]*\})*)\}", AUX)}
cites = {m.group(1): m.group(2) for m in re.finditer(r"\\bibcite\{([^}]+)\}\{([^}]+)\}", AUX)}

ROMAN = ["", "I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII"]


def body_of(tex: str) -> str:
    return tex.split(r"\begin{document}", 1)[1].split(r"\end{document}", 1)[0]


def preamble_macros(tex: str) -> str:
    keep = [l for l in tex.split(r"\begin{document}")[0].splitlines() if l.startswith(r"\newcommand")]
    return "\n".join(keep).replace(r"\mathrm{APCR}", r"\text{APCR}")


def balanced(s: str, i: int) -> int:
    """index just after the {...} group that starts at s[i] == '{'"""
    depth = 0
    for j in range(i, len(s)):
        if s[j] == "{":
            depth += 1
        elif s[j] == "}":
            depth -= 1
            if depth == 0:
                return j + 1
    raise ValueError("unbalanced")


def ncols(spec: str) -> int:
    spec = re.sub(r"@\{[^}]*\}", "", spec)
    spec = re.sub(r">\{(?:[^{}]|\{[^{}]*\})*\}", "", spec)
    spec = re.sub(r"p\{[^}]*\}", "p", spec)
    return sum(1 for c in spec if c in "lcrp")


def convert(tex: str) -> str:
    b = body_of(tex)

    # references to labels, equations and citations
    b = re.sub(r"\\eqref\{([^}]+)\}", lambda m: f"({labels[m.group(1)]})", b)
    b = re.sub(r"\\ref\{([^}]+)\}", lambda m: labels[m.group(1)], b)
    b = re.sub(r"\\cite\{([^}]+)\}", lambda m: ", ".join(f"[{cites[k.strip()]}]" for k in m.group(1).split(",")), b)

    # display math: texmath knows neither \textsc nor \nonumber
    def mathfix(m):
        env, t = m.group(1), m.group(2)
        t = re.sub(r"\\textsc\{([^}]*)\}", lambda k: r"\text{" + k.group(1).replace("\\_", "_").upper() + "}", t)
        t = t.replace(r"\nonumber", "").replace(r"\textstyle", "").replace("&", "")
        t = t.replace("\\ ", " ").replace(r"\!", "").replace(r"\,", "")
        lines = [l.strip() for l in t.split(r"\\") if l.strip()] if env != "equation" else [t.strip()]
        return "\n".join(r"\begin{equation}" + l.replace(r"\qquad", "", 1) if l.startswith(r"\qquad") else
                         r"\begin{equation}" + l for l in lines).replace(r"\begin{equation}", "\n" + r"\begin{equation}") \
            .replace("\n" + r"\begin{equation}", r"\end{equation}" + "\n" + r"\begin{equation}")[len(r"\end{equation}") + 1:] + r"\end{equation}"
    b = re.sub(r"\\begin\{(equation|align|gather)\}(.*?)\\end\{\1\}", mathfix, b, flags=re.S)

    # symbols LibreOffice cannot import from Word math; Word shows both forms
    b = b.replace(r"^{*}", r"^{\star}").replace(r"\setminus", r"\smallsetminus")

    # words in math as one text run (Word and LibreOffice both keep them upright and together)
    b = re.sub(r"\\mathrm\{([A-Za-z_]+)\}", r"\\text{\1}", b)

    # equation numbers written into the math, right of the formula
    def number_eq(m):
        return r"\qquad (" + labels[m.group(1)] + ")"
    b = re.sub(r"\\label\{(eq:[^}]+)\}", number_eq, b)

    # title block
    b = re.sub(r"\\author\{.*?siit\.tu\.ac\.th\}\}", "", b, flags=re.S)
    authors = ("AUTHORSTART\n\nPhanapon Maneechot, Atiwat Thanapatsiri, Hiran Sanguantam, Sunya Nuchapong, Somchart Fugkeaw\n\n"
               "\\textit{Sirindhorn International Institute of Technology, Thammasat University, Thailand}\n\n"
               "6622780326@g.siit.tu.ac.th, 6622780334@g.siit.tu.ac.th, 6622770632@g.siit.tu.ac.th, "
               "6622782637@g.siit.tu.ac.th, somchart@siit.tu.ac.th\n\nAUTHOREND\n\n")
    b = b.replace(r"\maketitle", authors)
    b = re.sub(r"\\begin\{abstract\}\s*(.*?)\s*\\end\{abstract\}",
               lambda m: r"\textbf{\textit{Abstract}---" + m.group(1).strip() + "}", b, flags=re.S)
    b = re.sub(r"\\begin\{IEEEkeywords\}\s*(.*?)\s*\\end\{IEEEkeywords\}",
               lambda m: r"\textbf{\textit{Index Terms}---" + m.group(1).strip() + "}", b, flags=re.S)

    # section numbers in IEEE style
    out, sec, sub, subsub = [], 0, 0, 0
    pos = 0
    for m in re.finditer(r"\\(section|subsection|subsubsection)\{", b):
        out.append(b[pos:m.start()])
        end = balanced(b, m.end() - 1)
        title = b[m.end():end - 1]
        lab = re.match(r"\\label\{[^}]+\}", b[end:])
        if lab:
            end += lab.end()
        kind = m.group(1)
        if kind == "section":
            sec, sub, subsub = sec + 1, 0, 0
            out.append(r"\section*{" + f"{ROMAN[sec]}. " + title + "}")
        elif kind == "subsection":
            sub, subsub = sub + 1, 0
            out.append(r"\subsection*{" + f"{chr(64 + sub)}. " + title + "}")
        else:
            subsub += 1
            out.append(r"\subsubsection*{" + f"{subsub}) " + title + "}")
        pos = end
    out.append(b[pos:])
    b = "".join(out)

    # captions with their numbers; wide floats marked for a one-column section
    def float_env(m):
        env, inner = m.group(1), m.group(2)
        lab = re.search(r"\\label\{([^}]+)\}", inner)
        num = labels[lab.group(1)] if lab else "?"
        prefix = f"Fig. {num}. " if env.startswith("figure") else f"TABLE {num}: "

        def cap(c):
            i = c.end() - 1
            j = balanced(inner, i)
            return r"\caption{" + prefix + inner[i + 1:j - 1] + "}"
        cm = re.search(r"\\caption\{", inner)
        if cm:
            j = balanced(inner, cm.end() - 1)
            inner = inner[:cm.start()] + cap(cm) + inner[j:]
        inner = re.sub(r"\\label\{[^}]+\}", "", inner)
        base = env.rstrip("*")
        txt = r"\begin{" + base + "}" + inner + r"\end{" + base + "}"
        if env.endswith("*"):
            return "\n\nSPANSTART\n\n" + txt + "\n\nSPANEND\n\n"
        return txt
    b = re.sub(r"\\begin\{(figure\*?|table\*?)\}(?:\[[^\]]*\])?(.*?)\\end\{\1\}", float_env, b, flags=re.S)

    # tables: plain column specs; drop size and spacing commands pandoc does not know
    def tab(m):
        i = m.end() - 1
        j = balanced(b2, i)
        spec = b2[i + 1:j - 1]
        return r"\begin{tabular}{" + "l" * ncols(spec) + "}", j
    res, pos = [], 0
    b2 = b
    for m in re.finditer(r"\\begin\{tabular\}\{", b2):
        if m.start() < pos:
            continue
        rep, j = tab(m)
        res.append(b2[pos:m.start()])
        res.append(rep)
        pos = j
    res.append(b2[pos:])
    b = "".join(res)
    b = re.sub(r"\\setlength\{\\tabcolsep\}\{[^}]*\}", "", b)
    b = re.sub(r"\\(footnotesize|scriptsize|small|centering)\b", "", b)
    # table footnote rows: keep the text as a plain row
    # a footnote row after \bottomrule becomes a small paragraph under the table
    def tabnote(m):
        i = m.end() - 1
        j = balanced(b, i)
        rest = b[j:]
        end = rest.index(r"\end{tabular}")
        tail = rest[:end].strip().rstrip("\\").strip()
        return (r"\bottomrule" + "\n" + r"\end{tabular}" + "\n\nTABNOTE " + b[i + 1:j - 1].strip() + " " + tail + "\n\n", j + end + len(r"\end{tabular}"))
    while True:
        m = re.search(r"\\bottomrule\s*\\multicolumn\{\d+\}\{(?:[^{}]|\{[^{}]*\})*\}\{", b)
        if not m:
            break
        new_txt, stop = tabnote(m)
        b = b[:m.start()] + new_txt + b[stop:]
    b = b.replace(r"$^{c}$", r"\textsuperscript{c}")
    while True:
        m = re.search(r"\\multicolumn\{(\d+)\}\{(?:[^{}]|\{[^{}]*\})*\}\{", b)
        if not m:
            break
        j = balanced(b, m.end() - 1)
        b = b[:m.start()] + b[m.end():j - 1] + " &" * (int(m.group(1)) - 1) + b[j:]

    # references as numbered paragraphs
    def bib(m):
        items = re.split(r"\\bibitem\{([^}]+)\}", m.group(1))[1:]
        paras = ["\\section*{References}"]
        for k in range(0, len(items), 2):
            paras.append(f"BIBITEM[{cites[items[k]]}] " + items[k + 1].strip())
        return "\n\n".join(paras)
    b = re.sub(r"\\begin\{thebibliography\}\{\d+\}(.*?)\\end\{thebibliography\}", bib, b, flags=re.S)

    title = re.search(r"\\title\{(.*?)\}\n", tex).group(1)
    return ("\\documentclass{article}\n" + preamble_macros(tex) + "\n\\title{" + title + "}\n\\begin{document}\n"
            + b.replace(r"\title{" + title + "}", "") + "\n\\end{document}\n")


# ---------------------------------------------------------------- reference document (styles)
def reference_doc(dst: Path):
    src = HERE / "ref-default.docx"
    z = zipfile.ZipFile(src)
    files = {n: z.read(n) for n in z.namelist()}
    st = files["word/styles.xml"].decode()

    def style(sid, ppr, rpr):
        nonlocal st
        m = re.search(r'(<w:style [^>]*w:styleId="%s"[^>]*>)(.*?)(</w:style>)' % sid, st, re.S)
        if not m:
            return
        inner = m.group(2)
        inner = re.sub(r"<w:pPr>.*?</w:pPr>|<w:pPr/>", "", inner, flags=re.S)
        inner = re.sub(r"<w:rPr>.*?</w:rPr>|<w:rPr/>", "", inner, flags=re.S)
        st = st[:m.start()] + m.group(1) + inner + f"<w:pPr>{ppr}</w:pPr><w:rPr>{rpr}</w:rPr>" + m.group(3) + st[m.end():]

    tnr = '<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="Times New Roman" w:cs="Times New Roman"/>'
    black = '<w:color w:val="000000"/>'
    st = re.sub(r"<w:rFonts [^>]*/>", tnr, st)
    body = f'<w:spacing w:before="0" w:after="0" w:line="228" w:lineRule="auto"/><w:ind w:firstLine="202"/><w:jc w:val="both"/>'
    style("Normal", '<w:spacing w:before="0" w:after="0"/>', tnr + '<w:sz w:val="20"/><w:szCs w:val="20"/>')
    style("BodyText", body, tnr + '<w:sz w:val="20"/><w:szCs w:val="20"/>')
    style("FirstParagraph", body, tnr + '<w:sz w:val="20"/><w:szCs w:val="20"/>')
    style("Compact", '<w:spacing w:before="0" w:after="0"/><w:ind w:firstLine="0"/>', tnr + '<w:sz w:val="16"/><w:szCs w:val="16"/>')
    style("Title", '<w:spacing w:before="0" w:after="160"/><w:jc w:val="center"/>', tnr + black + '<w:sz w:val="48"/><w:szCs w:val="48"/>')
    style("Heading1", '<w:keepNext/><w:spacing w:before="160" w:after="80"/><w:ind w:firstLine="0"/><w:jc w:val="center"/><w:outlineLvl w:val="0"/>',
          tnr + black + '<w:b w:val="0"/><w:smallCaps/><w:sz w:val="20"/><w:szCs w:val="20"/>')
    style("Heading2", '<w:keepNext/><w:spacing w:before="120" w:after="60"/><w:ind w:firstLine="0"/><w:outlineLvl w:val="1"/>',
          tnr + black + '<w:b w:val="0"/><w:i/><w:sz w:val="20"/><w:szCs w:val="20"/>')
    style("Heading3", '<w:keepNext/><w:spacing w:before="60" w:after="0"/><w:ind w:firstLine="202"/><w:outlineLvl w:val="2"/>',
          tnr + black + '<w:b w:val="0"/><w:i/><w:sz w:val="20"/><w:szCs w:val="20"/>')
    cap = '<w:spacing w:before="60" w:after="120"/><w:ind w:firstLine="0"/><w:jc w:val="both"/>'
    style("ImageCaption", cap, tnr + black + '<w:i w:val="0"/><w:sz w:val="16"/><w:szCs w:val="16"/>')
    style("TableCaption", '<w:keepNext/><w:spacing w:before="120" w:after="60"/><w:ind w:firstLine="0"/><w:jc w:val="center"/>',
          tnr + black + '<w:i w:val="0"/><w:smallCaps/><w:sz w:val="16"/><w:szCs w:val="16"/>')
    style("Caption", cap, tnr + black + '<w:i w:val="0"/><w:sz w:val="16"/><w:szCs w:val="16"/>')
    style("CaptionedFigure", '<w:keepNext/><w:spacing w:before="120" w:after="0"/><w:jc w:val="center"/>', "")
    style("Figure", '<w:keepNext/><w:spacing w:before="120" w:after="0"/><w:jc w:val="center"/>', "")
    style("SourceCode", '<w:spacing w:before="0" w:after="0"/>', '<w:sz w:val="14"/>')
    style("Bibliography", '<w:spacing w:before="0" w:after="20"/><w:ind w:left="360" w:hanging="360"/><w:jc w:val="both"/>',
          tnr + '<w:sz w:val="16"/><w:szCs w:val="16"/>')
    m = re.search(r'(<w:style w:type="character"[^>]*w:styleId="VerbatimChar">.*?<w:rPr>)(.*?)(</w:rPr>)', st, re.S)
    mono = '<w:rFonts w:ascii="Courier New" w:hAnsi="Courier New" w:eastAsia="Courier New" w:cs="Courier New"/>'
    st = (st[:m.start()] + m.group(1) + mono + re.sub(r"<w:sz[^>]*/>|<w:szCs[^>]*/>|<w:rFonts[^>]*/>", "", m.group(2))
          + '<w:sz w:val="14"/><w:szCs w:val="14"/>' + m.group(3) + st[m.end():])
    st = re.sub(r'(<w:color w:val="345A8A" ?/>)\s*&gt;', r'\1', st)   # a stray character in pandoc's default styles
    m = re.search(r'<w:style w:type="table" w:default="1" w:styleId="Table">.*?</w:style>', st, re.S)
    t = m.group(0).replace("<w:tblCellMar>", '<w:tblBorders><w:top w:val="single" w:sz="8" w:space="0" w:color="000000"/>'
                           '<w:bottom w:val="single" w:sz="8" w:space="0" w:color="000000"/></w:tblBorders><w:tblCellMar>', 1)
    t = t.replace('<w:left w:w="108" w:type="dxa" />', '<w:left w:w="57" w:type="dxa" />').replace('<w:right w:w="108" w:type="dxa" />', '<w:right w:w="57" w:type="dxa" />')
    st = st[:m.start()] + t + st[m.end():]
    files["word/styles.xml"] = st.encode()
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as o:
        for n, d in files.items():
            o.writestr(n, d)


# ---------------------------------------------------------------- post-processing
PAGE = ('<w:pgSz w:w="12240" w:h="15840"/>'
        '<w:pgMar w:top="1080" w:right="900" w:bottom="1440" w:left="900" w:header="720" w:footer="720" w:gutter="0"/>')
COL_W = int((12240 - 1800 - 360) / 2)         # twips: two columns, 0.25 in gap
FULL_W = 12240 - 1800


def sect(cols: int, cont: bool = True) -> str:
    c = f'<w:cols w:num="2" w:space="360"/>' if cols == 2 else '<w:cols w:space="720"/>'
    t = '<w:type w:val="continuous"/>' if cont else ""
    return f"<w:sectPr>{t}{PAGE}{c}</w:sectPr>"


def para_with_sect(cols: int, cont: bool = True) -> str:
    return f'<w:p><w:pPr><w:spacing w:before="0" w:after="0"/>{sect(cols, cont)}</w:pPr></w:p>'


def postprocess(raw: Path, out: Path):
    z = zipfile.ZipFile(raw)
    files = {n: z.read(n) for n in z.namelist()}
    d = files["word/document.xml"].decode()

    def marker(word):
        return re.compile(r"<w:p>(?:(?!<w:p>).)*?<w:t[^>]*>" + word + r"</w:t>.*?</w:p>", re.S)

    # authors centred; title section one column
    a0 = marker("AUTHORSTART").search(d)
    d = d[:a0.start()] + d[a0.end():]
    a1 = marker("AUTHOREND").search(d)
    seg = d[a0.start():a1.start()]
    seg = re.sub(r"<w:pPr>(.*?)</w:pPr>", r'<w:pPr>\1<w:ind w:firstLine="0"/><w:jc w:val="center"/></w:pPr>', seg)
    seg = re.sub(r"<w:p>(?!<w:pPr>)", r'<w:p><w:pPr><w:ind w:firstLine="0"/><w:jc w:val="center"/></w:pPr>', seg)
    d = d[:a0.start()] + seg + para_with_sect(1, cont=False) + d[a1.end():]

    # wide floats: their own one-column section
    d = marker("SPANSTART").sub(lambda m: para_with_sect(2), d)
    d = marker("SPANEND").sub(lambda m: para_with_sect(1), d)

    # last section: two columns
    d = re.sub(r"<w:sectPr\s*/>\s*</w:body>|<w:sectPr(?: [^>]*)?>(?:(?!<w:sectPr).)*?</w:sectPr>\s*</w:body>",
               "</w:body>", d, flags=re.S)
    d = d.replace("</w:body>", sect(2) + "</w:body>")

    # references: hanging indent, 8 pt
    def bibp(m):
        p = m.group(0).replace("BIBITEM", "", 1)
        p = re.sub(r"<w:pPr>.*?</w:pPr>", "", p, count=1, flags=re.S)
        return p.replace("<w:p>", '<w:p><w:pPr><w:pStyle w:val="Bibliography"/></w:pPr>', 1)
    d = re.sub(r"<w:p>(?:(?!<w:p>).)*?BIBITEM.*?</w:p>", bibp, d, flags=re.S)
    d = d.replace('<m:sepChr m:val="" />', "")

    def notep(m):
        p = m.group(0).replace("TABNOTE ", "", 1)
        p = re.sub(r"<w:pPr>.*?</w:pPr>", "", p, count=1, flags=re.S)
        return p.replace("<w:p>", '<w:p><w:pPr><w:pStyle w:val="Compact"/><w:spacing w:before="20" w:after="120"/></w:pPr>', 1)
    d = re.sub(r"<w:p>(?:(?!<w:p>).)*?TABNOTE .*?</w:p>", notep, d, flags=re.S)
    d = d.replace('<w:pStyle w:val="SourceCode" /><w:jc w:val="center" />', '<w:pStyle w:val="SourceCode" /><w:jc w:val="left" />')

    # images: fit the column, or the page width inside a one-column section
    sections = re.split(r"(<w:sectPr>.*?</w:sectPr>)", d, flags=re.S)
    fixed = []
    for part in sections:
        fixed.append(part)
    # decide per drawing by looking at the next sectPr after it
    def fit(m):
        start = m.start()
        nxt = d.find("<w:sectPr>", start)
        cols1 = '<w:cols w:space="720"/>' in d[nxt:d.find("</w:sectPr>", nxt)]
        maxw = (FULL_W * 0.72 if cols1 else COL_W) * 635      # twips -> EMU
        cx, cy = int(m.group(1)), int(m.group(2))
        if cx > maxw:
            cy = int(cy * maxw / cx)
            cx = int(maxw)
        return f'cx="{cx}" cy="{cy}"'
    d = re.sub(r'cx="(\d+)" cy="(\d+)"', fit, d)

    # tables: full width of their column, 8 pt, top and bottom rules like booktabs
    def tbl(m):
        t = m.group(0)
        nxt = d.find("<w:sectPr>", m.start())
        avail = FULL_W if '<w:cols w:space="720"/>' in d[nxt:d.find("</w:sectPr>", nxt)] else COL_W
        if "FigureTable" in t:     # a figure that is not an image (the EUJF listing): fit it to the column
            t = re.sub(r"<w:gridCol [^>]*/>", f'<w:gridCol w:w="{avail}"/>', t)
            t = re.sub(r"<w:tblW [^>]*/>", '<w:tblW w:w="5000" w:type="pct"/>', t)
            return t
        rows = re.findall(r"<w:tr>.*?</w:tr>", t, re.S)
        ncol = len(re.findall(r"<w:gridCol ", t))
        lens = [[] for _ in range(ncol)]
        for r in rows:
            for j, c in enumerate(re.findall(r"<w:tc>.*?</w:tc>", r, re.S)[:ncol]):
                txt = "".join(re.findall(r"<(?:w|m):t[^>]*>([^<]*)<", c))
                lens[j].append(len(txt))
        head = re.findall(r"<w:tc>.*?</w:tc>", rows[0], re.S) if rows else []
        hw = [max((len(w) for w in "".join(re.findall(r"<(?:w|m):t[^>]*>([^<]*)<", c)).split()), default=3) + 1 for c in head]
        weight = [2 + max(5, min(max(l or [4]), 26), hw[j] if j < len(hw) else 0) for j, l in enumerate(lens)]
        widths = [int(avail * w / sum(weight)) for w in weight]
        t = re.sub(r"<w:tblGrid>.*?</w:tblGrid>", "<w:tblGrid>" + "".join(f'<w:gridCol w:w="{w}"/>' for w in widths) + "</w:tblGrid>", t, flags=re.S)
        def row(rm):
            k = iter(widths)
            return re.sub(r"<w:tcPr />|<w:tcPr/>", lambda _: f'<w:tcPr><w:tcW w:w="{next(k, widths[-1])}" w:type="dxa"/></w:tcPr>', rm.group(0))
        t = re.sub(r"<w:tr>.*?</w:tr>", row, t, flags=re.S)
        t = re.sub(r"<w:tblW [^>]*/>", '<w:tblW w:w="5000" w:type="pct"/>', t)
        t = t.replace('<w:jc w:val="start" />', '<w:jc w:val="center" />', 1)
        return t
    d = re.sub(r"<w:tbl>.*?</w:tbl>", tbl, d, flags=re.S)

    files["word/document.xml"] = d.encode()
    files["word/styles.xml"] = re.sub(rb'(<w:color w:val="345A8A" ?/>)\s*&gt;', rb"\1", files["word/styles.xml"])
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as o:
        for n, data in files.items():
            if not n.endswith("/"):
                o.writestr(n, data)


def main():
    work = HERE / "docx-build"
    work.mkdir(exist_ok=True)
    (work / "docx.tex").write_text(convert(TEX), encoding="utf-8")
    shutil.copytree(HERE / "figs", work / "figs", dirs_exist_ok=True)
    reference_doc(work / "reference.docx")
    subprocess.run(["pandoc", "docx.tex", "-f", "latex", "-t", "docx", "--reference-doc", "reference.docx",
                    "-o", "raw.docx"], cwd=work, check=True)
    postprocess(work / "raw.docx", HERE / "main.docx")
    print("wrote main.docx")


if __name__ == "__main__":
    main()

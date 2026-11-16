"""Read the tables of results/opensource/comparison.md and turn them into LaTeX rows."""
import re

SYS = {"online-boutique": "Online Boutique", "bank-of-anthos": "Bank of Anthos", "robot-shop": "Robot Shop",
       "acme-air": "Acme Air", "petclinic": "PetClinic", "piggymetrics": "PiggyMetrics",
       "lakeside-mutual": "Lakeside Mutual", "ftgo": "FTGO", "hotel-reservation": "Hotel Reservation",
       "bookinfo": "Bookinfo"}
SYS_RE = re.compile(r"(?<![\w-])(" + "|".join(map(re.escape, SYS)) + r")(?![\w-])")


def tables(md):
    """{heading: [table, ...]}, each table a list of rows (lists of cell strings), header first."""
    out, head, cur = {}, None, None
    for line in md.splitlines():
        if line.startswith("#"):
            head = line.lstrip("#").strip()
            cur = None
            continue
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if all(re.fullmatch(r":?-+:?", c) for c in cells):
                continue
            if cur is None:
                cur = []
                out.setdefault(head, []).append(cur)
            cur.append(cells)
        else:
            cur = None
    return out


def esc(t, systems=True):
    parts = re.split(r"(`[^`]*`)", t)
    res = []
    for p in parts:
        if p.startswith("`") and p.endswith("`") and len(p) > 1:
            inner = p[1:-1].replace("\\", "/").replace("_", r"\_").replace("&", r"\&").replace("%", r"\%").replace("#", r"\#").replace("{", r"\{").replace("}", r"\}")
            res.append(r"\texttt{" + inner + "}")
            continue
        p = p.replace("&", r"\&").replace("%", r"\%").replace("#", r"\#").replace("_", r"\_")
        p = re.sub(r"\*\*(.+?)\*\*", r"\\textbf{\1}", p)
        p = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"\\textit{\1}", p)
        p = re.sub(r'"([^"]*)"', r"``\1''", p)
        p = p.replace("·", r"$\cdot$")
        if systems:
            p = SYS_RE.sub(lambda m: SYS[m.group(1)], p)
        res.append(p)
    return "".join(res)


def rows(tab, skip_header=True, systems=True, fix=None):
    out = []
    for r in tab[1 if skip_header else 0:]:
        cells = [esc(c, systems) for c in r]
        if fix:
            cells = fix(cells)
        out.append(" & ".join(cells) + r" \\")
    return "\n".join(out)

"""Write Section V of main.tex from the BENCH page (results/opensource/comparison.md).

Run after BENCH:   python3 paper/gen_sec5.py
It fills sec5_template.tex with the page's tables, replaces Section V in main.tex and copies the BENCH charts
into figs/. Then build: pdflatex main.tex (twice).
"""
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import mdtab  # noqa: E402
from mdtab import rows  # noqa: E402

RES = HERE.parent / "results" / "opensource"
MD = (RES / "comparison.md").read_text(encoding="utf-8")
T = mdtab.tables(MD)
RR = r">{\raggedright\arraybackslash}"
COMPOSE = {"Robot Shop", "PetClinic", "PiggyMetrics"}


def tab(head, i=0):
    return T[head][i]


def total_row(t, first_cols, label="Total"):
    r"""Sum the numeric columns after first_cols ($\cdot$ and n/a count as nothing)."""
    sums = []
    for j in range(first_cols, len(t[0])):
        v = 0
        for r in t[1:]:
            m = re.match(r"\**(\d+)", r[j])
            v += int(m.group(1)) if m else 0
        sums.append(str(v))
    return sums


def persys_fix(c):
    if c[0] in COMPOSE:
        c[0] += r"$^{c}$"
    return c


kinds = tab("Found, by kind of weakness")
ksum = total_row(kinds, 2)
persys = tab("Found on each system")
psum = total_row(persys, 1)
order = [r[0] for r in persys[1:]]
ids = {v: k for k, v in mdtab.SYS.items()}
def grid_of(ids_, per_row, w="0.32"):
    out = []
    for n, sid in enumerate(ids_):
        last = n == len(ids_) - 1
        out.append(r"\includegraphics[width=" + w + r"\textwidth]{figs/fig_system_" + sid + ".png}"
                   + ("" if last else ("\\\\[4pt]" if n % per_row == per_row - 1 else "\\hfill")))
    return "\n".join(out)


S = {}
S["compared"] = rows(tab("The tools compared"))
S["speed"] = rows(tab("Time to review one system"))
cost = tab("Computing resources to review one system")
cost = [cost[0]] + sorted(cost[1:], key=lambda r: -int(r[1].split("/")[0]))   # most systems first; CPU order kept
S["cost"] = rows(cost)
S["largest"] = rows(tab("The largest use on one system"), fix=lambda c: c[:3] + [c[3].replace(" (most CPU)", "")])
S["containers"] = rows(tab("What ATG's four containers use during a review"))
S["inventory"] = rows(tab("Inventory and visibility: detected or not"))
S["ops"] = rows(tab("Operations ATG listed (its API inventory)"))
S["found"] = rows(tab("How many known weaknesses each tool found"))
S["unmatched"] = rows(tab("ATG's reports that are not in the answer key"))
S["checks"] = rows(tab("Why the file scanners find configuration but no API behaviour or inventory"))
S["kinds"] = re.sub(r"\\\\\n(C1 |O1 )", lambda m: "\\\\\n\\midrule\n" + m.group(1), rows(kinds)) + "\n\\midrule\n & Total & " + " & ".join(ksum) + r" \\"
S["persys"] = rows(persys, fix=persys_fix) + "\n\\midrule\nTotal & " + " & ".join(psum) + r" \\"
S["pairs"] = rows(tab("ATG and a Kubernetes scanner used together"))
S["combos"] = rows(tab("Measured: every combination on the same answer key", 0))
S["misses"] = rows(tab("Measured: every combination on the same answer key", 1))
S["planA"] = rows(tab("Future plan", 0))
S["planB"] = rows(tab("Future plan", 1))
S["systems"] = rows(tab("Which systems each tool can read"))
S["langs"] = rows(tab("Services and languages each tool can review"))
S["syslangs"] = rows(tab("The services of each system and their languages"))
S["matrix"] = rows(tab("Which tool can review each language"))
S["cannot"] = rows(tab("What ATG cannot read"))
S["grid1"] = grid_of(order[:6], 3)
S["grid2"] = grid_of(order[6:], 4, "0.245")

tpl = (HERE / "sec5_template.tex").read_text(encoding="utf-8")
out = re.sub(r"%%(\w+)%%", lambda m: S[m.group(1)], tpl)
out = out.replace("(the operations table in section 3)", "(Table~\\ref{tab:ops})")
main = (HERE / "main.tex").read_text(encoding="utf-8")
i = main.index(r"\section{Evaluation}\label{sec:eval}")
j = main.index(r"\section{Discussion and Threats to Validity}")
main = main[:i] + out + main[j:]
# tables outside Section V that come from the page: between "% bench:NAME" and "% bench:end NAME"
main = re.sub(r"(% bench:(\w+)\n).*?(% bench:end \2)", lambda m: m.group(1) + S[m.group(2)] + "\n" + m.group(3), main, flags=re.S)
(HERE / "main.tex").write_text(main, encoding="utf-8")
figs = {"fig4_speed.png": "fig_speed.png", "fig6a_cpu.png": "fig_cpu.png", "fig6b_memory.png": "fig_memory.png",
        "fig1_groups_column.png": "fig_oss_groups.png", "fig2_systems_grid.png": "fig_systems_grid.png",
        "fig3a_systems.png": "fig_systems_covered.png", "fig3b_services.png": "fig_services.png", "fig3c_languages.png": "fig_languages.png"}
for a, b in figs.items():
    shutil.copy(RES / "figures" / a, HERE / "figs" / b)
print("Section V written into main.tex:", len(out.splitlines()), "lines,", len(figs), "figures copied")

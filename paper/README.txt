Automatic API Security Design Review for Microservices Using Threat Graph Analysis
LaTeX source of the full report (IEEE conference format, two columns).

Files
  main.tex       the report
  IEEEtran.cls   IEEE class file, version 1.8b
  figs/          every figure used by main.tex

Build
  pdflatex main.tex
  pdflatex main.tex      (second run resolves figure, table and reference numbers)

Overleaf: upload this ZIP as a new project; the compiler is pdfLaTeX and the main file is main.tex.

Where the figures come from
  fig_oss_groups.png, fig_oss_reach.png, fig_oss_plans.png
      drawn by bench/oss_figures.py in the project repository from the saved benchmark runs
      (BENCH-Windows.bat / bench.sh produce the same charts in results/opensource/figures/)
  fig_discovery.png, fig_curve.png, fig_stress.png
      drawn from results/tables.md and results/stress/ in the repository
  fig_threatgraph.png, fig_fixcard.png
      screenshots of ATG's threat graph page and hardening report for ShopLite
  fig_architecture.png
      the system architecture diagram

Word version
  make_docx.py builds main.docx from main.tex and main.aux (run pdflatex first; needs pandoc):
    python3 make_docx.py

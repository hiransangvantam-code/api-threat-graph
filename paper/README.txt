Automatic API Security Design Review for Microservices Using Threat Graph Analysis
LaTeX source of the full report (IEEE conference format, two columns).

Files
  main.tex       the report
  IEEEtran.cls   IEEE class file, version 1.8b
  figs/          every figure used by main.tex

Build
  pdflatex main.tex
  pdflatex main.tex      (second run resolves figure, table and reference numbers)

Overleaf: upload this folder (or the ZIP) as a new project; the compiler is pdfLaTeX and the main file is main.tex.

Where the figures come from (all from runs on the ten open-source systems)
  fig_oss_groups.png, fig_oss_reach.png
      bench/oss_figures.py (BENCH-Windows.bat / bench.sh draw the same charts in results/opensource/figures/)
  fig_window.png, fig_fixes.png, fig_stress_oss.png, fig_oss_plans.png
      bench/oss_report.py, from results/opensource/eval/ (results/opensource/eval/figures/)
  fig_threatgraph_boa.png, fig_fixcard_boa.png
      screenshots of ATG's threat graph page and hardening report for Bank of Anthos
  fig_architecture.png
      the system architecture diagram

Word version
  make_docx.py builds main.docx from main.tex and main.aux (run pdflatex first; needs pandoc):
    python3 make_docx.py
Section V alone, as pages and one picture per figure and table
  python3 make_eval.py

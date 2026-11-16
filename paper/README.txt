Automatic API Security Design Review for Microservices Using Threat Graph Analysis
LaTeX source of the full report (IEEE conference format, two columns).

Files
  ATG-Full-Report.pdf, ATG-Full-Report.docx   the built report (PDF and Word)
  ATG-Section-V-Evaluation.pdf               Section V on its own
  main.tex       the report
  IEEEtran.cls   IEEE class file, version 1.8b
  figs/          every figure used by main.tex
  gen_sec5.py, mdtab.py, sec5_template.tex   write Section V from the BENCH page

Build
  pdflatex main.tex
  pdflatex main.tex      (second run resolves figure, table and reference numbers)

Overleaf: upload this folder (or the ZIP) as a new project; the compiler is pdfLaTeX and the main file is main.tex.

Where the figures come from
  Section V reproduces the comparison page that BENCH writes (results/opensource/comparison.html):
  every table and chart on it, from one DEMO-ALL run and one BENCH run on the ten open-source systems.
  fig_speed.png, fig_cpu.png, fig_memory.png, fig_oss_groups.png, fig_systems_grid.png,
  fig_systems_covered.png, fig_services.png, fig_languages.png
      bench/oss_figures.py, run by BENCH-Windows.bat / bench.sh; the same charts are in
      results/opensource/figures/ as fig4_speed.png, fig6a_cpu.png, fig6b_memory.png,
      fig1_groups_column.png, fig2_systems_grid.png, fig3a_systems.png, fig3b_services.png and
      fig3c_languages.png (one-column versions of the page's charts)
  fig_threatgraph_boa.png, fig_fixcard_boa.png
      screenshots of ATG's threat graph page and hardening report for Bank of Anthos
  fig_architecture.png
      the system architecture diagram

Section V from a new BENCH run
  After DEMO-ALL and BENCH, rewrite Section V from the new comparison page and charts:
    python3 gen_sec5.py        (uses sec5_template.tex and mdtab.py; edits main.tex, copies the charts)
  The tables are filled from results/opensource/comparison.md. The paragraphs are in sec5_template.tex
  and quote numbers from this run, so read them again after a new run.

Word version
  make_docx.py builds main.docx from main.tex and main.aux (run pdflatex first; needs pandoc):
    python3 make_docx.py
Section V alone, as pages and one picture per figure and table
  python3 make_eval.py

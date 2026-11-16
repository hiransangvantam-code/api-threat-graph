#!/bin/sh
# The comparison with eight other tools on the ten open-source systems (macOS / Linux):
#   sh demo-all.sh      first: ATG reviews the ten systems (results/opensource/atg-laptop/)
#   sh bench.sh         then: Checkov, Kubescape, kube-linter, Polaris, Spectral, Bandit, gosec and
#                       njsscan run on the same ten systems, everything is scored against the same labels,
#                       and results/opensource/comparison.html shows every chart and table
# Needs only Docker and internet (the first run builds the tools image, about 5-10 minutes).
cd "$(dirname "$0")" || exit 1
fail() { echo; echo "Stopped: $1"; exit 1; }
docker info >/dev/null 2>&1 || fail "Docker is not running."
ls results/opensource/atg-laptop/*.json >/dev/null 2>&1 || fail "no ATG results yet: run sh demo-all.sh first"
echo "== 1/4 Build the tools image (first time: 5-10 minutes)"
docker build -q -t atg-bench-tools -f bench/tools.Dockerfile . >/dev/null || fail "the tools image did not build"
R="docker run --rm -v $PWD:/work -w /work atg-bench-tools"
echo "== 2/4 Run the eight tools on the ten systems (a few minutes)"
$R python bench/run_tools.py || fail "the tools"
echo "== 3/4 Score ATG and the tools against the same labels"
$R python bench/compare_tools.py --atg laptop || fail "the scoring"
echo "== 4/4 Draw the charts"
$R python bench/oss_figures.py --atg laptop || fail "the charts"
echo
echo "Done. Open results/opensource/comparison.html (charts and tables); the tables are also in comparison.md."

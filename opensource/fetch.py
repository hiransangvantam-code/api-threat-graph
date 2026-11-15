"""
Download the ten open-source systems at the exact commits the benchmark used.

    python opensource/fetch.py              all ten
    python opensource/fetch.py bookinfo     only these

Each system goes to opensource/<id>/upstream/ (not part of this repository: their code, and
the demo keys and passwords some of them ship, stay in their own projects). Needs git and
internet access to github.com.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
SYSTEMS = ["online-boutique", "bank-of-anthos", "robot-shop", "acme-air", "petclinic", "piggymetrics",
           "lakeside-mutual", "ftgo", "hotel-reservation", "bookinfo"]


def git(*args, cwd=None):
    subprocess.run(["git", *args], cwd=cwd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def fetch(repo: str, commit: str, dest: Path, sparse: str | None = None) -> None:
    if (dest / ".git").exists() and subprocess.run(["git", "rev-parse", "HEAD"], cwd=dest, capture_output=True,
                                                   text=True).stdout.strip() == commit:
        return
    dest.mkdir(parents=True, exist_ok=True)
    git("init", "-q", cwd=dest)
    subprocess.run(["git", "remote", "remove", "origin"], cwd=dest, capture_output=True)
    git("remote", "add", "origin", repo, cwd=dest)
    if sparse:
        git("sparse-checkout", "set", sparse, cwd=dest)
    git("fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", commit, cwd=dest)
    git("checkout", "-q", "FETCH_HEAD", cwd=dest)


def main() -> int:
    for sid in sys.argv[1:] or SYSTEMS:
        up = yaml.safe_load((HERE / sid / "system.yaml").read_text(encoding="utf-8"))["upstream"]
        root = HERE / sid / "upstream"
        repos = up.get("repos") or [{"repo": up["repo"], "commit": up["commit"], "dir": "."}]
        for r in repos:
            print(f"{sid}: {r['repo']} @ {r['commit'][:7]}", flush=True)
            fetch(r["repo"], r["commit"], root / r.get("dir", "."), up.get("sparse"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

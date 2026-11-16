"""Download the four tool binaries of the benchmark from their GitHub releases (used by tools.Dockerfile)."""
import io
import os
import sys
import tarfile
import urllib.request
from pathlib import Path

GH = "https://github.com"
FILES = [
    ("kubescape", f"{GH}/kubescape/kubescape/releases/download/v3.0.18/kubescape-ubuntu-latest", None),
    ("kube-linter", f"{GH}/stackrox/kube-linter/releases/download/v0.7.1/kube-linter-linux.tar.gz", "kube-linter"),
    ("polaris", f"{GH}/FairwindsOps/polaris/releases/download/9.6.1/polaris_linux_amd64.tar.gz", "polaris"),
    ("gosec", f"{GH}/securego/gosec/releases/download/v2.21.4/gosec_2.21.4_linux_amd64.tar.gz", "gosec"),
]

out = Path(sys.argv[1] if len(sys.argv) > 1 else "bin")
out.mkdir(parents=True, exist_ok=True)
for name, url, member in FILES:
    print(f"downloading {name}: {url}", flush=True)
    data = urllib.request.urlopen(url, timeout=300).read()
    if member:
        with tarfile.open(fileobj=io.BytesIO(data)) as t:
            m = next(x for x in t.getmembers() if os.path.basename(x.name) == member)
            data = t.extractfile(m).read()
    (out / name).write_bytes(data)
    (out / name).chmod(0o755)
print("done")

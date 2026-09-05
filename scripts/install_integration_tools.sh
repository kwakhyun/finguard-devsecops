#!/usr/bin/env bash
set -euo pipefail

# Official, versioned releases. Install only into the caller-selected directory.
tool_dir="${1:?usage: install_integration_tools.sh TOOL_DIRECTORY}"
mkdir -p "$tool_dir"
tool_dir="$(cd "$tool_dir" && pwd)"
case "$(uname -s)" in
  Darwin) tool_os=darwin ;;
  Linux) tool_os=linux ;;
  *) echo 'Supported systems: macOS and Linux' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  arm64|aarch64) tool_arch=arm64 ;;
  x86_64) tool_arch=amd64 ;;
  *) echo 'Supported architectures: arm64 and amd64' >&2; exit 1 ;;
esac

curl -fsSL --retry 2 "https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-${tool_os}-${tool_arch}" -o "$tool_dir/kind"
curl -fsSL --retry 2 "https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-${tool_os}-${tool_arch}.sha256sum" -o "$tool_dir/kind.sha256"
curl -fsSL --retry 2 "https://dl.k8s.io/release/v1.35.8/bin/${tool_os}/${tool_arch}/kubectl" -o "$tool_dir/kubectl"
curl -fsSL --retry 2 "https://dl.k8s.io/release/v1.35.8/bin/${tool_os}/${tool_arch}/kubectl.sha256" -o "$tool_dir/kubectl.sha256"
curl -fsSL --retry 2 "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-${tool_os}-${tool_arch}" -o "$tool_dir/cosign"
curl -fsSL --retry 2 'https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign_checksums.txt' -o "$tool_dir/cosign.sha256"

python3 - "$tool_dir" "$tool_os" "$tool_arch" <<'PY'
import hashlib
import sys
from pathlib import Path

directory, system, arch = sys.argv[1:]
for tool in ('kind', 'kubectl', 'cosign'):
    target = Path(directory) / tool
    checksums = target.with_suffix('.sha256').read_text()
    if tool == 'cosign':
        checksums = next(line for line in checksums.splitlines()
                         if line.split()[-1] == f'cosign-{system}-{arch}')
    expected = checksums.split()[0]
    if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
        raise SystemExit(f'Checksum mismatch: {tool}')
    target.chmod(0o755)
    print(f'{tool}: SHA-256 verified')
PY

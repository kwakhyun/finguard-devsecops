#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${project_dir}"

python_candidate="${FINGUARD_PYTHON:-${project_dir}/.venv/bin/python}"
if [[ "${python_candidate}" == */* ]]; then
  python_bin="${python_candidate}"
else
  python_bin="$(command -v -- "${python_candidate}" || true)"
fi
if [[ -z "${python_bin}" || ! -x "${python_bin}" ]]; then
  echo "FinGuard Python executable not found: ${python_candidate}" >&2
  echo "Create .venv as documented or set FINGUARD_PYTHON." >&2
  exit 3
fi

mkdir -p "${project_dir}/build"
demo_output="$(mktemp -d "${project_dir}/build/demo-evidence.XXXXXX")"
export FINGUARD_DEMO_SIGNING_KEY="${FINGUARD_DEMO_SIGNING_KEY:-local-demo-only-do-not-reuse}"

case "${1:-}" in
  "") "${python_bin}" -m pytest -q ;;
  --skip-tests) ;;
  *) echo "Usage: $0 [--skip-tests]" >&2; exit 3 ;;
esac
"${python_bin}" -m finguard scan source --workspace . --output build/reports/native
"${python_bin}" -m finguard scan lint --workspace . --output build/reports/native
"${python_bin}" -m finguard scan dependencies --workspace . --output build/reports/native
"${python_bin}" -m finguard demo \
  --scenario pass \
  --output "${demo_output}" \
  --signing-key-env FINGUARD_DEMO_SIGNING_KEY \
  --signing-key-id local-demo-v1
"${python_bin}" -m finguard verify \
  --evidence "${demo_output}/pass" \
  --signing-key-env FINGUARD_DEMO_SIGNING_KEY

set +e
"${python_bin}" -m finguard demo --scenario fail --output "${demo_output}"
fail_code=$?
set -e
if [[ "${fail_code}" -ne 2 ]]; then
  echo "Expected blocked scenario to exit with code 2; got ${fail_code}" >&2
  exit 1
fi

echo "FinGuard E2E demo completed: PASS evidence verified and risky release blocked."
echo "Evidence: ${demo_output}"

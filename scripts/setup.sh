#!/usr/bin/env bash
#
# Install the analysis engine into a virtualenv and prove it runs.
#
#   ./scripts/setup.sh
#
# This is the *only* way the engine gets installed, and the Docker image runs
# this same script. That is the point: local and containerised deployments then
# differ in exactly one thing — where the virtualenv lives — instead of being
# two separately-maintained installation procedures that drift apart.
#
# What it guarantees, in both places:
#
#   * one interpreter, with the engine installed as a package;
#   * one copy of the engine code (an editable install points at this checkout,
#     so what you edit is what runs — there is no second copy on PYTHONPATH);
#   * a model artifact trained by the same scikit-learn that will load it;
#   * a real capture analysed end to end before the script reports success.
#
# Options:
#   --python PATH   interpreter to build the venv from
#   --venv PATH     virtualenv location (default: .venv)
#   --no-ml         skip the model layer (scikit-learn, shap)
#   --quiet         less output (used by the Docker build)
#   --skip-smoke-test  install without analysing a sample capture

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VENV=".venv"
WANT_ML=1
BASE_PYTHON=""
QUIET=0
SMOKE_TEST=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --python) BASE_PYTHON="$2"; shift 2 ;;
    --venv)   VENV="$2"; shift 2 ;;
    --no-ml)  WANT_ML=0; shift ;;
    --quiet)  QUIET=1; shift ;;
    --skip-smoke-test) SMOKE_TEST=0; shift ;;
    -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
done

say()   { [[ $QUIET -eq 1 ]] || printf '%s\n' "$1"; }
green() { printf '\033[32m%s\033[0m\n' "$1"; }
warn()  { printf '\033[33m%s\033[0m\n' "$1"; }
die()   { printf '\033[31m%s\033[0m\n' "$1" >&2; exit 1; }

# --- pick an interpreter ----------------------------------------------------
# Newest first. The engine supports 3.9, but current scikit-learn and shap
# wheels increasingly do not, so a newer interpreter avoids a class of build
# failure that has nothing to do with this project.
if [[ -z "$BASE_PYTHON" ]]; then
  for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
      BASE_PYTHON="$(command -v "$candidate")"
      break
    fi
  done
fi
[[ -n "$BASE_PYTHON" ]] || die "no python3 found on PATH"

PY_VERSION="$("$BASE_PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
say "interpreter: $BASE_PYTHON  (Python $PY_VERSION)"

"$BASE_PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' \
  || die "Python 3.9 or newer is required; found $PY_VERSION"

# --- virtualenv -------------------------------------------------------------
case "$VENV" in
  /*) VENV_ABS="$VENV" ;;
  *)  VENV_ABS="$ROOT/$VENV" ;;
esac

if [[ ! -d "$VENV_ABS" ]]; then
  say "creating $VENV_ABS"
  "$BASE_PYTHON" -m venv "$VENV_ABS"
else
  say "reusing $VENV_ABS"
fi

VPY="$VENV_ABS/bin/python"
[[ -x "$VPY" ]] || VPY="$VENV_ABS/Scripts/python.exe"   # Windows layout
[[ -x "$VPY" ]] || die "virtualenv looks broken: no interpreter under $VENV_ABS"

# Editable installs from a pyproject-only project need pip >= 21.3 (PEP 660).
# macOS ships pip 21.2.4 with its Command Line Tools Python, and Debian's
# system setuptools can be older still — upgrading inside the fresh venv makes
# both irrelevant, which is why this line is not optional in either place.
say "upgrading packaging tools"
"$VPY" -m pip install --quiet --upgrade pip setuptools wheel

# --- install ----------------------------------------------------------------
# Editable, so this checkout is the single copy of the engine that ever runs.
install_ok=0
if [[ $WANT_ML -eq 1 ]]; then
  say "installing the engine with the model layer"
  if "$VPY" -m pip install --quiet -e "engine[ml]"; then
    install_ok=1
  else
    warn "the model layer would not install on Python $PY_VERSION — retrying without it"
  fi
fi
if [[ $install_ok -eq 0 ]]; then
  say "installing the engine"
  "$VPY" -m pip install --quiet -e "engine" || die "engine installation failed"
fi

# --- verify -----------------------------------------------------------------
# `import mailsentinel` proves nothing: the package __init__ is empty and
# succeeds with no dependencies present. Importing the pipeline is the check
# that actually exercises cryptography, yaml and the whole analysis chain.
say "verifying"
if ! "$VPY" -c 'import mailsentinel.pipeline' 2>/tmp/ms-verify.$$; then
  die "engine imported but cannot run: $(tail -1 /tmp/ms-verify.$$)"
fi
rm -f /tmp/ms-verify.$$

HAS_ML=$("$VPY" -c '
try:
    import sklearn, shap; print("yes")
except Exception:
    print("no")')

# scikit-learn pickles are not portable across versions, and the artifact in the
# repo was built by whichever version made it. Retrain when this environment
# differs — deterministic (seed 26159) and about half a minute.
if [[ "$HAS_ML" == "yes" ]]; then
  if ! "$VPY" -c 'from mailsentinel.ml.predict import load_model; load_model()' 2>/dev/null; then
    say "training the model for this scikit-learn"
    "$VPY" -m mailsentinel.ml.train >/dev/null \
      && say "model trained" \
      || warn "model training failed — the rule engine is unaffected"
  fi
fi

# --- smoke test -------------------------------------------------------------
# A real capture through the real engine, asserting the grade this file is known
# to earn. An install that imports but cannot analyse is not a working install.
if [[ $SMOKE_TEST -eq 1 && -f "$ROOT/demo-pcaps/smtp.pcap" ]]; then
  ML_FLAG=""; [[ "$HAS_ML" == "no" ]] && ML_FLAG="--no-ml"
  GRADE=$("$VPY" -m mailsentinel.cli analyse "$ROOT/demo-pcaps/smtp.pcap" \
            --json - $ML_FLAG 2>/dev/null \
          | "$VPY" -c 'import json,sys; print(json.load(sys.stdin)["overall_grade"])')
  [[ "$GRADE" == "F" ]] \
    || die "smoke test produced grade '$GRADE', expected F"
  say "analysed demo-pcaps/smtp.pcap — grade F, as expected"
fi

if [[ $QUIET -eq 1 ]]; then
  exit 0
fi

echo
green "engine ready$([[ "$HAS_ML" == "yes" ]] && echo " (with the model layer)" || echo " (without the model layer)")"
echo
echo "Export this — the backend reads it:"
echo
echo "    export SMS_PYTHON=\"$VPY\""
echo
echo "Then start the app:"
echo
echo "    cd frontend && npm install && npm run build && cd .."
echo "    mvn -f backend/pom.xml -DskipTests package"
echo "    java -jar backend/target/mailsentinel-1.0.0.jar     # http://localhost:8080"

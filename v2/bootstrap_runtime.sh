#!/bin/sh
set -eu

# Build only the hash-locked Python runtime needed by blind-v2 controls.  This
# deliberately does not fetch the legacy Qwen/WikiText assets used by the root
# regression workflow.

umask 077

CODEC_COMMIT=2e8d3b1591ee4a1ed822310f330317936871ff2b
CODEC_TREE=c0bb15784d252cd5036757bc64765c773a5f16e8
PLATFORM=
CODEC_ROOT=
RUNTIME=
PYTHON_BIN=
STAGING=
RUNTIME_PARENT=

fail() {
    printf 'V2 RUNTIME BOOTSTRAP FAIL: %s\n' "$*" >&2
    exit 1
}

validate_linux_runtime() {
    "$PYTHON_BIN" -I -B - \
        "$CODEC_ROOT/platforms/linux/scripts/runtime_safety.py" "$1" <<'PY'
import importlib.util
import json
from pathlib import Path
import sys

source = Path(sys.argv[1]).resolve(strict=True)
runtime = Path(sys.argv[2]).resolve(strict=True)
specification = importlib.util.spec_from_file_location(
    "_corelm_pinned_linux_runtime_safety", source
)
if specification is None or specification.loader is None:
    raise SystemExit("pinned Linux runtime-safety module could not be loaded")
module = importlib.util.module_from_spec(specification)
sys.modules[specification.name] = module
specification.loader.exec_module(module)
report = module.validate_existing_runtime(
    runtime, expected_version="3.12.10"
)
print(json.dumps(report, sort_keys=True))
PY
}

usage() {
    printf '%s\n' \
        'Usage: v2/bootstrap_runtime.sh --platform linux|macos \' \
        '  --codec-root PATH --runtime ABSOLUTE_PATH --python PYTHON_3_12_10'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --platform) [ "$#" -ge 2 ] || fail 'missing --platform value'; PLATFORM=$2; shift 2 ;;
        --codec-root) [ "$#" -ge 2 ] || fail 'missing --codec-root value'; CODEC_ROOT=$2; shift 2 ;;
        --runtime) [ "$#" -ge 2 ] || fail 'missing --runtime value'; RUNTIME=$2; shift 2 ;;
        --python) [ "$#" -ge 2 ] || fail 'missing --python value'; PYTHON_BIN=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) fail "unknown argument: $1" ;;
    esac
done

case "$PLATFORM" in linux|macos) ;; *) fail '--platform must be linux or macos' ;; esac
[ -n "$CODEC_ROOT" ] || fail '--codec-root is required'
[ -n "$RUNTIME" ] || fail '--runtime is required'
[ -n "$PYTHON_BIN" ] || fail '--python is required'
case "$RUNTIME" in /*) ;; *) fail '--runtime must be absolute' ;; esac
case "$RUNTIME" in /|/Users|/home|"$HOME") fail 'runtime target is too broad' ;; esac

CODEC_ROOT=$(CDPATH= cd -- "$CODEC_ROOT" && pwd -P) \
    || fail 'codec root does not exist'
[ -x "$PYTHON_BIN" ] || PYTHON_BIN=$(command -v "$PYTHON_BIN" 2>/dev/null || true)
[ -n "$PYTHON_BIN" ] && [ -x "$PYTHON_BIN" ] || fail 'Python executable not found'
"$PYTHON_BIN" -I -B -c '
import sys
raise SystemExit(0 if sys.version_info[:3] == (3, 12, 10) else 1)
' || fail 'bootstrap interpreter must be Python 3.12.10'

[ "$(git -C "$CODEC_ROOT" rev-parse HEAD)" = "$CODEC_COMMIT" ] \
    || fail 'codec commit differs from the registered v2 commit'
[ "$(git -C "$CODEC_ROOT" rev-parse 'HEAD^{tree}')" = "$CODEC_TREE" ] \
    || fail 'codec tree differs from the registered v2 tree'
[ -z "$(git -C "$CODEC_ROOT" status --porcelain --untracked-files=no)" ] \
    || fail 'tracked codec worktree files are modified'

[ ! -e "$RUNTIME" ] && [ ! -L "$RUNTIME" ] \
    || fail 'runtime destination already exists; refusing to overwrite it'
RUNTIME_PARENT=$(dirname -- "$RUNTIME")
if [ ! -e "$RUNTIME_PARENT" ]; then
    mkdir -p -- "$RUNTIME_PARENT"
    chmod 700 "$RUNTIME_PARENT"
fi
[ -d "$RUNTIME_PARENT" ] && [ ! -L "$RUNTIME_PARENT" ] \
    || fail 'runtime parent must be a non-symlink directory'
STAGING=$(mktemp -d "$RUNTIME_PARENT/.corelm-v2-runtime-stage.XXXXXX") \
    || fail 'could not create runtime staging directory'

cleanup() {
    if [ -n "$STAGING" ]; then
        case "$STAGING" in
            "$RUNTIME_PARENT"/.corelm-v2-runtime-stage.*)
                [ ! -e "$STAGING" ] || rm -rf -- "$STAGING"
                ;;
            *) printf 'V2 RUNTIME CLEANUP REFUSED: %s\n' "$STAGING" >&2 ;;
        esac
    fi
}
on_signal() {
    trap - EXIT HUP INT TERM
    cleanup
    exit 130
}
trap cleanup EXIT
trap on_signal HUP INT TERM

# A safe standalone interpreter remains linked so its relocatable layout is
# preserved.  actions/setup-python may instead expose a hosted-toolcache or
# framework target whose owner/mode chain fails the pinned codec checks; only
# that case uses a self-contained launcher copy.  This probe mirrors both
# platform implementations' physical-path policy.
if "$PYTHON_BIN" -I -B - <<'PY'
import os
from pathlib import Path
import stat
import sys

allowed_owners = {0, os.getuid()}
target = Path(sys.executable).resolve(strict=True)
target_status = target.lstat()
safe = (
    stat.S_ISREG(target_status.st_mode)
    and not stat.S_ISLNK(target_status.st_mode)
    and target_status.st_uid in allowed_owners
    and not target_status.st_mode & 0o022
)
current = target.parent
while safe:
    status = current.lstat()
    safe = (
        stat.S_ISDIR(status.st_mode)
        and not stat.S_ISLNK(status.st_mode)
        and status.st_uid in allowed_owners
        and not status.st_mode & 0o022
    )
    if current == Path("/"):
        break
    current = current.parent
raise SystemExit(0 if safe else 1)
PY
then
    "$PYTHON_BIN" -I -B -m venv "$STAGING"
else
    if [ "$PLATFORM" = macos ]; then
        "$PYTHON_BIN" -I -B -m venv --copies "$STAGING"
    else
        fail 'Linux base Python has an unsafe owner/mode chain; harden or replace it'
    fi
fi
RUNTIME_PYTHON="$STAGING/bin/python"
"$RUNTIME_PYTHON" -I -B -m pip install \
    --isolated --no-input --disable-pip-version-check --no-cache-dir \
    --only-binary=:all: --index-url https://pypi.org/simple \
    --require-hashes -r "$CODEC_ROOT/.github/locks/pip-bootstrap.txt"

if [ "$PLATFORM" = linux ]; then
    [ "$(uname -s)" = Linux ] || fail 'linux bootstrap requires Linux'
    [ "$(uname -m)" = x86_64 ] || fail 'linux bootstrap requires x86_64'
    "$RUNTIME_PYTHON" -I -B -m pip install \
        --isolated --no-input --disable-pip-version-check --no-cache-dir \
        --no-deps --only-binary=:all: --index-url https://pypi.org/simple \
        --require-hashes -r "$CODEC_ROOT/.github/locks/real-llm-linux-cpu-py312.txt"
    "$RUNTIME_PYTHON" -I -B -m pip install \
        --isolated --no-input --disable-pip-version-check --no-cache-dir \
        --no-deps --only-binary=:all: --index-url https://download.pytorch.org/whl/cpu \
        --require-hashes -r "$CODEC_ROOT/.github/locks/torch-linux-cpu-py312.txt"
    "$PYTHON_BIN" -I -B \
        "$CODEC_ROOT/platforms/linux/scripts/runtime_safety.py" initialize-runtime \
        --runtime "$STAGING" >/dev/null
    validate_linux_runtime "$STAGING" >/dev/null
else
    [ "$(uname -s)" = Darwin ] || fail 'macos bootstrap requires macOS'
    [ "$(uname -m)" = arm64 ] || fail 'macos bootstrap requires Apple Silicon arm64'
    "$RUNTIME_PYTHON" -I -B -m pip install \
        --isolated --no-input --disable-pip-version-check --no-cache-dir \
        --only-binary=:all: --index-url https://pypi.org/simple \
        --require-hashes -r "$CODEC_ROOT/RealLLM/requirements.lock"
    "$PYTHON_BIN" -I -B "$CODEC_ROOT/security/manage_local_runtime.py" \
        --path "$STAGING" --project "$CODEC_ROOT" --mode initialize >/dev/null
    [ "$("$PYTHON_BIN" -I -B "$CODEC_ROOT/security/manage_local_runtime.py" \
        --path "$STAGING" --project "$CODEC_ROOT" --mode preflight)" = existing ] \
        || fail 'staged macOS runtime marker validation failed'
fi

"$RUNTIME_PYTHON" -I -B -m pip check
if [ "$PLATFORM" = linux ]; then
    "$RUNTIME_PYTHON" -I -B "$CODEC_ROOT/security/verify_locked_environment.py" \
        --runtime "$STAGING" \
        --lock "$CODEC_ROOT/.github/locks/pip-bootstrap.txt" \
        --lock "$CODEC_ROOT/.github/locks/real-llm-linux-cpu-py312.txt" \
        --lock "$CODEC_ROOT/.github/locks/torch-linux-cpu-py312.txt"
else
    "$RUNTIME_PYTHON" -I -B "$CODEC_ROOT/security/verify_locked_environment.py" \
        --runtime "$STAGING" \
        --lock "$CODEC_ROOT/.github/locks/pip-bootstrap.txt" \
        --lock "$CODEC_ROOT/RealLLM/requirements.lock"
fi

if [ "$PLATFORM" = linux ]; then
    "$PYTHON_BIN" -I -B \
        "$CODEC_ROOT/platforms/linux/scripts/runtime_safety.py" publish-runtime \
        --staging "$STAGING" --destination "$RUNTIME" >/dev/null
else
    mv -- "$STAGING" "$RUNTIME"
fi
STAGING=

if [ "$PLATFORM" = linux ]; then
    validate_linux_runtime "$RUNTIME" >/dev/null
else
    [ "$("$PYTHON_BIN" -I -B "$CODEC_ROOT/security/manage_local_runtime.py" \
        --path "$RUNTIME" --project "$CODEC_ROOT" --mode preflight)" = existing ] \
        || fail 'published macOS runtime marker validation failed'
fi

"$RUNTIME/bin/python" -I -B -c '
import pathlib
import sys
expected = pathlib.Path(sys.argv[1]).resolve(strict=True)
actual = pathlib.Path(sys.prefix).resolve(strict=True)
if actual != expected or sys.version_info[:3] != (3, 12, 10):
    raise SystemExit(f"published runtime identity differs: {actual}")
' "$RUNTIME"

printf '%s\n' \
    'V2 RUNTIME BOOTSTRAP PASS' \
    "Platform: $PLATFORM" \
    "Runtime: $RUNTIME" \
    'Legacy model/data assets were not downloaded.'

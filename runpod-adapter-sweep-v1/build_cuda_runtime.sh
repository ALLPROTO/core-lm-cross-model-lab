#!/bin/sh
set -eu

# Build the exact CUDA runtime in private staging and publish it atomically.
# The codec checkout supplies the pinned CPython bootstrap, portable dependency
# lock, runtime-safety implementation, and installed-closure verifier.

umask 077

CODEC_ROOT=${CORELM_SWEEP_CODEC_ROOT:-}
RUNTIME_DIR=${CORELM_SWEEP_RUNTIME:-}
EXPECTED_SWEEP_COMMIT=${CORELM_SWEEP_EXPECTED_COMMIT:-}
EXPECTED_SWEEP_TREE=${CORELM_SWEEP_EXPECTED_TREE:-}
EXPECTED_CODEC_COMMIT=e7e0504b15769c925206ad1783d45a9ca0b62207
EXPECTED_CODEC_TREE=924d3195122e3a486e2d26e4fbdfe574654ae6c8
SAFETY_SCRIPT=
VERIFY_LOCKS=
STAGING_DIR=
RUNTIME_PARENT=
PUBLISHED_DIR=
BUILD_COMPLETE=0

# Re-exec before invoking any external command with a minimal environment.
# RunPod may inject provider and Hugging Face credentials into every Pod
# process; runtime construction never needs either credential.  The first
# /bin/sh performs only shell assignments and this exec, so no bootstrap, Git,
# pip, or validation child can inherit those secrets.
if [ "${1:-}" != --corelm-sanitized ]; then
    exec /usr/bin/env -i \
        HOME="${HOME:-/tmp}" \
        PATH=/usr/local/cuda/bin:/usr/bin:/bin \
        LANG=C.UTF-8 \
        LC_ALL=C.UTF-8 \
        TZ=UTC \
        PYTHONDONTWRITEBYTECODE=1 \
        PYTHONNOUSERSITE=1 \
        HF_HUB_DISABLE_TELEMETRY=1 \
        HF_HUB_DISABLE_IMPLICIT_TOKEN=1 \
        DO_NOT_TRACK=1 \
        CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0}" \
        CUDA_HOME=/usr/local/cuda \
        LD_LIBRARY_PATH=/usr/local/cuda/lib64:/usr/local/cuda/compat \
        GIT_CONFIG_GLOBAL=/dev/null \
        GIT_CONFIG_NOSYSTEM=1 \
        CORELM_SWEEP_CODEC_ROOT="$CODEC_ROOT" \
        CORELM_SWEEP_RUNTIME="$RUNTIME_DIR" \
        CORELM_SWEEP_EXPECTED_COMMIT="$EXPECTED_SWEEP_COMMIT" \
        CORELM_SWEEP_EXPECTED_TREE="$EXPECTED_SWEEP_TREE" \
        /bin/sh "$0" --corelm-sanitized
fi
shift
[ "$#" -eq 0 ] || {
    printf 'CUDA RUNTIME BUILD FAIL: unexpected arguments\n' >&2
    exit 2
}
[ -z "${HF_TOKEN+x}${HUGGING_FACE_HUB_TOKEN+x}${RUNPOD_API_KEY+x}${GITHUB_TOKEN+x}${AWS_ACCESS_KEY_ID+x}${AWS_SECRET_ACCESS_KEY+x}${SSH_AUTH_SOCK+x}${BASH_ENV+x}${ENV+x}${LD_PRELOAD+x}" ] || {
    printf 'CUDA RUNTIME BUILD FAIL: sanitized environment contains a credential or startup hook\n' >&2
    exit 1
}
observed_environment=$(
    /usr/bin/env | /usr/bin/cut -d= -f1 | \
        /usr/bin/grep -Ev '^(SHLVL|_)$' | /usr/bin/sort
)
expected_environment='CORELM_SWEEP_CODEC_ROOT
CORELM_SWEEP_EXPECTED_COMMIT
CORELM_SWEEP_EXPECTED_TREE
CORELM_SWEEP_RUNTIME
CUDA_HOME
CUDA_VISIBLE_DEVICES
DO_NOT_TRACK
GIT_CONFIG_GLOBAL
GIT_CONFIG_NOSYSTEM
HF_HUB_DISABLE_IMPLICIT_TOKEN
HF_HUB_DISABLE_TELEMETRY
HOME
LANG
LC_ALL
LD_LIBRARY_PATH
PATH
PWD
PYTHONDONTWRITEBYTECODE
PYTHONNOUSERSITE
TZ'
[ "$observed_environment" = "$expected_environment" ] || {
    printf 'CUDA RUNTIME BUILD FAIL: sanitized environment contains an unregistered name\n' >&2
    exit 1
}
unset observed_environment expected_environment
[ "$PATH" = /usr/local/cuda/bin:/usr/bin:/bin ] && \
[ "$LANG" = C.UTF-8 ] && [ "$LC_ALL" = C.UTF-8 ] && [ "$TZ" = UTC ] && \
[ "$PYTHONDONTWRITEBYTECODE" = 1 ] && [ "$PYTHONNOUSERSITE" = 1 ] && \
[ "$HF_HUB_DISABLE_TELEMETRY" = 1 ] && [ "$HF_HUB_DISABLE_IMPLICIT_TOKEN" = 1 ] && \
[ "$DO_NOT_TRACK" = 1 ] && [ "$CUDA_VISIBLE_DEVICES" = 0 ] && \
[ "$CUDA_HOME" = /usr/local/cuda ] && \
[ "$LD_LIBRARY_PATH" = /usr/local/cuda/lib64:/usr/local/cuda/compat ] && \
[ "$GIT_CONFIG_GLOBAL" = /dev/null ] && [ "$GIT_CONFIG_NOSYSTEM" = 1 ] || {
    printf 'CUDA RUNTIME BUILD FAIL: sanitized environment value differs\n' >&2
    exit 1
}
case "$EXPECTED_SWEEP_COMMIT:$EXPECTED_SWEEP_TREE" in
    *[!0-9a-f:]*) printf 'CUDA RUNTIME BUILD FAIL: expected source identity is invalid\n' >&2; exit 1 ;;
esac
case "$EXPECTED_SWEEP_COMMIT:$EXPECTED_SWEEP_TREE" in
    ????????????????????????????????????????:????????????????????????????????????????) ;;
    *) printf 'CUDA RUNTIME BUILD FAIL: expected source identity length is invalid\n' >&2; exit 1 ;;
esac

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
SWEEP_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)

fail() {
    printf 'CUDA RUNTIME BUILD FAIL: %s\n' "$*" >&2
    exit 1
}

verify_source_signature() {
    signature_root=$1
    signature_path=$2
    signature_commit=$3
    allowed_signers="$signature_root/$signature_path"
    [ -f "$allowed_signers" ] && [ ! -L "$allowed_signers" ] \
        || fail 'a commit-signature trust root is absent or unsafe'
    [ "$(sha256sum "$allowed_signers" | awk '{print $1}')" = "$TRUST_ROOT_SHA256" ] \
        || fail 'a commit-signature trust root differs'
    git -C "$signature_root" \
        -c gpg.ssh.allowedSignersFile="$allowed_signers" \
        -c gpg.ssh.program=/usr/bin/ssh-keygen \
        verify-commit "$signature_commit" >/dev/null 2>&1 \
        || fail 'source commit signature verification failed'
}

verify_raw_worktree() {
    raw_root=$1
    raw_paths=$(git -C "$raw_root" ls-tree -r --name-only HEAD) \
        || fail 'cannot enumerate signed-tree source files'
    [ -n "$raw_paths" ] || fail 'source checkout has no tracked files'
    raw_old_ifs=$IFS
    IFS='
'
    set -f
    for raw_relative in $raw_paths
    do
        case "$raw_relative" in
            *"	"*|*""*) fail 'tracked source path contains control whitespace' ;;
        esac
        [ -f "$raw_root/$raw_relative" ] && [ ! -L "$raw_root/$raw_relative" ] \
            || fail "tracked source is absent or not regular: $raw_relative"
        raw_index=$(git -C "$raw_root" ls-tree \
            --format='%(objectmode) %(objecttype) %(objectname)' \
            HEAD -- "$raw_relative") \
            || fail 'cannot inspect a signed-tree source entry'
        raw_mode=${raw_index%% *}
        raw_tail=${raw_index#* }
        raw_type=${raw_tail%% *}
        [ "$raw_type" = blob ] || fail 'signed-tree source entry is not a blob'
        raw_tail=${raw_tail#* }
        raw_expected=${raw_tail%% *}
        case "$raw_mode" in 100644|100755) ;; *) fail 'tracked source mode is unsupported' ;; esac
        raw_observed=$(git -C "$raw_root" hash-object --no-filters -- "$raw_root/$raw_relative") \
            || fail 'cannot hash a raw tracked source file'
        [ "$raw_observed" = "$raw_expected" ] \
            || fail "raw tracked source differs from the signed tree: $raw_relative"
    done
    set +f
    IFS=$raw_old_ifs
    unset raw_root raw_paths raw_old_ifs raw_relative raw_index raw_mode raw_type raw_tail raw_expected raw_observed
}

verify_exact_checkout() {
    checkout_root=$1
    checkout_commit=$2
    checkout_tree=$3
    checkout_label=$4
    checkout_observed=$(git -C "$checkout_root" rev-parse HEAD) \
        || fail "cannot resolve $checkout_label commit"
    [ "$checkout_observed" = "$checkout_commit" ] || fail "$checkout_label commit differs"
    checkout_observed=$(git -C "$checkout_root" rev-parse 'HEAD^{tree}') \
        || fail "cannot resolve $checkout_label tree"
    [ "$checkout_observed" = "$checkout_tree" ] || fail "$checkout_label tree differs"
    checkout_observed=$(git -C "$checkout_root" rev-parse --show-toplevel) \
        || fail "cannot resolve $checkout_label top level"
    [ "$checkout_observed" = "$checkout_root" ] || fail "$checkout_label root differs from the Git top level"
    checkout_observed=$(git -C "$checkout_root" rev-parse --absolute-git-dir) \
        || fail "cannot resolve $checkout_label git directory"
    [ -d "$checkout_observed" ] && [ ! -L "$checkout_observed" ] \
        || fail "$checkout_label git directory is unsafe"
    [ "$(stat -c '%u' -- "$checkout_root")" -eq "$(id -u)" ] \
        || fail "$checkout_label checkout is not owner controlled"
    checkout_mode=$(stat -c '%a' -- "$checkout_root")
    case "$checkout_mode" in *[2367][0-7]|*[0-7][2367]) fail "$checkout_label checkout is group/world writable" ;; esac
    checkout_branch=$(git -C "$checkout_root" rev-parse --abbrev-ref HEAD) \
        || fail "cannot inspect $checkout_label detached state"
    [ "$checkout_branch" = HEAD ] || fail "$checkout_label checkout must be detached"
    checkout_shallow=$(git -C "$checkout_root" rev-parse --is-shallow-repository) \
        || fail "cannot inspect $checkout_label shallow state"
    [ "$checkout_shallow" = false ] || fail "$checkout_label checkout must not be shallow"
    [ ! -e "$checkout_observed/shallow" ] && [ ! -e "$checkout_observed/info/grafts" ] \
        || fail "$checkout_label checkout contains shallow or graft metadata"
    checkout_replace=$(git -C "$checkout_root" for-each-ref --format='%(refname)' refs/replace) \
        || fail "cannot inspect $checkout_label replacement refs"
    [ -z "$checkout_replace" ] || fail "$checkout_label checkout contains replacement refs"
    checkout_status=$(git -C "$checkout_root" -c core.fsmonitor=false -c core.untrackedCache=false \
        status --porcelain=v1 --untracked-files=all --ignored=matching) \
        || fail "cannot inspect $checkout_label status"
    [ -z "$checkout_status" ] || fail "$checkout_label checkout is not byte-clean"
    checkout_index=$(git -C "$checkout_root" ls-files -v) \
        || fail "cannot inspect $checkout_label index flags"
    if printf '%s\n' "$checkout_index" | grep -E '^[a-zS]' >/dev/null; then
        fail "$checkout_label checkout contains assume-unchanged or skip-worktree entries"
    fi
    verify_raw_worktree "$checkout_root"
    unset checkout_root checkout_commit checkout_tree checkout_label checkout_observed checkout_mode checkout_branch checkout_shallow checkout_replace checkout_status checkout_index
}

cleanup() {
    if [ -n "$STAGING_DIR" ]; then
        case "$STAGING_DIR" in
            "$RUNTIME_PARENT"/.corelm-cuda-runtime-stage.*)
                if [ -d "$STAGING_DIR" ] && [ ! -L "$STAGING_DIR" ]; then
                    /bin/rm -rf -- "$STAGING_DIR"
                fi
                ;;
            *)
                printf 'CUDA RUNTIME CLEANUP REFUSED: %s\n' "$STAGING_DIR" >&2
                ;;
        esac
    fi
    if [ "$BUILD_COMPLETE" -ne 1 ] && [ -n "$PUBLISHED_DIR" ]; then
        case "$PUBLISHED_DIR" in
            "$RUNTIME_PARENT"/*)
                if [ "$PUBLISHED_DIR" = "$RUNTIME_DIR" ] && \
                   [ -d "$PUBLISHED_DIR" ] && [ ! -L "$PUBLISHED_DIR" ] && \
                   [ "$(stat -c '%u' -- "$PUBLISHED_DIR")" -eq "$(id -u)" ]; then
                    /bin/rm -rf -- "$PUBLISHED_DIR"
                fi
                ;;
            *)
                printf 'CUDA RUNTIME PUBLISHED CLEANUP REFUSED: %s\n' "$PUBLISHED_DIR" >&2
                ;;
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

[ "$HOME" = "$(readlink -f -- "$HOME")" ] && [ -d "$HOME" ] && [ ! -L "$HOME" ] \
    || fail 'HOME must be an existing canonical non-symlink directory'
[ "$(stat -c '%u' -- "$HOME")" -eq "$(id -u)" ] \
    || fail 'HOME is not owned by the current user'
home_mode=$(stat -c '%a' -- "$HOME")
case "$home_mode" in
    *[2367][0-7]|*[0-7][2367]) fail 'HOME is group/world writable' ;;
esac
unset home_mode

[ "$(uname -s)" = Linux ] || fail 'Linux is required'
[ "$(uname -m)" = x86_64 ] || fail 'x86_64 is required'
[ -n "$CODEC_ROOT" ] || fail 'CORELM_SWEEP_CODEC_ROOT is required'
[ -n "$RUNTIME_DIR" ] || fail 'CORELM_SWEEP_RUNTIME is required'
case "$CODEC_ROOT:$RUNTIME_DIR" in
    /*:/*) ;;
    *) fail 'codec and runtime paths must be absolute' ;;
esac
[ "$CODEC_ROOT" = "$(readlink -f -- "$CODEC_ROOT")" ] \
    || fail 'codec root must be canonical'
runtime_resolved=$(readlink -m -- "$RUNTIME_DIR") \
    || fail 'cannot canonicalize the runtime target'
[ "$RUNTIME_DIR" = "$runtime_resolved" ] \
    || fail 'runtime target must be canonical'
unset runtime_resolved

case "$RUNTIME_DIR" in
    "$SWEEP_ROOT"|"$SWEEP_ROOT"/*|"$CODEC_ROOT"|"$CODEC_ROOT"/*)
        fail 'runtime target overlaps a source checkout' ;;
esac

verify_exact_checkout "$SWEEP_ROOT" "$EXPECTED_SWEEP_COMMIT" "$EXPECTED_SWEEP_TREE" sweep
verify_exact_checkout "$CODEC_ROOT" "$EXPECTED_CODEC_COMMIT" "$EXPECTED_CODEC_TREE" codec

TRUST_ROOT_SHA256=36fb4a170eee7664be32f2a5d562db209fa4f6f1f24667cf6a3ef0166d155c16
verify_source_signature \
    "$SWEEP_ROOT" v4/signing/allowed_signers "$EXPECTED_SWEEP_COMMIT"
verify_source_signature \
    "$CODEC_ROOT" signing/allowed_signers "$EXPECTED_CODEC_COMMIT"
unset signature_root signature_path signature_commit allowed_signers TRUST_ROOT_SHA256

SAFETY_SCRIPT="$CODEC_ROOT/platforms/linux/scripts/runtime_safety.py"
VERIFY_LOCKS="$CODEC_ROOT/security/verify_locked_environment.py"
for required in \
    "$CODEC_ROOT/corelm" \
    "$CODEC_ROOT/.github/locks/pip-bootstrap.txt" \
    "$CODEC_ROOT/.github/locks/real-llm-linux-cpu-py312.txt" \
    "$CODEC_ROOT/platforms/linux/scripts/find-python312.sh" \
    "$SAFETY_SCRIPT" \
    "$VERIFY_LOCKS" \
    "$SCRIPT_DIR/torch-linux-cu130-py312.txt"
do
    [ -f "$required" ] && [ ! -L "$required" ] \
        || fail "required runtime input is absent or unsafe: $required"
done
unset required

[ ! -e "$RUNTIME_DIR" ] && [ ! -L "$RUNTIME_DIR" ] \
    || fail 'runtime destination must not already exist'
RUNTIME_PARENT=$(dirname -- "$RUNTIME_DIR")
if [ ! -e "$RUNTIME_PARENT" ]; then
    /usr/bin/install -d -m 700 -- "$RUNTIME_PARENT"
fi
[ -d "$RUNTIME_PARENT" ] && [ ! -L "$RUNTIME_PARENT" ] \
    || fail 'runtime parent is not a regular directory'
[ "$(readlink -f -- "$RUNTIME_PARENT")" = "$RUNTIME_PARENT" ] \
    || fail 'runtime parent must be canonical'
[ "$(stat -c '%u' -- "$RUNTIME_PARENT")" -eq "$(id -u)" ] \
    || fail 'runtime parent is not owned by the current user'
parent_mode=$(stat -c '%a' -- "$RUNTIME_PARENT")
case "$parent_mode" in
    *[2367][0-7]|*[0-7][2367]) fail 'runtime parent is group/world writable' ;;
esac
unset parent_mode

"$CODEC_ROOT/corelm" linux bootstrap
"$CODEC_ROOT/corelm" linux bootstrap --harden-installed
BASE_PYTHON=$("$CODEC_ROOT/platforms/linux/scripts/find-python312.sh") \
    || fail 'cannot resolve the pinned CPython 3.12.13 runtime'
[ -f "$BASE_PYTHON" ] && [ -x "$BASE_PYTHON" ] && [ ! -L "$BASE_PYTHON" ] \
    || fail 'resolved base Python is not a regular executable'

STAGING_DIR=$(mktemp -d "$RUNTIME_PARENT/.corelm-cuda-runtime-stage.XXXXXX") \
    || fail 'cannot create private runtime staging'
/bin/chmod 700 "$STAGING_DIR"
PYTHONDONTWRITEBYTECODE=1 \
    "$BASE_PYTHON" -I -B -m venv --copies "$STAGING_DIR"
runtime_python="$STAGING_DIR/bin/python"
[ -f "$runtime_python" ] && [ -x "$runtime_python" ] && [ ! -L "$runtime_python" ] \
    || fail 'staged venv does not contain a copied Python executable'

"$runtime_python" -I -B -m pip install \
    --isolated --no-input --disable-pip-version-check --no-cache-dir \
    --only-binary=:all: --index-url https://pypi.org/simple \
    --require-hashes \
    -r "$CODEC_ROOT/.github/locks/pip-bootstrap.txt"
"$runtime_python" -I -B -m pip install \
    --isolated --no-input --disable-pip-version-check --no-cache-dir \
    --no-deps --only-binary=:all: --index-url https://pypi.org/simple \
    --require-hashes \
    -r "$CODEC_ROOT/.github/locks/real-llm-linux-cpu-py312.txt"
"$runtime_python" -I -B -m pip install \
    --isolated --no-input --disable-pip-version-check --no-cache-dir \
    --no-deps --only-binary=:all: \
    --index-url https://download.pytorch.org/whl/cu130 \
    --extra-index-url https://pypi.org/simple \
    --require-hashes \
    -r "$SCRIPT_DIR/torch-linux-cu130-py312.txt"

"$BASE_PYTHON" -I -B "$SAFETY_SCRIPT" harden-owner-tree \
    --root "$STAGING_DIR" >/dev/null \
    || fail 'cannot harden the staged CUDA runtime'
"$BASE_PYTHON" -I -B "$SAFETY_SCRIPT" initialize-runtime \
    --runtime "$STAGING_DIR" >/dev/null \
    || fail 'cannot initialize the staged runtime marker'
"$BASE_PYTHON" -I -B "$SAFETY_SCRIPT" validate-runtime \
    --runtime "$STAGING_DIR" >/dev/null \
    || fail 'staged CUDA runtime failed path validation'
"$runtime_python" -I -B -m pip check
"$runtime_python" -I -B "$VERIFY_LOCKS" \
    --runtime "$STAGING_DIR" \
    --lock "$CODEC_ROOT/.github/locks/pip-bootstrap.txt" \
    --lock "$CODEC_ROOT/.github/locks/real-llm-linux-cpu-py312.txt" \
    --lock "$SCRIPT_DIR/torch-linux-cu130-py312.txt"
"$runtime_python" -I -B - <<'PY'
import importlib.metadata
import platform
import torch

expected = {
    "huggingface-hub": "1.25.1",
    "numpy": "2.5.1",
    "safetensors": "0.8.0",
    "tokenizers": "0.22.2",
    "torch": "2.13.0+cu130",
    "transformers": "5.14.1",
}
observed = {name: importlib.metadata.version(name) for name in expected}
if platform.python_version() != "3.12.13" or observed != expected:
    raise SystemExit("CUDA runtime identity differs from the exact lock")
if torch.__version__ != "2.13.0+cu130" or torch.version.cuda != "13.0":
    raise SystemExit("PyTorch CUDA build identity differs")
if not torch.cuda.is_available() or torch.cuda.device_count() != 1:
    raise SystemExit("exactly one CUDA device is required")
if not torch.cuda.is_bf16_supported():
    raise SystemExit("the CUDA device does not support BF16")
PY

"$CODEC_ROOT/corelm" linux bootstrap --harden-installed
PREPUBLISH_PYTHON=$("$CODEC_ROOT/platforms/linux/scripts/find-python312.sh") \
    || fail 'base Python changed before CUDA runtime publication'
[ "$PREPUBLISH_PYTHON" = "$BASE_PYTHON" ] \
    || fail 'base Python identity changed before CUDA runtime publication'
"$BASE_PYTHON" -I -B "$SAFETY_SCRIPT" publish-runtime \
    --staging "$STAGING_DIR" \
    --destination "$RUNTIME_DIR" >/dev/null \
    || fail 'cannot atomically publish the CUDA runtime'
PUBLISHED_DIR=$RUNTIME_DIR
STAGING_DIR=

runtime_python="$RUNTIME_DIR/bin/python"
"$BASE_PYTHON" -I -B "$SAFETY_SCRIPT" validate-runtime \
    --runtime "$RUNTIME_DIR" >/dev/null \
    || fail 'published CUDA runtime failed validation'
"$runtime_python" -I -B -m pip check
"$runtime_python" -I -B "$VERIFY_LOCKS" \
    --runtime "$RUNTIME_DIR" \
    --lock "$CODEC_ROOT/.github/locks/pip-bootstrap.txt" \
    --lock "$CODEC_ROOT/.github/locks/real-llm-linux-cpu-py312.txt" \
    --lock "$SCRIPT_DIR/torch-linux-cu130-py312.txt"
"$CODEC_ROOT/corelm" linux bootstrap --harden-installed
FINAL_PYTHON=$("$CODEC_ROOT/platforms/linux/scripts/find-python312.sh") \
    || fail 'base Python changed during CUDA runtime construction'
[ "$FINAL_PYTHON" = "$BASE_PYTHON" ] \
    || fail 'base Python identity changed during CUDA runtime construction'

verify_exact_checkout "$SWEEP_ROOT" "$EXPECTED_SWEEP_COMMIT" "$EXPECTED_SWEEP_TREE" sweep
verify_exact_checkout "$CODEC_ROOT" "$EXPECTED_CODEC_COMMIT" "$EXPECTED_CODEC_TREE" codec
TRUST_ROOT_SHA256=36fb4a170eee7664be32f2a5d562db209fa4f6f1f24667cf6a3ef0166d155c16
verify_source_signature \
    "$SWEEP_ROOT" v4/signing/allowed_signers "$EXPECTED_SWEEP_COMMIT"
verify_source_signature \
    "$CODEC_ROOT" signing/allowed_signers "$EXPECTED_CODEC_COMMIT"
unset signature_root signature_path signature_commit allowed_signers TRUST_ROOT_SHA256

BUILD_COMPLETE=1

printf '%s\n' \
    'CUDA RUNTIME BUILD PASS' \
    'Python: CPython 3.12.13' \
    'PyTorch: 2.13.0+cu130' \
    'CUDA: 13.0' \
    "Runtime: $RUNTIME_DIR"

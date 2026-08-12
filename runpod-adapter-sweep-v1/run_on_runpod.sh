#!/bin/bash
# Fail-closed one-shot launcher for the exploratory RunPod adapter sweep.

if [[ "$#" -ne 1 || "$1" != --corelm-clean-entry ]]; then
  printf 'RUNPOD SWEEP FAIL: use launch_runpod.py with the exact runtime and -I -B\n' >&2
  exit 2
fi
shift
if [[ -n "$(compgen -A function)" ]]; then
  printf 'RUNPOD SWEEP FAIL: the sterile entry environment imported a Bash function\n' >&2
  exit 1
fi

set -Eeuo pipefail
umask 077

fail() {
  printf 'RUNPOD SWEEP FAIL: %s\n' "$1" >&2
  exit 1
}

case "$-" in
  *x*) fail 'xtrace must be disabled because the inherited HF_TOKEN is secret' ;;
esac
(( BASH_VERSINFO[0] >= 5 )) || fail 'GNU Bash 5 or newer is required'

# Capture the very small input surface, then remove the inherited environment.
# The token remains a non-exported shell value until the downloader alone needs
# it; it is never put in argv or printed.
expected_commit=${CORELM_SWEEP_EXPECTED_COMMIT-}
expected_tree=${CORELM_SWEEP_EXPECTED_TREE-}
codec_root=${CORELM_SWEEP_CODEC_ROOT-}
python_executable=${CORELM_SWEEP_PYTHON-}
run_root=${CORELM_SWEEP_ROOT-}
image_digest=${CORELM_SWEEP_IMAGE_DIGEST-}
original_home=${HOME-}
hf_token=${HF_TOKEN-}
# If a hostile parent environment happened to export one of these lowercase
# names, assignment would retain its export attribute. Remove that attribute
# before enumerating the inherited environment so the captured values survive
# only as private shell variables.
export -n expected_commit expected_tree codec_root python_executable run_root image_digest original_home hf_token 2>/dev/null || true

mapfile -t inherited_names < <(compgen -e)
for inherited_name in "${inherited_names[@]}"; do
  export -n "$inherited_name" 2>/dev/null || true
  unset -v "$inherited_name" 2>/dev/null || true
done
unset inherited_name inherited_names

export PATH=/usr/local/cuda/bin:/usr/local/bin:/usr/bin:/bin
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export TZ=UTC
export PYTHONDONTWRITEBYTECODE=1
export PYTHONNOUSERSITE=1
export HF_HUB_DISABLE_TELEMETRY=1
export HF_HUB_DISABLE_IMPLICIT_TOKEN=1
export DO_NOT_TRACK=1
export TOKENIZERS_PARALLELISM=false
export CUDA_DEVICE_ORDER=PCI_BUS_ID
export CUDA_VISIBLE_DEVICES=0
export CUDA_HOME=/usr/local/cuda
export LD_LIBRARY_PATH=/usr/local/cuda/lib64:/usr/local/cuda/compat
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
unset BASH_ENV ENV CDPATH GLOBIGNORE HISTFILE PYTHONPATH PYTHONHOME SSH_AUTH_SOCK
ulimit -c 0 || fail 'core dumps must be disabled before handling HF_TOKEN'

cleanup_secret() {
  unset HF_TOKEN hf_token
}
trap cleanup_secret EXIT

[[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] ||
  fail 'CORELM_SWEEP_EXPECTED_COMMIT must be an exact 40-hex commit'
[[ "$expected_tree" =~ ^[0-9a-f]{40}$ ]] ||
  fail 'CORELM_SWEEP_EXPECTED_TREE must be an exact 40-hex tree'
[[ "$codec_root" = /* && -d "$codec_root" && ! -L "$codec_root" ]] ||
  fail 'CORELM_SWEEP_CODEC_ROOT must name an absolute, existing, non-symlink directory'
[[ "$python_executable" = /* && -f "$python_executable" && -x "$python_executable" ]] ||
  fail 'CORELM_SWEEP_PYTHON must name an absolute executable regular file'
[[ "$run_root" = /* && "$run_root" != / && ! -e "$run_root" && ! -L "$run_root" ]] ||
  fail 'CORELM_SWEEP_ROOT must be an absolute, previously nonexistent directory'
[[ "$image_digest" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  fail 'CORELM_SWEEP_IMAGE_DIGEST must be an immutable sha256 image digest'
[[ "$original_home" = /* && -d "$original_home" && ! -L "$original_home" ]] ||
  fail 'the original HOME must be an absolute, existing, non-symlink directory'
for input_path in "$codec_root" "$python_executable" "$run_root" "$original_home"; do
  [[ "$input_path" != *[$'\n\r\t']* ]] || fail 'input paths may not contain control whitespace'
done
unset input_path
[[ ${#hf_token} -ge 20 && "$hf_token" == hf_* && "$hf_token" != *[$' \t\r\n']* ]] ||
  fail 'a non-blank Hugging Face fine-grained read token is required via the HF_TOKEN secret'

for required_command in git ssh-keygen nvidia-smi timeout tar gzip sha256sum find grep readlink getconf df awk uname id dirname basename mkdir chmod stat tee; do
  command -v "$required_command" >/dev/null 2>&1 ||
    fail "required host command is absent: $required_command"
done
unset required_command
[[ "$(command -v timeout)" = /usr/bin/timeout ]] ||
  fail 'GNU timeout must be /usr/bin/timeout'
[[ "$(command -v tar)" = /usr/bin/tar ]] ||
  fail 'GNU tar must be /usr/bin/tar'

script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
script_dir=$(dirname -- "$script_path")
[[ "$script_path" = "$script_dir/run_on_runpod.sh" ]] ||
  fail 'launcher path resolution failed'
sweep_repo=$(git -C "$script_dir" rev-parse --show-toplevel) ||
  fail 'launcher is not inside a Git checkout'
[[ "$sweep_repo" = "$(readlink -f -- "$sweep_repo")" ]] ||
  fail 'sweep checkout traverses a symlink'
[[ "$codec_root" = "$(readlink -f -- "$codec_root")" ]] ||
  fail 'codec checkout traverses a symlink'
[[ "$python_executable" = "$(readlink -f -- "$python_executable")" ]] ||
  fail 'CORELM_SWEEP_PYTHON must be the canonical executable path, not a symlink'
[[ "$run_root" = "$(readlink -m -- "$run_root")" ]] ||
  fail 'CORELM_SWEEP_ROOT is not canonical'
runtime_root=$(dirname -- "$(dirname -- "$python_executable")")
[[ -d "$runtime_root" && ! -L "$runtime_root" && "$runtime_root" = "$(readlink -f -- "$runtime_root")" ]] ||
  fail 'CUDA runtime root is not a canonical directory'
runtime_safety="$codec_root/platforms/linux/scripts/runtime_safety.py"
verify_locks="$codec_root/security/verify_locked_environment.py"
pip_bootstrap_lock="$codec_root/.github/locks/pip-bootstrap.txt"
portable_runtime_lock="$codec_root/.github/locks/real-llm-linux-cpu-py312.txt"
cuda_runtime_lock="$script_dir/torch-linux-cu130-py312.txt"
for runtime_input in "$runtime_safety" "$verify_locks" "$pip_bootstrap_lock" "$portable_runtime_lock" "$cuda_runtime_lock"; do
  [[ -f "$runtime_input" && ! -L "$runtime_input" ]] ||
    fail 'a required runtime validation input is absent or unsafe'
done
unset runtime_input
run_parent=$(dirname -- "$run_root")
[[ -d "$run_parent" && ! -L "$run_parent" && "$run_parent" = "$(readlink -f -- "$run_parent")" ]] ||
  fail 'CORELM_SWEEP_ROOT parent must be an existing canonical non-symlink directory'
[[ "$(stat -c '%u' -- "$run_parent")" -eq "$(id -u)" ]] ||
  fail 'CORELM_SWEEP_ROOT parent is not owned by the current user'
run_parent_mode=$(stat -c '%a' -- "$run_parent")
case "$run_parent_mode" in
  *[2367][0-7]|*[0-7][2367]) fail 'CORELM_SWEEP_ROOT parent is group/world writable' ;;
esac
unset run_parent_mode

paths_overlap() {
  local left=$1 right=$2
  [[ "$left" = "$right" || "$left" = "$right"/* || "$right" = "$left"/* ]]
}
for protected_root in "$sweep_repo" "$codec_root" "$runtime_root" "$original_home"; do
  paths_overlap "$run_root" "$protected_root" &&
    fail 'CORELM_SWEEP_ROOT overlaps source, runtime, or the original home'
done
unset protected_root

assert_exact_checkout() {
  local root=$1 required_commit=$2 required_tree=$3
  local observed status replace_refs index_listing tracked relative tree_entry
  local mode tail type expected raw_observed

  observed=$(git -C "$root" --no-optional-locks rev-parse --verify HEAD) ||
    fail 'cannot resolve checkout HEAD'
  [[ "$observed" = "$required_commit" ]] || fail 'checkout commit differs from the expected commit'
  observed=$(git -C "$root" --no-optional-locks rev-parse --verify 'HEAD^{tree}') ||
    fail 'cannot resolve checkout tree'
  [[ "$observed" = "$required_tree" ]] || fail 'checkout tree differs from the expected tree'
  if git -C "$root" symbolic-ref -q HEAD >/dev/null 2>&1; then
    fail 'source checkout must be detached'
  fi
  [[ "$(git -C "$root" rev-parse --is-shallow-repository)" = false ]] ||
    fail 'source checkout must not be shallow'
  [[ ! -e "$root/.git/shallow" && ! -e "$root/.git/info/grafts" ]] ||
    fail 'source checkout contains shallow or graft metadata'
  replace_refs=$(git -C "$root" for-each-ref --format='%(refname)' refs/replace) ||
    fail 'cannot inspect replacement refs'
  [[ -z "$replace_refs" ]] || fail 'source checkout contains replacement refs'
  status=$(git -C "$root" --no-optional-locks \
    -c core.fsmonitor=false -c core.untrackedCache=false \
    status --porcelain=v1 --untracked-files=all --ignored=matching) ||
    fail 'cannot inspect source checkout status'
  [[ -z "$status" ]] || fail 'source checkout is not sterile: tracked, untracked, or ignored bytes exist'
  index_listing=$(git -C "$root" ls-files -v) ||
    fail 'cannot inspect source checkout index flags'
  if grep -E '^[a-zS]' <<<"$index_listing" >/dev/null; then
    fail 'source checkout contains assume-unchanged or skip-worktree entries'
  fi
  tracked=$(git -C "$root" ls-tree -r --name-only HEAD) ||
    fail 'cannot enumerate signed-tree source files'
  [[ -n "$tracked" ]] || fail 'source checkout has no tracked files'
  while IFS= read -r relative; do
    [[ "$relative" != *[$'\t\r']* ]] || fail 'tracked source path contains control whitespace'
    [[ -f "$root/$relative" && ! -L "$root/$relative" ]] ||
      fail 'tracked source is absent or not a regular file'
    tree_entry=$(git -C "$root" ls-tree \
      --format='%(objectmode) %(objecttype) %(objectname)' \
      HEAD -- "$relative") ||
      fail 'cannot inspect a signed-tree source entry'
    mode=${tree_entry%% *}
    tail=${tree_entry#* }
    type=${tail%% *}
    [[ "$type" = blob ]] || fail 'signed-tree source entry is not a blob'
    tail=${tail#* }
    expected=${tail%% *}
    [[ "$mode" = 100644 || "$mode" = 100755 ]] || fail 'tracked source mode is unsupported'
    raw_observed=$(git -C "$root" hash-object --no-filters -- "$root/$relative") ||
      fail 'cannot hash a raw tracked source file'
    [[ "$raw_observed" = "$expected" ]] ||
      fail 'raw tracked source differs from the signed tree'
  done <<<"$tracked"
}

assert_exact_checkout "$sweep_repo" "$expected_commit" "$expected_tree"
assert_exact_checkout \
  "$codec_root" e7e0504b15769c925206ad1783d45a9ca0b62207 \
  924d3195122e3a486e2d26e4fbdfe574654ae6c8

verify_signed_commit() {
  local root=$1 commit=$2 allowed_signers=$3 observed
  [[ -f "$allowed_signers" && ! -L "$allowed_signers" ]] ||
    fail 'a pinned allowed_signers trust root is absent or unsafe'
  observed=$(sha256sum "$allowed_signers" | awk '{print $1}') ||
    fail 'cannot hash the commit-signature trust root'
  [[ "$observed" = 36fb4a170eee7664be32f2a5d562db209fa4f6f1f24667cf6a3ef0166d155c16 ]] ||
    fail 'the commit-signature trust root differs'
  git -C "$root" -c gpg.ssh.allowedSignersFile="$allowed_signers" \
    -c gpg.ssh.program=/usr/bin/ssh-keygen \
    verify-commit "$commit" >/dev/null 2>&1 ||
    fail 'commit signature verification failed'
}

verify_signed_commit \
  "$sweep_repo" "$expected_commit" "$sweep_repo/v4/signing/allowed_signers"
verify_signed_commit \
  "$codec_root" e7e0504b15769c925206ad1783d45a9ca0b62207 \
  "$codec_root/signing/allowed_signers"

[[ -r /etc/os-release ]] || fail '/etc/os-release is absent'
grep -qx 'ID=ubuntu' /etc/os-release || fail 'host OS must be Ubuntu'
grep -Eq '^VERSION_ID="?24\.04"?$' /etc/os-release || fail 'host OS must be Ubuntu 24.04'
[[ "$(uname -m)" = x86_64 ]] || fail 'host architecture must be x86_64'

mapfile -t gpu_inventory < <(
  nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader,nounits 2>/dev/null
)
[[ "${#gpu_inventory[@]}" -eq 1 ]] || fail 'exactly one visible NVIDIA GPU is required'
IFS=',' read -r gpu_name gpu_memory_mib gpu_driver_version <<<"${gpu_inventory[0]}"
gpu_name=$(awk '{$1=$1; print}' <<<"$gpu_name")
gpu_memory_mib=${gpu_memory_mib//[[:space:]]/}
gpu_driver_version=${gpu_driver_version//[[:space:]]/}
[[ "$gpu_memory_mib" =~ ^[0-9]+$ && "$gpu_memory_mib" -ge 78000 ]] ||
  fail 'the single GPU must expose at least 78000 MiB VRAM'
[[ "$gpu_driver_version" =~ ^[0-9]+([.][0-9]+){1,3}$ ]] ||
  fail 'the NVIDIA driver version is invalid'
cpu_count=$(getconf _NPROCESSORS_ONLN)
[[ "$cpu_count" =~ ^[0-9]+$ && "$cpu_count" -ge 16 ]] ||
  fail 'at least 16 online CPUs are required'
ram_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
[[ "$ram_kib" =~ ^[0-9]+$ && "$ram_kib" -ge 115343360 ]] ||
  fail 'at least 110 GiB system RAM is required'
cgroup_admission=$(
  "$python_executable" -E -s -B "$script_dir/cgroup_contract.py" admission \
    --minimum-cpu-cores 16 \
    --minimum-memory-bytes 118111600640
) || fail 'current-process cgroup admission failed'
[[ "$cgroup_admission" != *$'\n'* ]] || fail 'cgroup admission output is multiline'
IFS=$'\t' read -r cgroup_version cgroup_cpu_quota cgroup_cpu_period cgroup_memory_max cgroup_extra \
  <<<"$cgroup_admission"
[[ -z "${cgroup_extra-}" && "$cgroup_version" =~ ^v[12]$ ]] ||
  fail 'cgroup admission output differs'
[[ "$cgroup_cpu_quota" = max || "$cgroup_cpu_quota" =~ ^[0-9]+$ ]] ||
  fail 'cgroup CPU quota output is invalid'
[[ "$cgroup_cpu_period" =~ ^[0-9]+$ && "$cgroup_cpu_period" -gt 0 ]] ||
  fail 'cgroup CPU period output is invalid'
[[ "$cgroup_memory_max" = max || "$cgroup_memory_max" =~ ^[0-9]+$ ]] ||
  fail 'cgroup memory limit output is invalid'
unset cgroup_admission cgroup_extra
free_kib=$(df -Pk -- "$run_parent" | awk 'NR == 2 {print $4}')
[[ "$free_kib" =~ ^[0-9]+$ && "$free_kib" -ge 104857600 ]] ||
  fail 'at least 100 GiB free space is required on the run volume'

python_version=$(
  "$python_executable" -E -s -B -c \
    'import platform; print(platform.python_implementation()+" "+platform.python_version())'
) || fail 'cannot execute the supplied Python runtime'
[[ "$python_version" = 'CPython 3.12.13' ]] ||
  fail 'CORELM_SWEEP_PYTHON must be exact CPython 3.12.13'
"$python_executable" -E -s -B "$runtime_safety" validate-runtime \
  --runtime "$runtime_root" >/dev/null ||
  fail 'the supplied CUDA runtime failed path and marker validation'
"$python_executable" -E -s -B "$verify_locks" \
  --runtime "$runtime_root" \
  --lock "$pip_bootstrap_lock" \
  --lock "$portable_runtime_lock" \
  --lock "$cuda_runtime_lock" ||
  fail 'the supplied CUDA runtime differs from the exact three-lock closure'
"$python_executable" -E -s -B -c '
from importlib.metadata import version
expected = {
    "huggingface-hub": "1.25.1",
    "numpy": "2.5.1",
    "safetensors": "0.8.0",
    "tokenizers": "0.22.2",
    "torch": "2.13.0+cu130",
    "transformers": "5.14.1",
}
observed = {name: version(name) for name in expected}
assert observed == expected, (observed, expected)
' || fail 'the Python package set differs from the frozen codec runtime lock'
"$python_executable" -E -s -B -c \
  'import torch; assert torch.cuda.is_available(); assert torch.cuda.device_count() == 1; assert torch.version.cuda' ||
  fail 'the Python runtime does not expose exactly one CUDA device'

printf 'STEP CONTRACT_TESTS\n'
CORELM_SWEEP_TEST_CODEC_ROOT="$codec_root" \
  /usr/bin/timeout --foreground --signal=TERM --kill-after=60s 900s \
  "$python_executable" -E -s -B -m unittest discover \
  -s "$script_dir" -p 'test_*.py' -v ||
  fail 'the model-free Linux sweep contract tests failed'

execution_cache_parent=$(dirname -- "$runtime_root")
[[ -d "$execution_cache_parent" && ! -L "$execution_cache_parent" && \
   "$execution_cache_parent" = "$(readlink -f -- "$execution_cache_parent")" ]] ||
  fail 'the executable-cache parent is not a canonical directory'
[[ "$(stat -c '%u' -- "$execution_cache_parent")" -eq "$(id -u)" ]] ||
  fail 'the executable-cache parent is not owned by the current user'
execution_cache_parent_mode=$(stat -c '%a' -- "$execution_cache_parent")
case "$execution_cache_parent_mode" in
  *[2367][0-7]|*[0-7][2367]) fail 'the executable-cache parent is group/world writable' ;;
esac
execution_cache_id=$(builtin printf '%s' "$run_root" | sha256sum | awk '{print $1}') ||
  fail 'cannot derive the one-shot executable-cache identity'
[[ "$execution_cache_id" =~ ^[0-9a-f]{64}$ ]] ||
  fail 'the executable-cache identity is invalid'
execution_cache_root="$execution_cache_parent/.corelm-exec-cache-$execution_cache_id"
[[ ! -e "$execution_cache_root" && ! -L "$execution_cache_root" ]] ||
  fail 'the one-shot executable-cache root already exists'
mkdir -m 0700 -- "$execution_cache_root"
mkdir -m 0700 -- \
  "$execution_cache_root/triton" \
  "$execution_cache_root/torchinductor" \
  "$execution_cache_root/torch-extensions" \
  "$execution_cache_root/cuda" \
  "$execution_cache_root/pytorch-kernels"
export TRITON_CACHE_DIR="$execution_cache_root/triton"
export TORCHINDUCTOR_CACHE_DIR="$execution_cache_root/torchinductor"
export TORCH_EXTENSIONS_DIR="$execution_cache_root/torch-extensions"
export CUDA_CACHE_PATH="$execution_cache_root/cuda"
export PYTORCH_KERNEL_CACHE_PATH="$execution_cache_root/pytorch-kernels"
unset execution_cache_parent execution_cache_parent_mode execution_cache_id

mkdir -m 0700 -- "$run_root"
mkdir -m 0700 -- \
  "$run_root/assets" \
  "$run_root/evidence" \
  "$run_root/export" \
  "$run_root/home" \
  "$run_root/tmp" \
  "$run_root/xdg-cache"
export HOME="$run_root/home"
export TMPDIR="$run_root/tmp"
export XDG_CACHE_HOME="$run_root/xdg-cache"
export HF_HOME="$run_root/home/huggingface"

printf 'STEP EXECUTABLE_CACHE_SMOKE\n'
/usr/bin/timeout --foreground --signal=TERM --kill-after=60s 120s \
  "$python_executable" -E -s -B -c '
import os
from pathlib import Path

import torch
from torch._native.ops.bmm_outer_product.triton_kernels import bmm_outer_product

left = torch.ones((1, 32, 1), device="cuda")
right = torch.ones((1, 1, 32), device="cuda")
observed = bmm_outer_product(left, right)
torch.cuda.synchronize()
assert observed.shape == (1, 32, 32)
assert torch.equal(observed, torch.ones_like(observed))
triton_root = Path(os.environ["TRITON_CACHE_DIR"]).resolve(strict=True)
compiled = list(triton_root.rglob("cuda_utils*.so"))
assert compiled and all(path.is_file() for path in compiled), compiled
assert all(path.resolve().is_relative_to(triton_root) for path in compiled), compiled
for name in ("HOME", "TMPDIR", "XDG_CACHE_HOME"):
    assert not list(Path(os.environ[name]).rglob("*.so")), name
' || fail 'the executable cache cannot compile and load the pinned Triton CUDA helper'

prepare_assets="$script_dir/prepare_assets.py"
runner="$script_dir/run_adapter_sweep.py"
verifier="$script_dir/verify_adapter_sweep.py"
token_scanner="$script_dir/scan_token_persistence.py"
for program in "$prepare_assets" "$runner" "$verifier" "$token_scanner"; do
  [[ -f "$program" && ! -L "$program" ]] || fail 'a required sweep Python program is absent or unsafe'
done
unset program

run_timed() {
  local label=$1
  local seconds=$2
  shift 2
  printf 'STEP %s\n' "$label"
  /usr/bin/timeout --foreground --signal=TERM --kill-after=60s "${seconds}s" "$@"
}

# Only this command receives HF_TOKEN. The Python downloader itself uses the
# token only for the gated Gemma profile and uses token=False for public models.
export HF_TOKEN="$hf_token"
download_status=0
run_timed ASSET_DOWNLOAD 3600 \
  "$python_executable" -E -s -B "$prepare_assets" download \
  --cache "$run_root/assets" \
  --receipt "$run_root/evidence/assets-download.json" || download_status=$?
unset HF_TOKEN
[[ "$download_status" -eq 0 ]] || fail 'asset download or digest verification failed'
for forbidden_token_path in \
  "$HF_HOME/token" \
  "$HF_HOME/stored_tokens" \
  "$HOME/.cache/huggingface/token" \
  "$HOME/.cache/huggingface/stored_tokens" \
  "$HOME/.netrc"
do
  [[ ! -e "$forbidden_token_path" ]] ||
    fail 'the downloader persisted a Hugging Face credential file'
done
unset forbidden_token_path
builtin printf '%s' "$hf_token" | \
  "$python_executable" -I -B "$token_scanner" \
  --root "$run_root/home" \
  --root "$run_root/tmp" \
  --root "$run_root/xdg-cache" \
  --root "$run_root/assets" \
  --root "$run_root/evidence" \
  --root "$execution_cache_root" ||
  fail 'the downloader persisted a credential or created an unsafe scan tree'
unset hf_token execution_cache_root

export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1

# OPT conversion is deliberately a fresh, single-purpose process. It receives
# no provider/model credential, user-site path, proxy, or inherited shell hook;
# its receipt records the narrower application-offline boundary honestly.
run_timed OPT_CONVERSION 900 \
  /usr/bin/env -i \
  HOME="$HOME" \
  TMPDIR="$TMPDIR" \
  XDG_CACHE_HOME="$XDG_CACHE_HOME" \
  PATH="$PATH" \
  LANG=C.UTF-8 \
  LC_ALL=C.UTF-8 \
  TZ=UTC \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONNOUSERSITE=1 \
  HF_HUB_OFFLINE=1 \
  TRANSFORMERS_OFFLINE=1 \
  HF_HUB_DISABLE_TELEMETRY=1 \
  HF_HUB_DISABLE_IMPLICIT_TOKEN=1 \
  DO_NOT_TRACK=1 \
  CUDA_VISIBLE_DEVICES= \
  CUDA_HOME=/usr/local/cuda \
  LD_LIBRARY_PATH=/usr/local/cuda/lib64:/usr/local/cuda/compat \
  "$python_executable" -E -s -B "$prepare_assets" convert \
  --cache "$run_root/assets" \
  --receipt "$run_root/evidence/opt-conversion.json"

run_timed ASSET_VERIFY 900 \
  "$python_executable" -E -s -B "$prepare_assets" verify \
  --cache "$run_root/assets" \
  --conversion-receipt "$run_root/evidence/opt-conversion.json" \
  --receipt "$run_root/evidence/assets-verify.json"

run_timed SWEEP_PREFLIGHT 900 \
  "$python_executable" -E -s -B "$runner" preflight \
  --codec-root "$codec_root" \
  --cache "$run_root/assets" \
  --assets "$run_root/evidence/assets-verify.json" \
  --output "$run_root/evidence/preflight.json"

# Orchestrate is the only matrix command. Its contract launches the 28 cells
# sequentially as fresh process groups; this wrapper never launches models in
# parallel and never reuses this run directory.
run_timed SWEEP_ORCHESTRATE 41400 \
  "$python_executable" -E -s -B "$runner" orchestrate \
  --codec-root "$codec_root" \
  --cache "$run_root/assets" \
  --assets "$run_root/evidence/assets-verify.json" \
  --preflight "$run_root/evidence/preflight.json" \
  --run-dir "$run_root/evidence/run" \
  --cell-timeout-seconds 2700

run_timed SWEEP_VERIFY 900 \
  "$python_executable" -E -s -B "$verifier" verify-run \
  --codec-root "$codec_root" \
  --cache "$run_root/assets" \
  --assets "$run_root/evidence/assets-verify.json" \
  --preflight "$run_root/evidence/preflight.json" \
  --run-dir "$run_root/evidence/run" \
  --output "$run_root/evidence/structural-verification.json"

mkdir -m 0700 -- "$run_root/evidence/replays"
replay_pairs=(
  'qwen2.5-0.5b:tracked-legal-protocol-v1:1350'
  'smollm2-135m:tracked-source-code-v1:900'
  'mistral-7b-v0.1:tracked-structured-json-v1:2700'
  'pythia-14m:tracked-technical-prose-v1:900'
  'distilgpt2:tracked-legal-protocol-v1:900'
  'opt-125m:tracked-source-code-v1:900'
  'gemma-2b:tracked-structured-json-v1:1800'
)
for replay_pair in "${replay_pairs[@]}"; do
  replay_model=${replay_pair%%:*}
  replay_tail=${replay_pair#*:}
  replay_workload=${replay_tail%%:*}
  replay_timeout=${replay_tail##*:}
  run_timed "REPLAY_${replay_model}" "$replay_timeout" \
    "$python_executable" -E -s -B "$verifier" replay-cell \
    --codec-root "$codec_root" \
    --cache "$run_root/assets" \
    --assets "$run_root/evidence/assets-verify.json" \
    --preflight "$run_root/evidence/preflight.json" \
    --run-dir "$run_root/evidence/run" \
    --structural "$run_root/evidence/structural-verification.json" \
    --model-id "$replay_model" \
    --workload-id "$replay_workload" \
    --output "$run_root/evidence/replays/${replay_model}--${replay_workload}.json"
done
unset replay_pair replay_model replay_tail replay_timeout replay_workload replay_pairs

assert_exact_checkout "$sweep_repo" "$expected_commit" "$expected_tree"
assert_exact_checkout \
  "$codec_root" e7e0504b15769c925206ad1783d45a9ca0b62207 \
  924d3195122e3a486e2d26e4fbdfe574654ae6c8

printf '%s\n' \
  'schemaVersion=corelm-runpod-adapter-sweep-source-v1' \
  "sweepCommit=$expected_commit" \
  "sweepTree=$expected_tree" \
  'commitSignatureTrustRootSHA256=36fb4a170eee7664be32f2a5d562db209fa4f6f1f24667cf6a3ef0166d155c16' \
  'sweepCommitSignatureVerified=true' \
  'codecCommit=e7e0504b15769c925206ad1783d45a9ca0b62207' \
  'codecTree=924d3195122e3a486e2d26e4fbdfe574654ae6c8' \
  'codecCommitSignatureVerified=true' \
  'classification=EXPLORATORY_PUBLIC_REGRESSION_ONLY' \
  'scientificEvidence=false' \
  'countsTowardScientificVerdict=false' \
  "containerImageDigest=$image_digest" \
  'containerImageDigestAuthority=operator-supplied-control-plane-value' \
  "gpuName=$gpu_name" \
  "gpuMemoryMiB=$gpu_memory_mib" \
  "gpuDriverVersion=$gpu_driver_version" \
  "cgroupVersion=$cgroup_version" \
  "cgroupCpuQuota=$cgroup_cpu_quota" \
  "cgroupCpuPeriod=$cgroup_cpu_period" \
  "cgroupMemoryMax=$cgroup_memory_max" \
  "codecRequirementsSHA256=$(sha256sum "$codec_root/RealLLM/requirements.lock" | awk '{print $1}')" \
  "pipBootstrapLockSHA256=$(sha256sum "$pip_bootstrap_lock" | awk '{print $1}')" \
  "portableRuntimeLockSHA256=$(sha256sum "$portable_runtime_lock" | awk '{print $1}')" \
  "cudaTorchLockSHA256=$(sha256sum "$cuda_runtime_lock" | awk '{print $1}')" \
  >"$run_root/evidence/source-identity.txt"

find "$run_root/evidence" -type d -exec chmod 0700 {} +
find "$run_root/evidence" -type f -exec chmod 0600 {} +
[[ -z "$(find "$run_root/evidence" -type l -print -quit)" ]] ||
  fail 'evidence contains a symlink'
[[ -z "$(find "$run_root/evidence" ! -type d ! -type f -print -quit)" ]] ||
  fail 'evidence contains a special filesystem object'
[[ -z "$(find "$run_root/evidence" -type f -links +1 -print -quit)" ]] ||
  fail 'evidence contains a hard-linked regular file'
[[ -z "$(find "$run_root/evidence" ! -uid "$(id -u)" -print -quit)" ]] ||
  fail 'evidence contains an object owned by another user'

# Never print a matching line: even a defensive scan must not disclose a
# credential or endpoint to the terminal.
privacy_status=0
grep -R -I -q -E \
  '(hf_[A-Za-z0-9]{20,}|HF_TOKEN|RUNPOD_API_KEY|SSH_(AUTH_SOCK|CONNECTION)|pod(Id|_id)|/workspace/|/root/|(^|[^0-9])([0-9]{1,3}\.){3}[0-9]{1,3}([^0-9]|$))' \
  "$run_root/evidence" || privacy_status=$?
[[ "$privacy_status" -eq 1 ]] || fail 'privacy scan rejected the evidence tree or could not read it'
for private_path in "$run_root" "$sweep_repo" "$codec_root" "$HOME"; do
  privacy_status=0
  grep -R -I -F -q -- "$private_path" "$run_root/evidence" || privacy_status=$?
  [[ "$privacy_status" -eq 1 ]] || fail 'privacy scan found a private absolute path or could not read evidence'
done
unset private_path privacy_status

archive="$run_root/export/corelm-runpod-adapter-sweep-v1.tar.gz"
(
  cd "$run_root"
  /usr/bin/tar \
    --sort=name \
    --format=pax \
    --mtime='UTC 1970-01-01' \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --pax-option=delete=atime,delete=ctime \
    -cf - evidence | gzip -n >"$archive"
)
chmod 0600 "$archive"
(
  cd "$run_root/export"
  sha256sum "$(basename -- "$archive")" >SHA256SUMS
  chmod 0600 SHA256SUMS
  sha256sum -c SHA256SUMS
)

printf 'RUNPOD SWEEP COMPLETE\n'
printf 'Retrieve both files over the host-key-pinned SSH channel:\n'
printf '  %s\n' "$archive" "$run_root/export/SHA256SUMS"
printf 'Verify locally before terminating the Pod; never publish the assets directory.\n'

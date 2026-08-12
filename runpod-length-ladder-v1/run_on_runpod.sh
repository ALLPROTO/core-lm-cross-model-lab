#!/bin/bash
# Fail-closed one-shot launcher for the public-Qwen prefill-length ladder.

if [[ "$#" -ne 1 || "$1" != --corelm-length-clean-entry ]]; then
  printf 'RUNPOD LENGTH FAIL: use launch_runpod.py with the exact runtime and -I -B\n' >&2
  exit 2
fi
shift
if [[ -n "$(compgen -A function)" ]]; then
  printf 'RUNPOD LENGTH FAIL: the sterile entry environment imported a Bash function\n' >&2
  exit 1
fi

set -Eeuo pipefail
umask 077

fail() {
  printf 'RUNPOD LENGTH FAIL: %s\n' "$1" >&2
  exit 1
}

case "$-" in
  *x*) fail 'xtrace must be disabled' ;;
esac
(( BASH_VERSINFO[0] >= 5 )) || fail 'GNU Bash 5 or newer is required'

# Capture only the non-secret registered inputs, remove every inherited name,
# and construct the complete child environment below.
expected_commit=${CORELM_LENGTH_EXPECTED_COMMIT-}
expected_tree=${CORELM_LENGTH_EXPECTED_TREE-}
codec_root=${CORELM_LENGTH_CODEC_ROOT-}
python_executable=${CORELM_LENGTH_PYTHON-}
run_root=${CORELM_LENGTH_ROOT-}
image_digest=${CORELM_LENGTH_IMAGE_DIGEST-}
original_home=${HOME-}
export -n expected_commit expected_tree codec_root python_executable run_root image_digest original_home 2>/dev/null || true

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
ulimit -c 0 || fail 'core dumps must be disabled'

[[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] ||
  fail 'CORELM_LENGTH_EXPECTED_COMMIT must be an exact 40-hex commit'
[[ "$expected_tree" =~ ^[0-9a-f]{40}$ ]] ||
  fail 'CORELM_LENGTH_EXPECTED_TREE must be an exact 40-hex tree'
[[ "$codec_root" = /* && -d "$codec_root" && ! -L "$codec_root" ]] ||
  fail 'CORELM_LENGTH_CODEC_ROOT must name an absolute existing non-symlink directory'
[[ "$python_executable" = /* && -f "$python_executable" && -x "$python_executable" ]] ||
  fail 'CORELM_LENGTH_PYTHON must name an absolute executable regular file'
[[ "$run_root" = /* && "$run_root" != / && ! -e "$run_root" && ! -L "$run_root" ]] ||
  fail 'CORELM_LENGTH_ROOT must be an absolute previously nonexistent directory'
[[ "$image_digest" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  fail 'CORELM_LENGTH_IMAGE_DIGEST must be an immutable sha256 image digest'
[[ "$original_home" = /* && -d "$original_home" && ! -L "$original_home" ]] ||
  fail 'the original HOME must be an absolute existing non-symlink directory'
for input_path in "$codec_root" "$python_executable" "$run_root" "$original_home"; do
  [[ "$input_path" != *[$'\n\r\t']* ]] || fail 'input paths may not contain control whitespace'
done
unset input_path

for forbidden_name in \
  HF_TOKEN HUGGING_FACE_HUB_TOKEN RUNPOD_API_KEY GITHUB_TOKEN GH_TOKEN \
  AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN \
  GOOGLE_APPLICATION_CREDENTIALS AZURE_CLIENT_SECRET SSH_AUTH_SOCK
do
  [[ -z "${!forbidden_name+x}" ]] || fail "forbidden credential variable survived sterile entry: $forbidden_name"
done
unset forbidden_name

for required_command in \
  git ssh-keygen nvidia-smi timeout tar gzip sha256sum find grep readlink \
  getconf df awk uname id dirname basename mkdir chmod stat tee
do
  command -v "$required_command" >/dev/null 2>&1 ||
    fail "required host command is absent: $required_command"
done
unset required_command
[[ "$(command -v timeout)" = /usr/bin/timeout ]] || fail 'GNU timeout must be /usr/bin/timeout'
[[ "$(command -v tar)" = /usr/bin/tar ]] || fail 'GNU tar must be /usr/bin/tar'
[[ "$(command -v gzip)" = /usr/bin/gzip ]] || fail 'GNU gzip must be /usr/bin/gzip'

script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
script_dir=$(dirname -- "$script_path")
[[ "$script_path" = "$script_dir/run_on_runpod.sh" ]] || fail 'launcher path resolution failed'
safe_git() {
  command git \
    -c core.fsmonitor=false \
    -c core.untrackedCache=false \
    -c core.hooksPath=/dev/null \
    -c protocol.file.allow=never \
    "$@"
}

sweep_repo=$(safe_git -C "$script_dir" rev-parse --show-toplevel) || fail 'launcher is not inside a Git checkout'
adapter_dir="$sweep_repo/runpod-adapter-sweep-v1"
[[ "$sweep_repo" = "$(readlink -f -- "$sweep_repo")" ]] || fail 'sweep checkout traverses a symlink'
[[ "$codec_root" = "$(readlink -f -- "$codec_root")" ]] || fail 'codec checkout traverses a symlink'
[[ "$python_executable" = "$(readlink -f -- "$python_executable")" ]] ||
  fail 'CORELM_LENGTH_PYTHON must be the canonical executable path, not a symlink'
[[ "$run_root" = "$(readlink -m -- "$run_root")" ]] || fail 'CORELM_LENGTH_ROOT is not canonical'

runtime_root=$(dirname -- "$(dirname -- "$python_executable")")
[[ -d "$runtime_root" && ! -L "$runtime_root" && "$runtime_root" = "$(readlink -f -- "$runtime_root")" ]] ||
  fail 'CUDA runtime root is not a canonical directory'
runtime_safety="$codec_root/platforms/linux/scripts/runtime_safety.py"
verify_locks="$codec_root/security/verify_locked_environment.py"
pip_bootstrap_lock="$codec_root/.github/locks/pip-bootstrap.txt"
portable_runtime_lock="$codec_root/.github/locks/real-llm-linux-cpu-py312.txt"
cuda_runtime_lock="$adapter_dir/torch-linux-cu130-py312.txt"
cgroup_contract="$adapter_dir/cgroup_contract.py"
for runtime_input in \
  "$runtime_safety" "$verify_locks" "$pip_bootstrap_lock" \
  "$portable_runtime_lock" "$cuda_runtime_lock" "$cgroup_contract"
do
  [[ -f "$runtime_input" && ! -L "$runtime_input" ]] ||
    fail 'a required runtime validation input is absent or unsafe'
done
unset runtime_input

run_parent=$(dirname -- "$run_root")
[[ -d "$run_parent" && ! -L "$run_parent" && "$run_parent" = "$(readlink -f -- "$run_parent")" ]] ||
  fail 'CORELM_LENGTH_ROOT parent must be an existing canonical non-symlink directory'
[[ "$(stat -c '%u' -- "$run_parent")" -eq "$(id -u)" ]] ||
  fail 'CORELM_LENGTH_ROOT parent is not owned by the current user'
run_parent_mode=$(stat -c '%a' -- "$run_parent")
case "$run_parent_mode" in
  *[2367][0-7]|*[0-7][2367]) fail 'CORELM_LENGTH_ROOT parent is group/world writable' ;;
esac
unset run_parent_mode

paths_overlap() {
  local left=$1 right=$2
  [[ "$left" = "$right" || "$left" = "$right"/* || "$right" = "$left"/* ]]
}
for protected_root in "$sweep_repo" "$codec_root" "$runtime_root" "$original_home"; do
  paths_overlap "$run_root" "$protected_root" &&
    fail 'CORELM_LENGTH_ROOT overlaps source, runtime, or the original home'
done
unset protected_root

root_filesystem_device=$(stat -c '%d' -- /) || fail 'cannot inspect the root-filesystem device'
[[ "$root_filesystem_device" =~ ^[0-9]+$ ]] || fail 'root-filesystem device identity is invalid'
for container_disk_path in "$sweep_repo" "$codec_root" "$runtime_root" "$run_parent" "$original_home"; do
  [[ "$(stat -c '%d' -- "$container_disk_path")" = "$root_filesystem_device" ]] ||
    fail 'source, runtime, home, and attempt paths must remain on the root container-disk device'
done
unset container_disk_path

assert_no_mount_below() {
  local protected_path=$1 protected_prefix line mount_field decoded_mount
  protected_prefix=${protected_path%/}/
  while IFS= read -r line; do
    set -- $line
    [[ "$#" -ge 5 ]] || fail 'mountinfo grammar differs'
    mount_field=$5
    decoded_mount=${mount_field//\\040/ }
    decoded_mount=${decoded_mount//\\011/$'\t'}
    decoded_mount=${decoded_mount//\\012/$'\n'}
    decoded_mount=${decoded_mount//\\134/\\}
    [[ "$decoded_mount" = /* && "$decoded_mount" != *\\* && "$decoded_mount" != *$'\n'* && "$decoded_mount" != *$'\r'* ]] ||
      fail 'mountinfo contains an unsafe mount-point field'
    if [[ "$decoded_mount" != / && \
      ( "$decoded_mount" = "$protected_path" || \
        "$decoded_mount" = "$protected_prefix"* || \
        "$protected_path" = "${decoded_mount%/}/"* ) ]]; then
      fail 'an execution path crosses or contains a mount and is not a plain root-filesystem tree'
    fi
  done </proc/self/mountinfo
}
for container_disk_path in "$sweep_repo" "$codec_root" "$runtime_root" "$run_parent" "$original_home"; do
  assert_no_mount_below "$container_disk_path"
done
unset container_disk_path

assert_exact_checkout() {
  local root=$1 required_commit=$2 required_tree=$3
  local observed status replace_refs index_listing tracked relative tree_entry
  local mode tail type expected raw_observed git_directory root_mode

  [[ "$root" = "$(readlink -f -- "$root")" && -d "$root" && ! -L "$root" ]] ||
    fail 'checkout root is not canonical and safe'
  [[ "$(stat -c '%u' -- "$root")" -eq "$(id -u)" ]] || fail 'checkout root is not owner controlled'
  root_mode=$(stat -c '%a' -- "$root")
  case "$root_mode" in
    *[2367][0-7]|*[0-7][2367]) fail 'checkout root is group/world writable' ;;
  esac
  observed=$(safe_git -C "$root" --no-optional-locks rev-parse --show-toplevel) || fail 'cannot resolve checkout root'
  [[ "$observed" = "$root" ]] || fail 'checkout differs from its Git top level'
  git_directory=$(safe_git -C "$root" --no-optional-locks rev-parse --absolute-git-dir) || fail 'cannot resolve Git directory'
  [[ -d "$git_directory" && ! -L "$git_directory" ]] || fail 'checkout Git directory is unsafe'
  observed=$(safe_git -C "$root" --no-optional-locks rev-parse --verify HEAD) || fail 'cannot resolve checkout HEAD'
  [[ "$observed" = "$required_commit" ]] || fail 'checkout commit differs from the expected commit'
  observed=$(safe_git -C "$root" --no-optional-locks rev-parse --verify 'HEAD^{tree}') || fail 'cannot resolve checkout tree'
  [[ "$observed" = "$required_tree" ]] || fail 'checkout tree differs from the expected tree'
  if safe_git -C "$root" symbolic-ref -q HEAD >/dev/null 2>&1; then
    fail 'source checkout must be detached'
  fi
  observed=$(safe_git -C "$root" rev-parse --is-shallow-repository) || fail 'cannot inspect shallow state'
  [[ "$observed" = false ]] || fail 'source checkout must not be shallow'
  [[ ! -e "$git_directory/shallow" && ! -e "$git_directory/info/grafts" ]] ||
    fail 'source checkout contains shallow or graft metadata'
  replace_refs=$(safe_git -C "$root" for-each-ref --format='%(refname)' refs/replace) || fail 'cannot inspect replacement refs'
  [[ -z "$replace_refs" ]] || fail 'source checkout contains replacement refs'
  status=$(safe_git -C "$root" --no-optional-locks \
    -c core.fsmonitor=false -c core.untrackedCache=false \
    status --porcelain=v1 --untracked-files=all --ignored=matching) || fail 'cannot inspect source checkout status'
  [[ -z "$status" ]] || fail 'source checkout is not sterile: tracked, untracked, or ignored bytes exist'
  index_listing=$(safe_git -C "$root" ls-files -v) || fail 'cannot inspect source checkout index flags'
  if grep -E '^[a-zS]' <<<"$index_listing" >/dev/null; then
    fail 'source checkout contains assume-unchanged or skip-worktree entries'
  fi
  tracked=$(safe_git -C "$root" ls-tree -r --name-only HEAD) || fail 'cannot enumerate signed-tree source files'
  [[ -n "$tracked" ]] || fail 'source checkout has no tracked files'
  while IFS= read -r relative; do
    [[ "$relative" != *[$'\t\r']* ]] || fail 'tracked source path contains control whitespace'
    [[ -f "$root/$relative" && ! -L "$root/$relative" ]] || fail 'tracked source is absent or not a regular file'
    tree_entry=$(safe_git -C "$root" ls-tree \
      --format='%(objectmode) %(objecttype) %(objectname)' HEAD -- "$relative") ||
      fail 'cannot inspect a signed-tree source entry'
    mode=${tree_entry%% *}
    tail=${tree_entry#* }
    type=${tail%% *}
    [[ "$type" = blob ]] || fail 'signed-tree source entry is not a blob'
    tail=${tail#* }
    expected=${tail%% *}
    [[ "$mode" = 100644 || "$mode" = 100755 ]] || fail 'tracked source mode is unsupported'
    raw_observed=$(safe_git -C "$root" hash-object --no-filters -- "$root/$relative") || fail 'cannot hash a raw tracked source file'
    [[ "$raw_observed" = "$expected" ]] || fail 'raw tracked source differs from the signed tree'
  done <<<"$tracked"
}

assert_exact_checkout "$sweep_repo" "$expected_commit" "$expected_tree"
assert_exact_checkout \
  "$codec_root" e7e0504b15769c925206ad1783d45a9ca0b62207 \
  924d3195122e3a486e2d26e4fbdfe574654ae6c8

verify_signed_commit() {
  local root=$1 commit=$2 allowed_signers=$3 observed
  [[ -f "$allowed_signers" && ! -L "$allowed_signers" ]] || fail 'a pinned allowed_signers trust root is absent or unsafe'
  observed=$(sha256sum "$allowed_signers") || fail 'cannot hash the commit-signature trust root'
  observed=${observed%% *}
  [[ "$observed" = 36fb4a170eee7664be32f2a5d562db209fa4f6f1f24667cf6a3ef0166d155c16 ]] ||
    fail 'the commit-signature trust root differs'
  safe_git -C "$root" \
    -c gpg.format=ssh \
    -c gpg.ssh.allowedSignersFile="$allowed_signers" \
    -c gpg.ssh.program=/usr/bin/ssh-keygen \
    verify-commit "$commit" >/dev/null 2>&1 ||
    fail 'commit signature verification failed'
}

verify_signed_commit "$sweep_repo" "$expected_commit" "$sweep_repo/v4/signing/allowed_signers"
verify_signed_commit \
  "$codec_root" e7e0504b15769c925206ad1783d45a9ca0b62207 \
  "$codec_root/signing/allowed_signers"

[[ -r /etc/os-release ]] || fail '/etc/os-release is absent'
grep -qx 'ID=ubuntu' /etc/os-release || fail 'host OS must be Ubuntu'
grep -Eq '^VERSION_ID="?24[.]04"?$' /etc/os-release || fail 'host OS must be Ubuntu 24.04'
[[ "$(uname -m)" = x86_64 ]] || fail 'host architecture must be x86_64'

mapfile -t gpu_inventory < <(
  nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader,nounits 2>/dev/null
)
[[ "${#gpu_inventory[@]}" -eq 1 ]] || fail 'exactly one visible NVIDIA GPU is required'
IFS=',' read -r gpu_name gpu_memory_mib gpu_driver_version <<<"${gpu_inventory[0]}"
gpu_name=$(awk '{$1=$1; print}' <<<"$gpu_name")
gpu_memory_mib=${gpu_memory_mib//[[:space:]]/}
gpu_driver_version=${gpu_driver_version//[[:space:]]/}
[[ "$gpu_memory_mib" =~ ^[0-9]+$ && "$gpu_memory_mib" -ge 40960 ]] ||
  fail 'the single GPU must expose at least 40960 MiB VRAM'
[[ "$gpu_driver_version" =~ ^[0-9]+([.][0-9]+){1,3}$ ]] || fail 'the NVIDIA driver version is invalid'
cpu_count=$(getconf _NPROCESSORS_ONLN)
[[ "$cpu_count" =~ ^[0-9]+$ && "$cpu_count" -ge 8 ]] || fail 'at least 8 online CPUs are required'
ram_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
[[ "$ram_kib" =~ ^[0-9]+$ && "$ram_kib" -ge 33554432 ]] || fail 'at least 32 GiB system RAM is required'
cgroup_admission=$(
  "$python_executable" -E -s -B "$cgroup_contract" admission \
    --minimum-cpu-cores 8 \
    --minimum-memory-bytes 34359738368
) || fail 'current-process cgroup admission failed'
[[ "$cgroup_admission" != *$'\n'* ]] || fail 'cgroup admission output is multiline'
IFS=$'\t' read -r cgroup_version cgroup_cpu_quota cgroup_cpu_period cgroup_memory_max cgroup_extra <<<"$cgroup_admission"
[[ -z "${cgroup_extra-}" && "$cgroup_version" =~ ^v[12]$ ]] || fail 'cgroup admission output differs'
[[ "$cgroup_cpu_quota" = max || "$cgroup_cpu_quota" =~ ^[0-9]+$ ]] || fail 'cgroup CPU quota output is invalid'
[[ "$cgroup_cpu_period" =~ ^[0-9]+$ && "$cgroup_cpu_period" -gt 0 ]] || fail 'cgroup CPU period output is invalid'
[[ "$cgroup_memory_max" = max || "$cgroup_memory_max" =~ ^[0-9]+$ ]] || fail 'cgroup memory limit output is invalid'
unset cgroup_admission cgroup_extra
free_kib=$(df -Pk -- "$run_parent" | awk 'NR == 2 {print $4}')
[[ "$free_kib" =~ ^[0-9]+$ && "$free_kib" -ge 20971520 ]] || fail 'at least 20 GiB free container-disk space is required'

python_version=$(
  "$python_executable" -E -s -B -c 'import platform; print(platform.python_implementation()+" "+platform.python_version())'
) || fail 'cannot execute the supplied Python runtime'
[[ "$python_version" = 'CPython 3.12.13' ]] || fail 'CORELM_LENGTH_PYTHON must be exact CPython 3.12.13'
"$python_executable" -E -s -B "$runtime_safety" validate-runtime --runtime "$runtime_root" >/dev/null ||
  fail 'the supplied CUDA runtime failed path and marker validation'
"$python_executable" -E -s -B "$verify_locks" \
  --runtime "$runtime_root" \
  --lock "$pip_bootstrap_lock" \
  --lock "$portable_runtime_lock" \
  --lock "$cuda_runtime_lock" || fail 'the supplied CUDA runtime differs from the exact three-lock closure'
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
"$python_executable" -E -s -B -c '
import torch
assert torch.cuda.is_available()
assert torch.cuda.device_count() == 1
assert torch.version.cuda == "13.0"
assert torch.cuda.is_bf16_supported()
' || fail 'the exact runtime does not expose one BF16-capable CUDA device'

run_timed() {
  local label=$1
  local seconds=$2
  shift 2
  printf 'STEP %s\n' "$label"
  /usr/bin/timeout --foreground --signal=TERM --kill-after=60s "${seconds}s" "$@"
}

printf 'STEP CONTRACT_TESTS_LENGTH\n'
CORELM_SWEEP_TEST_CODEC_ROOT="$codec_root" CORELM_LENGTH_TEST_CODEC_ROOT="$codec_root" \
  /usr/bin/timeout --foreground --signal=TERM --kill-after=60s 600s \
  "$python_executable" -E -s -B -m unittest discover \
  -s "$script_dir" -p 'test_*.py' -v || fail 'the model-free length-ladder contract tests failed'
printf 'STEP CONTRACT_TESTS_CGROUP\n'
/usr/bin/timeout --foreground --signal=TERM --kill-after=60s 300s \
  "$python_executable" -E -s -B -m unittest discover \
  -s "$adapter_dir" -p 'test_cgroup_contract.py' -v || fail 'the cgroup contract tests failed'

assert_no_auth_files() {
  local checked_home=$1 forbidden_auth_path private_ssh_file
  for forbidden_auth_path in \
    "$checked_home/.cache/huggingface/token" \
    "$checked_home/.cache/huggingface/stored_tokens" \
    "$checked_home/.huggingface/token" \
    "$checked_home/.netrc" \
    "$checked_home/.git-credentials" \
    "$checked_home/.config/gh/hosts.yml" \
    "$checked_home/.aws/credentials" \
    "$checked_home/.config/gcloud/application_default_credentials.json" \
    "$checked_home/.docker/config.json" \
    "$checked_home/.kube/config"
  do
    [[ ! -e "$forbidden_auth_path" ]] || fail 'the Pod image contains a forbidden authentication file'
  done
  if [[ -d "$checked_home/.ssh" && ! -L "$checked_home/.ssh" ]]; then
    private_ssh_file=$(find "$checked_home/.ssh" -maxdepth 1 -type f \
      -name 'id_*' ! -name '*.pub' -print -quit) ||
      fail 'cannot inspect the Pod home for SSH private key material'
    [[ -z "$private_ssh_file" ]] || fail 'the Pod image contains SSH private key material'
  fi
}
assert_no_auth_files /root
[[ "$original_home" = /root ]] || assert_no_auth_files "$original_home"

mkdir -m 0700 -- "$run_root"
mkdir -m 0700 -- \
  "$run_root/assets" \
  "$run_root/evidence" \
  "$run_root/export" \
  "$run_root/home" \
  "$run_root/tmp" \
  "$run_root/xdg-cache" \
  "$run_root/executable-cache"
export HOME="$run_root/home"
export TMPDIR="$run_root/tmp"
export XDG_CACHE_HOME="$run_root/xdg-cache"
export HF_HOME="$run_root/home/huggingface"
export TRITON_CACHE_DIR="$run_root/executable-cache/triton"
export TORCHINDUCTOR_CACHE_DIR="$run_root/executable-cache/torchinductor"
export TORCH_EXTENSIONS_DIR="$run_root/executable-cache/torch-extensions"
export CUDA_CACHE_PATH="$run_root/executable-cache/cuda"
export PYTORCH_KERNEL_CACHE_PATH="$run_root/executable-cache/pytorch-kernels"
mkdir -m 0700 -- \
  "$TRITON_CACHE_DIR" "$TORCHINDUCTOR_CACHE_DIR" "$TORCH_EXTENSIONS_DIR" \
  "$CUDA_CACHE_PATH" "$PYTORCH_KERNEL_CACHE_PATH"

run_timed EXECUTABLE_CACHE_SMOKE 120 \
  "$python_executable" -E -s -B -c '
import os
from pathlib import Path

import torch
from torch._native.ops.bmm_outer_product.triton_kernels import bmm_outer_product

left = torch.ones((1, 32, 1), device="cuda", dtype=torch.bfloat16)
right = torch.ones((1, 1, 32), device="cuda", dtype=torch.bfloat16)
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
'

prepare_assets="$script_dir/prepare_assets.py"
runner="$script_dir/run_length_ladder.py"
verifier="$script_dir/verify_length_ladder.py"
for program in "$prepare_assets" "$runner" "$verifier"; do
  [[ -f "$program" && ! -L "$program" ]] || fail 'a required length-ladder Python program is absent or unsafe'
done
unset program

run_timed ASSET_DOWNLOAD 1800 \
  "$python_executable" -E -s -B "$prepare_assets" download \
  --cache "$run_root/assets" \
  --receipt "$run_root/evidence/assets.json"
assert_no_auth_files "$HOME"

export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1

run_timed ASSET_OFFLINE_VERIFY 600 \
  "$python_executable" -E -s -B "$prepare_assets" verify \
  --cache "$run_root/assets" \
  --receipt "$run_root/evidence/assets.json"

run_timed LENGTH_PREFLIGHT 600 \
  "$python_executable" -E -s -B "$runner" preflight \
  --codec-root "$codec_root" \
  --cache "$run_root/assets" \
  --assets "$run_root/evidence/assets.json" \
  --output "$run_root/evidence/preflight.json"

# The orchestrator is the sole matrix command: six fresh direct-prefill model
# processes followed by six fresh codec-only master-slice processes.  Internal
# Direct workers use the registered P-specific limits 600, 600, 600, 600,
# 900, and 1350 seconds in ascending P order.  Each fresh codec-only secondary
# worker uses 300 seconds.  Their 6,450-second sum has 1,950 seconds of
# process-group cleanup and manifest reserve inside this outer bound.
run_timed LENGTH_ORCHESTRATE 8400 \
  "$python_executable" -E -s -B "$runner" orchestrate \
  --codec-root "$codec_root" \
  --cache "$run_root/assets" \
  --assets "$run_root/evidence/assets.json" \
  --preflight "$run_root/evidence/preflight.json" \
  --run-dir "$run_root/evidence/run"

run_timed LENGTH_STRUCTURAL_VERIFY 1800 \
  "$python_executable" -E -s -B "$verifier" verify \
  --codec-root "$codec_root" \
  --cache "$run_root/assets" \
  --assets "$run_root/evidence/assets.json" \
  --preflight "$run_root/evidence/preflight.json" \
  --run-dir "$run_root/evidence/run" \
  --output "$run_root/evidence/structural-verification.json"

run_timed LENGTH_RENDER_RESULTS 60 \
  "$python_executable" -E -s -B "$verifier" render-results \
  --structural "$run_root/evidence/structural-verification.json" \
  --output "$run_root/evidence/RESULTS.md"

mkdir -m 0700 -- "$run_root/evidence/replays"
for replay_level in p000256 p000512 p001024 p002048 p004096 p008192; do
  case "$replay_level" in
    p000256|p000512|p001024|p002048) replay_timeout=600 ;;
    p004096) replay_timeout=900 ;;
    p008192) replay_timeout=1350 ;;
    *) fail 'unregistered replay level reached the closed replay loop' ;;
  esac
  run_timed "REPLAY_${replay_level}" "$replay_timeout" \
    "$python_executable" -E -s -B "$verifier" replay-cell \
    --codec-root "$codec_root" \
    --cache "$run_root/assets" \
    --assets "$run_root/evidence/assets.json" \
    --preflight "$run_root/evidence/preflight.json" \
    --run-dir "$run_root/evidence/run" \
    --structural "$run_root/evidence/structural-verification.json" \
    --length-level "$replay_level" \
    --output "$run_root/evidence/replays/${replay_level}.json"
done
unset replay_level replay_timeout

assert_exact_checkout "$sweep_repo" "$expected_commit" "$expected_tree"
assert_exact_checkout \
  "$codec_root" e7e0504b15769c925206ad1783d45a9ca0b62207 \
  924d3195122e3a486e2d26e4fbdfe574654ae6c8
verify_signed_commit "$sweep_repo" "$expected_commit" "$sweep_repo/v4/signing/allowed_signers"
verify_signed_commit \
  "$codec_root" e7e0504b15769c925206ad1783d45a9ca0b62207 \
  "$codec_root/signing/allowed_signers"

printf '%s\n' \
  'schemaVersion=corelm-runpod-length-ladder-source-v1' \
  "sweepCommit=$expected_commit" \
  "sweepTree=$expected_tree" \
  'commitSignatureTrustRootSHA256=36fb4a170eee7664be32f2a5d562db209fa4f6f1f24667cf6a3ef0166d155c16' \
  'sweepCommitSignatureVerified=true' \
  'codecCommit=e7e0504b15769c925206ad1783d45a9ca0b62207' \
  'codecTree=924d3195122e3a486e2d26e4fbdfe574654ae6c8' \
  'codecCommitSignatureVerified=true' \
  'classification=PREREGISTERED_PUBLIC_LENGTH_LADDER_ONLY' \
  'scientificEvidence=false' \
  'countsTowardScientificVerdict=false' \
  'platform=RunPod Pod' \
  'isolationBoundary=provider-managed-container-not-independent-VM' \
  'modelId=qwen2.5-0.5b' \
  'workloadId=tracked-technical-prose-v1' \
  'prefillTokens=256,512,1024,2048,4096,8192' \
  'structurallyVerifiedDirectCells=6' \
  'structurallyVerifiedSecondaryControls=6' \
  'samePodModelReplays=6' \
  'allSeriesModelReplay=true' \
  'independentModelReplay=false' \
  'registeredResultsRendererCompleted=true' \
  'applicationOfflineAfterAssetDownload=true' \
  'packetLevelNetworkIsolationProved=false' \
  'executionPathsOnRootFilesystemDevice=true' \
  'executionPathsCrossOrContainNonRootMounts=false' \
  'podVolumeUsed=false' \
  'networkVolumeUsed=false' \
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
[[ -z "$(find "$run_root/evidence" -type l -print -quit)" ]] || fail 'evidence contains a symlink'
[[ -z "$(find "$run_root/evidence" ! -type d ! -type f -print -quit)" ]] || fail 'evidence contains a special filesystem object'
[[ -z "$(find "$run_root/evidence" -type f -links +1 -print -quit)" ]] || fail 'evidence contains a hard-linked regular file'
[[ -z "$(find "$run_root/evidence" ! -uid "$(id -u)" -print -quit)" ]] || fail 'evidence contains an object owned by another user'

# A successful scan emits no matching line, so it cannot disclose a credential
# or private endpoint to the terminal.
privacy_status=0
grep -R -I -q -E \
  '(hf_[A-Za-z0-9]{20,}|HF_TOKEN|HUGGING_FACE_HUB_TOKEN|RUNPOD_API_KEY|'\
'GITHUB_TOKEN|GH_TOKEN|AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)|'\
'SSH_(AUTH_SOCK|CONNECTION)|pod(Id|_id)|/workspace/|/root/)' \
  "$run_root/evidence" || privacy_status=$?
[[ "$privacy_status" -eq 1 ]] || fail 'privacy scan rejected the evidence tree or could not read it'
for private_path in \
  "$run_root" "$sweep_repo" "$codec_root" "$runtime_root" \
  "$HOME" "$original_home"
do
  privacy_status=0
  grep -R -I -F -q -- "$private_path" "$run_root/evidence" || privacy_status=$?
  [[ "$privacy_status" -eq 1 ]] || fail 'privacy scan found a private absolute path or could not read evidence'
done
unset private_path privacy_status

archive_tar="$run_root/export/corelm-runpod-length-ladder-v1.tar"
archive="$archive_tar.gz"
run_timed ARCHIVE_TAR 600 \
  /usr/bin/tar \
  --sort=name \
  --format=gnu \
  --mtime='UTC 1970-01-01' \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -C "$run_root" \
  -cf "$archive_tar" evidence
chmod 0600 "$archive_tar"
run_timed ARCHIVE_GZIP 300 /usr/bin/gzip -n -9 -- "$archive_tar"
[[ -f "$archive" && ! -L "$archive" ]] || fail 'archive compression did not produce the registered file'
chmod 0600 "$archive"
(
  cd "$run_root/export"
  sha256sum "$(basename -- "$archive")" >SHA256SUMS
  chmod 0600 SHA256SUMS
  sha256sum -c SHA256SUMS
)

printf 'RUNPOD LENGTH COMPLETE\n'
printf 'Retrieve both files over the host-key-pinned SSH channel:\n'
printf '  %s\n' "$archive" "$run_root/export/SHA256SUMS"
printf 'Verify locally before terminating the Pod; never publish the assets, runtime, home, or cache directories.\n'

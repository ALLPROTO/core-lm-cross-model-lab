# Secure one-shot RunPod length-ladder execution

This runbook executes the six registered prefill lengths in `ladder.json` for
one unchanged Qwen checkpoint, tokenizer, technical-prose workload, dynamic
cache adapter, and codec configuration.  The result is classified
`PREREGISTERED_PUBLIC_LENGTH_LADDER_ONLY`, sets
`countsTowardScientificVerdict=false`, and does not alter a frozen Core LM
verdict.

## Platform and evidence boundary

A RunPod **Pod** is a provider-managed Linux container.  It is not an
independently administered VM and this contour makes no claim about control of
the host kernel, hypervisor, or physical machine.  The producer, structural
verifier, and six replay processes use the same Pod, signed source,
runtime, and public model snapshot.  They are useful same-environment checks,
not independent replication.

The primary series is six fresh direct-prefill model processes.  Only after all
six finish does the orchestrator run six fresh codec-only processes over exact
prefix slices of the retained P=8192 raw BF16 cache.  The structural verifier
checks all **6 direct cells and 6 secondary controls**, including offline raw
re-encoding.  The launcher then performs exactly **6 same-Pod model replays**,
one at every registered P.  This establishes fresh direct-cache provenance at
all points without claiming that the replays are independent replications.

`run_on_runpod.sh` is one shot.  It requires exact detached, signed, byte-clean
sweep and codec checkouts; the exact locked CUDA runtime; one admitted GPU; and
a previously nonexistent output root.  It neither provisions nor terminates a
Pod.

## Prospective CPU-quota amendment

The signed preregistration commit
`b0f3b207dcddcd19c921d52bd73871508e335e79` and signed provider-credential
successor `28cfda0b32b9cb3f33a028b73b325a9e6751da5a` both preceded this operational
amendment. Three later allocation/admission probes stopped before any model
asset download: two at control-plane envelope readback and one at the
current-process cgroup resource gate. None performed inference or exposed an
experimental result. The amendment is therefore prospective to the first
evidence-producing attempt.

The Pod must still expose at least eight online logical CPUs. Separately, the
minimum accepted finite current-process cgroup CPU quota ceiling is exactly
seven core-equivalents: `quota >= 7 * period` for cgroup v2 `cpu.max`, or
`cpu.cfs_quota_us >= 7 * cpu.cfs_period_us` for cgroup v1. An explicit unlimited
quota remains admissible; a finite quota below this floor is not. The
hypothesis, exact model assets, workload, six `P` values, codec, execution
order, estimand, decision and publication rules, and all timeouts are
unchanged. Because no timeout is relaxed, less CPU capacity can only make a
stage visibly `INCOMPLETE`; it cannot change, filter, substitute, or silently
retry a result.

## Provisioning envelope and cost fuse

Use an on-demand **Secure Cloud** Pod with this minimum envelope:

| Item | Required value |
|---|---|
| GPU | exactly one NVIDIA CUDA GPU, at least 40,960 MiB visible VRAM, BF16 support |
| CPU and RAM | at least 8 online logical CPUs; current-process cgroup v1/v2 CPU quota ceiling of at least 7 core-equivalents or explicit unlimited; at least 32 GiB RAM with a matching cgroup limit |
| Userspace | Ubuntu 24.04, x86_64, GNU Bash 5 or newer |
| Image | resolved and recorded as an immutable `sha256:<64-hex>` digest |
| Runtime | only `runpod-adapter-sweep-v1/build_cuda_runtime.sh`; CPython 3.12.13, PyTorch 2.13.0+cu130 |
| Container disk | 50 GB, with at least 20 GiB free at launcher admission |
| Pod/network volume | none |
| Exposure | SSH only; no Jupyter and no public application ports |
| Lifecycle fuse | provider-side terminate-after **10 hours** from Pod creation |
| Spend fuse | combined live rate at most **USD 0.50/hour** and projected total at most **USD 5.00** |

An A40 48 GB is the preferred low-cost shape when it satisfies the live
resource and price gates.  At a combined rate around USD 0.44685/hour, ten
hours projects to about USD 4.47; this is only an illustrative estimate, not a
price quote.  The registration does not bind a GPU marketing
name; all twelve producer/control processes must remain on the one admitted
device, whose exact identity is recorded.  Recheck the authenticated live offer
before creation.  Refuse the Pod if either rate or ten-hour projection exceeds
the limits above.  An account-level spend limit is not a per-Pod fuse, so the
provider termination timer is mandatory.

Use only container disk.  Do not attach a Pod volume or network volume: stopped
Pod volumes and network volumes can outlive active compute and continue to
incur cost.  Terminate rather than stop the Pod after verified retrieval.
The launcher also requires source, codec, runtime, bootstrap home, and attempt
parent to have the same filesystem device identity as `/`.  That closes the
registered execution path against an accidentally selected mounted volume; it
also rejects a non-root mount at, above, or below any execution path.  This is
not a provider attestation that no unrelated mount exists elsewhere.

Authoritative platform references:

- [RunPod GPU pricing](https://www.runpod.io/pricing)
- [Pod pricing and billing](https://docs.runpod.io/pods/pricing)
- [Pod storage types](https://docs.runpod.io/pods/storage/types)
- [Manage and terminate Pods](https://docs.runpod.io/pods/manage-pods)
- [RunPod-provided environment variables](https://docs.runpod.io/pods/templates/environment-variables)

## Network and credential boundary

Network access is required to clone the two public repositories, build the
hash-locked runtime, and anonymously materialize the pinned public Qwen files.
After the asset receipt is written, the launcher sets `HF_HUB_OFFLINE=1`,
`TRANSFORMERS_OFFLINE=1`, and `HF_HUB_DISABLE_IMPLICIT_TOKEN=1` for all
preflight, model, codec, verifier, and replay work.

This is application/library-level offline behavior.  The launcher does not
install a firewall or prove that the managed container lacks an egress route.

Create no RunPod Secret and no Hugging Face token for this run.  Do not inject
`HF_TOKEN`, `HUGGING_FACE_HUB_TOKEN`, a GitHub token, an operator RunPod API
key, a cloud credential, a signing key, an SSH client private key, or an agent
socket.  RunPod automatically injects one Pod-scoped `RUNPOD_API_KEY` into PID
1.  That unavoidable provider field is the sole credential-name exception at
the PID 1 boundary: the entrypoint requires exactly that one credential name,
disables core dumps before the bounded read, discards all values, and never
copies the provider key into its own environment or the clean `execve`.
Every credential field in the application entry environment, and every other
credential name in PID 1, is a terminal failure.  Before asset access, Bash
also rejects conventional
Hugging Face, GitHub CLI, Git, AWS, Google, Docker, Kubernetes, and netrc
credential files plus SSH client private-key filenames in both `/root` and the
registered bootstrap home; it repeats the check in the fresh run home after
download.  The downloader explicitly uses anonymous `token=False`.

Provisioning authority remains local.  If a short-lived RunPod lifecycle API
key is used by the operator, keep it only in the local control process and
delete it after termination.  Give the Pod only a newly generated Ed25519
**public** login key.  Keep its private half and a mode-0600 `known_hosts` file
locally.  Pin the exact ED25519 host key obtained through the authenticated
control plane before the first SSH command; never use
`StrictHostKeyChecking=no` or `accept-new`.

## Exact source and runtime

Obtain the preregistered sweep commit and tree from the signed public record,
not from the checkout being tested.  Replace the placeholders below:

```text
LENGTH_COMMIT=<PUBLISHED_40_HEX_PREREGISTRATION_COMMIT>
LENGTH_TREE=<PUBLISHED_40_HEX_PREREGISTRATION_TREE>
POD_IMAGE_DIGEST=sha256:<AUTHENTICATED_CONTROL_PLANE_64_HEX_DIGEST>
```

The codec identity is fixed:

```text
commit e7e0504b15769c925206ad1783d45a9ca0b62207
tree   924d3195122e3a486e2d26e4fbdfe574654ae6c8
```

Create one owner-private top-level directory on container disk.  The following
layout keeps source, codec, runtime, and attempt roots disjoint:

```bash
set -eu
set +x
unset RUNPOD_API_KEY
ulimit -c 0
test "$(ulimit -c)" = 0
umask 077
PRIVATE_ROOT=/corelm-length
BOOTSTRAP_HOME=$PRIVATE_ROOT/bootstrap-home
SWEEP_SOURCE=$PRIVATE_ROOT/sweep-source
CODEC_SOURCE=$PRIVATE_ROOT/codec-source
RUNTIME_ROOT=$PRIVATE_ROOT/cuda-runtime
ATTEMPT_PARENT=$PRIVATE_ROOT/attempts
mkdir -m 0700 -- "$PRIVATE_ROOT" "$BOOTSTRAP_HOME" "$ATTEMPT_PARENT"

env -i HOME="$BOOTSTRAP_HOME" PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  GIT_ASKPASS=/bin/false GIT_TERMINAL_PROMPT=0 \
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
  /usr/bin/git -c core.hooksPath=/dev/null -c protocol.file.allow=never \
  clone https://github.com/ALLPROTO/core-lm-cross-model-lab.git \
  "$SWEEP_SOURCE"
env -i HOME="$BOOTSTRAP_HOME" PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  GIT_ASKPASS=/bin/false GIT_TERMINAL_PROMPT=0 \
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
  /usr/bin/git -c core.hooksPath=/dev/null -c protocol.file.allow=never \
  clone https://github.com/ALLPROTO/core-lm-benchmark.git \
  "$CODEC_SOURCE"
env -i HOME="$BOOTSTRAP_HOME" PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
  /usr/bin/git -c core.hooksPath=/dev/null -c protocol.file.allow=never \
  -C "$SWEEP_SOURCE" checkout --detach "$LENGTH_COMMIT"
env -i HOME="$BOOTSTRAP_HOME" PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
  /usr/bin/git -c core.hooksPath=/dev/null -c protocol.file.allow=never \
  -C "$CODEC_SOURCE" checkout --detach \
  e7e0504b15769c925206ad1783d45a9ca0b62207
export HOME="$BOOTSTRAP_HOME"
```

Before executing any checked-out program, define and run this operator-entered
bootstrap.  It never sources a worktree file.  Every Git command disables
worktree hooks, filesystem monitors, and file transports; every command failure
is captured rather than hidden by an empty command substitution.  It verifies
detached/full history, no grafts or replacement refs, no index flags, no
tracked/untracked/ignored bytes, raw bytes for every tracked blob, the exact
tree, and the commit signature under the pinned trust root:

```bash
set -eu
set +x
umask 077
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
unset BASH_ENV ENV CDPATH GLOBIGNORE SSH_AUTH_SOCK

bootstrap_fail() {
  printf 'SOURCE BOOTSTRAP FAIL: %s\n' "$1" >&2
  return 1
}

bootstrap_git() {
  /usr/bin/env -i \
    HOME="$BOOTSTRAP_HOME" \
    PATH=/usr/bin:/bin \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 \
    /usr/bin/git \
    -c core.fsmonitor=false \
    -c core.untrackedCache=false \
    -c core.hooksPath=/dev/null \
    -c protocol.file.allow=never \
    "$@"
}

verify_source_checkout() {
  local root=$1 required_commit=$2 required_tree=$3 signers=$4
  local observed git_directory replace_refs status index_listing tracked
  local relative tree_entry mode tail type expected raw_observed
  local signer_line signer_digest root_mode

  test "$root" = "$(/usr/bin/readlink -f -- "$root")" && \
    test -d "$root" && test ! -L "$root" || \
    bootstrap_fail 'checkout root is not canonical'
  test "$(/usr/bin/stat -c '%u' -- "$root")" -eq "$(/usr/bin/id -u)" || \
    bootstrap_fail 'checkout root is not owner controlled'
  root_mode=$(/usr/bin/stat -c '%a' -- "$root") || \
    bootstrap_fail 'cannot inspect checkout mode'
  case "$root_mode" in
    *[2367][0-7]|*[0-7][2367]) bootstrap_fail 'checkout root is group/world writable' ;;
  esac
  observed=$(bootstrap_git -C "$root" rev-parse --show-toplevel) || \
    bootstrap_fail 'cannot resolve checkout root'
  test "$observed" = "$root" || bootstrap_fail 'checkout top level differs'
  git_directory=$(bootstrap_git -C "$root" rev-parse --absolute-git-dir) || \
    bootstrap_fail 'cannot resolve Git directory'
  test -d "$git_directory" && test ! -L "$git_directory" || \
    bootstrap_fail 'Git directory is unsafe'
  observed=$(bootstrap_git -C "$root" rev-parse --verify HEAD) || \
    bootstrap_fail 'cannot resolve commit'
  test "$observed" = "$required_commit" || bootstrap_fail 'commit differs'
  observed=$(bootstrap_git -C "$root" rev-parse --verify 'HEAD^{tree}') || \
    bootstrap_fail 'cannot resolve tree'
  test "$observed" = "$required_tree" || bootstrap_fail 'tree differs'
  if bootstrap_git -C "$root" symbolic-ref -q HEAD >/dev/null 2>&1; then
    bootstrap_fail 'checkout is not detached'
  fi
  observed=$(bootstrap_git -C "$root" rev-parse --is-shallow-repository) || \
    bootstrap_fail 'cannot inspect shallow state'
  test "$observed" = false || bootstrap_fail 'checkout is shallow'
  test ! -e "$git_directory/shallow" && \
    test ! -e "$git_directory/info/grafts" || \
    bootstrap_fail 'checkout contains shallow or graft metadata'
  replace_refs=$(bootstrap_git -C "$root" for-each-ref \
    --format='%(refname)' refs/replace) || \
    bootstrap_fail 'cannot inspect replacement refs'
  test -z "$replace_refs" || bootstrap_fail 'replacement refs exist'
  status=$(bootstrap_git -C "$root" --no-optional-locks status \
    --porcelain=v1 --untracked-files=all --ignored=matching) || \
    bootstrap_fail 'cannot inspect worktree status'
  test -z "$status" || bootstrap_fail 'checkout is not byte-clean'
  index_listing=$(bootstrap_git -C "$root" ls-files -v) || \
    bootstrap_fail 'cannot inspect index flags'
  if /usr/bin/grep -E '^[a-zS]' <<<"$index_listing" >/dev/null; then
    bootstrap_fail 'index contains assume-unchanged or skip-worktree flags'
  fi
  tracked=$(bootstrap_git -C "$root" ls-tree -r --name-only HEAD) || \
    bootstrap_fail 'cannot enumerate tracked files'
  test -n "$tracked" || bootstrap_fail 'checkout has no tracked files'
  while IFS= read -r relative; do
    case "$relative" in *$'\t'*|*$'\r'*) bootstrap_fail 'unsafe tracked path' ;; esac
    test -f "$root/$relative" && test ! -L "$root/$relative" || \
      bootstrap_fail 'tracked source is not a regular file'
    tree_entry=$(bootstrap_git -C "$root" ls-tree \
      --format='%(objectmode) %(objecttype) %(objectname)' \
      HEAD -- "$relative") || bootstrap_fail 'cannot inspect tree entry'
    mode=${tree_entry%% *}
    tail=${tree_entry#* }
    type=${tail%% *}
    tail=${tail#* }
    expected=${tail%% *}
    test "$type" = blob || bootstrap_fail 'tree entry is not a blob'
    case "$mode" in 100644|100755) ;; *) bootstrap_fail 'tree mode differs' ;; esac
    raw_observed=$(bootstrap_git -C "$root" hash-object --no-filters \
      -- "$root/$relative") || bootstrap_fail 'cannot hash raw worktree file'
    test "$raw_observed" = "$expected" || bootstrap_fail 'raw worktree bytes differ'
  done <<<"$tracked"
  test -f "$signers" && test ! -L "$signers" || \
    bootstrap_fail 'allowed_signers is absent or unsafe'
  signer_line=$(/usr/bin/sha256sum "$signers") || \
    bootstrap_fail 'cannot hash allowed_signers'
  signer_digest=${signer_line%% *}
  test "$signer_digest" = \
    36fb4a170eee7664be32f2a5d562db209fa4f6f1f24667cf6a3ef0166d155c16 || \
    bootstrap_fail 'allowed_signers digest differs'
  bootstrap_git -C "$root" \
    -c gpg.format=ssh \
    -c gpg.ssh.allowedSignersFile="$signers" \
    -c gpg.ssh.program=/usr/bin/ssh-keygen \
    verify-commit "$required_commit" >/dev/null 2>&1 || \
    bootstrap_fail 'commit signature verification failed'
}

verify_source_checkout "$SWEEP_SOURCE" "$LENGTH_COMMIT" "$LENGTH_TREE" \
  "$SWEEP_SOURCE/v4/signing/allowed_signers"
verify_source_checkout "$CODEC_SOURCE" \
  e7e0504b15769c925206ad1783d45a9ca0b62207 \
  924d3195122e3a486e2d26e4fbdfe574654ae6c8 \
  "$CODEC_SOURCE/signing/allowed_signers"
```

Keep these functions in the trusted setup shell.  The launcher and reused
builder repeat the same gates, but a worktree program cannot bootstrap trust in
itself.  The operator-entered calls above are therefore mandatory.  The pinned
`allowed_signers` digest is the external trust root.

Build the runtime outside both checkouts.  The `CORELM_SWEEP_*` names below are
intentional because the length contour reuses the already reviewed adapter
suite builder and its three exact locks at the same signed source identity:

```bash
set -eu
set +x
unset RUNPOD_API_KEY
ulimit -c 0
test "$(ulimit -c)" = 0
export CORELM_SWEEP_EXPECTED_COMMIT="$LENGTH_COMMIT"
export CORELM_SWEEP_EXPECTED_TREE="$LENGTH_TREE"
export CORELM_SWEEP_CODEC_ROOT="$CODEC_SOURCE"
export CORELM_SWEEP_RUNTIME="$RUNTIME_ROOT"
test ! -e "$RUNTIME_ROOT"
verify_source_checkout "$SWEEP_SOURCE" "$LENGTH_COMMIT" "$LENGTH_TREE" \
  "$SWEEP_SOURCE/v4/signing/allowed_signers"
verify_source_checkout "$CODEC_SOURCE" \
  e7e0504b15769c925206ad1783d45a9ca0b62207 \
  924d3195122e3a486e2d26e4fbdfe574654ae6c8 \
  "$CODEC_SOURCE/signing/allowed_signers"
/usr/bin/timeout --foreground --signal=TERM --kill-after=60s 7200s \
  "$SWEEP_SOURCE/runpod-adapter-sweep-v1/build_cuda_runtime.sh"
```

The builder creates exact CPython 3.12.13 plus the hash-locked portable and
CUDA package closure, requires PyTorch 2.13.0+cu130 and one BF16 CUDA device,
hardens the owner-only runtime, and publishes it atomically.  Do not replace it
with `pip install`, a notebook, or an interactive virtual environment.

## Launch

Repeat the external identity/signature block immediately before launch.  The
attempt parent must already exist and be mode 0700; the attempt root must not
exist.  Use a new root for every failed or complete attempt.

Invoke the entrypoint with an empty environment and only the six registered
non-secret inputs plus `HOME`:

```bash
set -eu
set +x
unset RUNPOD_API_KEY
ulimit -c 0
test "$(ulimit -c)" = 0
RUN_ROOT=$ATTEMPT_PARENT/attempt-01
test ! -e "$RUN_ROOT"
verify_source_checkout "$SWEEP_SOURCE" "$LENGTH_COMMIT" "$LENGTH_TREE" \
  "$SWEEP_SOURCE/v4/signing/allowed_signers"
verify_source_checkout "$CODEC_SOURCE" \
  e7e0504b15769c925206ad1783d45a9ca0b62207 \
  924d3195122e3a486e2d26e4fbdfe574654ae6c8 \
  "$CODEC_SOURCE/signing/allowed_signers"
cd "$SWEEP_SOURCE"
exec /usr/bin/env -i \
  HOME="$BOOTSTRAP_HOME" \
  CORELM_LENGTH_EXPECTED_COMMIT="$LENGTH_COMMIT" \
  CORELM_LENGTH_EXPECTED_TREE="$LENGTH_TREE" \
  CORELM_LENGTH_CODEC_ROOT="$CODEC_SOURCE" \
  CORELM_LENGTH_PYTHON="$RUNTIME_ROOT/bin/python" \
  CORELM_LENGTH_ROOT="$RUN_ROOT" \
  CORELM_LENGTH_IMAGE_DIGEST="$POD_IMAGE_DIGEST" \
  "$RUNTIME_ROOT/bin/python" -I -B \
  ./runpod-length-ladder-v1/launch_runpod.py
```

The entrypoint requires only RunPod's documented Pod-scoped key name in PID 1,
rejects every credential in its own entry environment and every other PID 1
credential name, and uses `execve` to enter exact `/bin/bash` with the same
seven non-secret fields.  Bash then removes all inherited names and constructs
the fixed runtime environment before any source or asset action.

The admitted command sequence is:

1. Length-suite model-free tests, then the shared cgroup contract tests.
2. The exact pinned Triton `bmm_outer_product` CUDA smoke test, requiring its
   `cuda_utils` shared object only below the registered executable cache and no
   shared objects below `HOME`, `TMPDIR`, or `XDG_CACHE_HOME`.
3. Anonymous Qwen download and exact digest receipt.
4. Credential-file rejection and application-offline asset verification.
5. Nested-token preflight for P=256, 512, 1,024, 2,048, 4,096, and 8,192.
6. One orchestrator: six fresh direct cells in the registered nonmonotone order,
   then six fresh codec-only controls sourced only from the P=8192 direct raw
   anchor.
7. One structural verification of all six direct and all six secondary outputs,
   including retained raw BF16 re-encoding and exact integer trend arithmetic.
8. The registered model-free renderer writes `evidence/RESULTS.md` from the
   structurally verified receipt, before any replay or packaging step.
9. Six same-Pod model replays, one at every registered P.
10. Source re-verification, privacy checks, and deterministic evidence-only
   packaging.

Internal `run-cell` and `run-secondary` commands are not operator entrypoints.
The orchestrator launches each in a fresh process group, applies the selected
Qwen profile's maximum as the P=8,192 ceiling and the registered P-specific
direct limits of 600, 600, 600, 600, 900, and 1,350 seconds in ascending P
order.  Each codec-only secondary worker has a separate 300-second limit.  It
never silently retries.  The six direct ceilings sum to 4,650 seconds and the
six secondary ceilings sum to 1,800 seconds; the 8,400-second outer
orchestrator therefore reserves 1,950 seconds for deterministic process-group
cleanup and run-manifest closure.  A timeout, OOM, signal, missing artifact,
nonzero exit, digest mismatch, or surviving process group makes the attempt
incomplete.  Never rerun into the same root.

The wrapper ceilings are:

| Stage | Seconds |
|---|---:|
| Length tests | 600 |
| Cgroup tests | 300 |
| Exact Triton CUDA executable-cache smoke | 120 |
| Anonymous asset download | 1,800 |
| Offline asset verification | 600 |
| Preflight | 600 |
| Complete orchestrator | 8,400 |
| Structural verification | 1,800 |
| Registered results renderer | 60 |
| Six registered-length replays | P-specific: 600, 600, 600, 600, 900, 1,350 |
| Tar plus gzip | 600 + 300 |

These launcher ceilings total 19,830 seconds (5:30:30).  With the 7,200-second
runtime-builder ceiling, the nominal admitted compute path totals 27,030 seconds
(7:30:30), leaving 2 hours 29 minutes 30 seconds inside the ten-hour provider fuse for
cloning, control checks, retrieval, and termination.  The first failing outer
timed command may add up to a 60-second TERM-to-KILL grace before the
fail-closed wrapper exits; later stages do not start.  Direct and secondary
worker cleanup occurs inside the orchestrator's 1,950-second reserve.  On the
first terminal failure, retrieve only bounded diagnostics if safe and
terminate immediately; the provider ten-hour fuse remains absolute.  Start
result retrieval immediately on successful completion.

## Archive retrieval and local verification

The launcher packages only `evidence/`.  It excludes model assets, runtime,
home, temporary files, executable caches, and all private control data.  The
two output files are:

```text
corelm-runpod-length-ladder-v1.tar.gz
SHA256SUMS
```

Retrieve both over the host-key-pinned channel:

```bash
REMOTE_EXPORT=/corelm-length/attempts/attempt-01/export
LOCAL_EVIDENCE_DIR=$(mktemp -d \
  "${TMPDIR:-/tmp}/corelm-length-evidence.XXXXXX")
LOCAL_EVIDENCE_DIR=$(cd "$LOCAL_EVIDENCE_DIR" && pwd -P)
chmod 0700 "$LOCAL_EVIDENCE_DIR"
scp -P "$SSH_PORT" \
  -i "$EPHEMERAL_SSH_PRIVATE_KEY" \
  -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$PINNED_KNOWN_HOSTS" \
  "root@$SSH_HOST:$REMOTE_EXPORT/corelm-runpod-length-ladder-v1.tar.gz" \
  "root@$SSH_HOST:$REMOTE_EXPORT/SHA256SUMS" \
  "$LOCAL_EVIDENCE_DIR/"
```

Before extraction, require exact inventory, checksum grammar, file bounds, and
safe tar members:

```bash
set -e
python3 - "$LOCAL_EVIDENCE_DIR" <<'PY'
import os
import hashlib
import pathlib
import re
import stat
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
status = root.lstat()
if (
    not stat.S_ISDIR(status.st_mode)
    or status.st_uid != os.getuid()
    or status.st_mode & 0o077
    or root.resolve(strict=True) != root
):
    raise SystemExit("local evidence directory is not private and canonical")
limits = {
    "corelm-runpod-length-ladder-v1.tar.gz": 4 * 1024**3,
    "SHA256SUMS": 1024,
}
if {entry.name for entry in root.iterdir()} != set(limits):
    raise SystemExit("local evidence directory inventory differs")
for name, maximum in limits.items():
    item = (root / name).lstat()
    if (
        not stat.S_ISREG(item.st_mode)
        or item.st_nlink != 1
        or item.st_uid != os.getuid()
        or not 0 < item.st_size <= maximum
    ):
        raise SystemExit(f"unsafe transferred file: {name}")
raw = (root / "SHA256SUMS").read_bytes()
match = re.fullmatch(
    rb"[0-9a-f]{64}  corelm-runpod-length-ladder-v1[.]tar[.]gz\n",
    raw,
)
if match is None:
    raise SystemExit("SHA256SUMS grammar differs")
archive_path = root / "corelm-runpod-length-ladder-v1.tar.gz"
digest = hashlib.sha256()
with archive_path.open("rb") as source:
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
if digest.hexdigest().encode("ascii") != raw[:64]:
    raise SystemExit("archive checksum differs")
with tarfile.open(archive_path, "r|gz") as archive:
    count = 0
    total = 0
    seen = set()
    for member in archive:
        count += 1
        if count > 4096:
            raise SystemExit("archive member count exceeded")
        path = pathlib.PurePosixPath(member.name)
        if (
            path.is_absolute()
            or not path.parts
            or path.parts[0] != "evidence"
            or ".." in path.parts
            or not (member.isfile() or member.isdir())
        ):
            raise SystemExit(f"unsafe archive member: {member.name!r}")
        canonical = path.as_posix()
        if canonical in seen:
            raise SystemExit(f"duplicate archive member: {member.name!r}")
        seen.add(canonical)
        total += member.size
        if total > 4 * 1024**3:
            raise SystemExit("archive expansion bound exceeded")
    if count == 0:
        raise SystemExit("archive is empty")
PY
chmod 0600 "$LOCAL_EVIDENCE_DIR/corelm-runpod-length-ladder-v1.tar.gz" \
  "$LOCAL_EVIDENCE_DIR/SHA256SUMS"
cd "$LOCAL_EVIDENCE_DIR"
sha256sum -c SHA256SUMS
```

On macOS, use `shasum -a 256 -c SHA256SUMS` for the final checksum command.
This proves transfer integrity relative to the checksum retrieved from the same
Pod and rejects unsafe archive topology.  It is not an independent semantic or
model verification.

## Termination and cleanup

Only after checksum and archive-inventory verification succeeds:

1. Terminate the Pod; do not stop it.
2. Confirm through the authenticated control plane that the Pod is absent and
   that no Pod or network volume exists.
3. Capture the final billed duration and cost without recording Pod IDs,
   endpoints, private paths, or credentials in public evidence.
4. Delete the local short-lived RunPod lifecycle API key, if one was created.
5. Remove the ephemeral SSH public key from RunPod and retire its local private
   key and pinned `known_hosts` entry according to operator policy.
6. Confirm that no reusable template contains a credential, source, asset,
   runtime, or evidence path.

No Hugging Face token or RunPod Secret exists to revoke in this contour.  If
either was accidentally created or mapped, the attempt violates admission:
terminate it, delete/revoke the credential, and start a wholly new attempt only
after correcting the template.

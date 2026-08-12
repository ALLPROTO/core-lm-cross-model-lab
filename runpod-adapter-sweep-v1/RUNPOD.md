# Secure one-shot RunPod Pod execution

This runbook launches the seven-profile, four-workload matrix defined by
`profiles.json` and `workloads.json`. Its classification is
`EXPLORATORY_PUBLIC_REGRESSION_ONLY`. It is not scientific evidence, does not
extend the frozen V15 verdict, and does not establish support for every model
in an architecture family.

## Platform and claim boundary

A RunPod **Pod** is a provider-managed Linux container with assigned GPU,
storage, cgroup limits, and network connectivity. This contour does not boot or
test a virtual machine and makes no claim about an independently controlled
kernel, hypervisor, or host. The producer, structural verifier, and replay
verifier run in the same Pod from the same source, runtime, model cache, and
operator-controlled attempt. That is useful corroboration, but it is **not an
independent replication**.

`run_on_runpod.sh` is deliberately one shot. It requires exact detached and
sterile sweep and codec checkouts, an exact CUDA runtime, a previously
nonexistent output root, one CUDA device, an immutable container-image digest,
and an inherited Hugging Face secret. It does not provision or terminate a Pod.

## Provisioning envelope and cost fuse

Use an on-demand **Secure Cloud** Pod with this minimum envelope:

| Item | Required value |
|---|---|
| GPU | exactly one NVIDIA CUDA GPU, any supported model name, at least 78,000 MiB visible VRAM, BF16 support |
| CPU / RAM | at least 16 online CPUs and 110 GiB RAM, with matching current-process cgroup v1 or v2 limits |
| Container userspace | Ubuntu 24.04, x86_64; GNU Bash 5 or newer |
| Container image | pinned by an immutable `sha256:<64-hex>` digest |
| Runtime | produced only by `build_cuda_runtime.sh`; exact CPython 3.12.13 and PyTorch 2.13.0+cu130 |
| Container disk | 50 GB |
| Pod volume | 150 GB, encrypted, at least 100 GiB free at launch |
| Exposure | SSH only; no public Jupyter or port 8888 |
| Lifecycle | on demand, server-side terminate-after **20 hours** |
| Cost | operator hard ceiling **USD 35 total** |

The launcher deliberately does not bind a GPU marketing name. The actual
device name and memory are recorded, while admission is the generic single-GPU
contract above. Choose an eligible current offer whose complete 20-hour
projection, including storage, is below USD 35. At the illustrative rate
admitted on 2026-08-12, USD 1.59/GPU-hour plus about USD 0.0274/storage-hour,
20 hours projects to about USD 32.35. Recheck the live price before creation;
refuse any combined rate above USD 1.75/hour or any projection above USD 35.
RunPod's account spend limit is not a per-Pod cap, so the provider-side
20-hour termination timer is the primary cost fuse.

For cgroup v1, the launcher binds the `cpu,cpuacct` and `memory` controller
paths from `/proc/self/cgroup` through each mount root and mount point in
`/proc/self/mountinfo`; it never assumes that controller-root counters belong
to the Pod. For cgroup v2 it applies the same current-process resolution. It
requires at least 16 quota-equivalent cores and a 110 GiB memory limit (or an
explicit unlimited form), and records `cgroupVersion`, quota, period, and
memory limit in `source-identity.txt`.

Authoritative service references:

- [RunPod GPU pricing](https://www.runpod.io/pricing)
- [Pod pricing and billing](https://docs.runpod.io/pods/pricing)
- [Pod storage types](https://docs.runpod.io/pods/storage/types)
- [Manage and terminate Pods](https://docs.runpod.io/pods/manage-pods)

Use an encrypted Pod volume, not a network volume, for this one-shot contour. A
Pod volume survives **stop** and continues to incur storage charges, but it is
deleted on **terminate**. A network volume survives Pod termination and is not
admitted here.

RunPod may expose an encrypted Pod volume through a FUSE filesystem that forces
all directories/files to appear as mode 0777/0666 and ignores `chmod`. Such a
mount is useful for encrypted persistence but is **not** admitted as the
owner-private execution root. In that case keep source and runtime on the
owner-private container disk. Put cache, run root, and evidence either there or
on an owner-private child of a `nosuid,nodev,noexec` tmpfs that is charged to the
admitted Pod memory cgroup and itself exposes at least 100 GiB free. No executable
code may be loaded from that tmpfs. The launcher therefore creates fresh
owner-private Triton, TorchInductor, PyTorch-extension, PyTorch Jiterator-kernel,
and CUDA executable-cache directories beside the exact runtime on the container
disk and passes only those fixed paths to model/replay children. Prove enough
free space for all registered assets and outputs before launch. Before any model
asset is downloaded, the
launcher compiles and loads the pinned Triton CUDA helper with `HOME`, `TMPDIR`,
and `XDG_CACHE_HOME` still on the no-exec run volume, and requires the resulting
shared object to exist only below `TRITON_CACHE_DIR`. The executable caches are
shared across fresh processes solely as compiler output; they carry no model
cache, KV state, prompt state, or result state. They are ephemeral, excluded
from evidence and the archive, and removed with the Pod.
Retain the encrypted Pod volume
only as an optional encrypted transport staging area after the launcher has completed;
never weaken the mode checks to run directly on the permissive mount.

Obtain the exact resolved container digest from the authenticated control
plane. Supply it as `CORELM_SWEEP_IMAGE_DIGEST`; a mutable image tag is not an
acceptable value. The launcher records the operator-supplied digest in the
source receipt, but that receipt is not a provider attestation of the host or
container image.

## Network boundary

Network access is needed to build the locked runtime and materialize model
assets. After materialization, the launcher unsets `HF_TOKEN` and configures
Hugging Face and Transformers for local-files/offline behavior with
`HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`, and
`HF_HUB_DISABLE_IMPLICIT_TOKEN=1`.

This is an **application/library-level offline contract**. The launcher does
not install an OS firewall, detach the Pod network, or prove packet-level egress
isolation. A successful receipt shows that admitted code used the registered
local-assets path and offline library settings; it does not prove that the
managed container had no network route.

## Access and secrets

Create a new Ed25519 SSH key pair for this Pod. Give RunPod only its public key;
do not upload an existing personal key, private key, agent socket, or RunPod API
key. Keep the local private key and a dedicated `known_hosts` file mode 0600.
Before the first SSH login, compare the Pod's ED25519 host-key fingerprint over
an authenticated RunPod control-plane channel and pin that exact public host
key. Do not use `StrictHostKeyChecking=accept-new`, `no`, or an empty
`UserKnownHostsFile`.

Gemma requires prior operator acceptance of its Hugging Face terms. Create a
dedicated fine-grained read-only token with only the required model access.
Store it in [RunPod Secrets](https://docs.runpod.io/pods/templates/secrets) and
map it to `HF_TOKEN` in the Pod template. Never paste the value into chat, a
shell command, cloud-init, Docker arguments, a notebook, a file, or a log. Do
not run `hf auth login`. The downloader receives the token only through its
environment. Immediately afterward the launcher removes that exported value;
the dedicated persistence scanner receives the retained bytes only on stdin,
never in argv, environment, or logs, and then the shell value is destroyed.
Core dumps remain disabled throughout. Because the Pod mapping exists before the
runtime build, the builder must be launched through the secret-stripping
subshell shown below; `corelm`, pip, and runtime-verification subprocesses must
never inherit `HF_TOKEN`.

Some provider SSH sessions do not inherit a Pod-mapped secret even though PID 1
does. If `HF_TOKEN` is absent (not merely empty), the exact Python entrypoint
boundedly reads `/proc/1/environ`, requires one strict ASCII `HF_TOKEN` field,
and copies only that value into the sterile launcher environment. It does not
copy any other PID 1 variable. Operators must not read, export, or relay the
token manually.

Do not place a RunPod API key, cloud credential, SSH private material, or local
signing private key in the Pod. Provisioning authority and execution authority
remain separate.

## Exact source and CUDA runtime

Obtain the sweep commit, tree, and resolved container digest from reviewed
publication/control-plane records through trusted channels. Do not derive an
expected identity from the same untrusted checkout it is meant to authenticate.
Replace these placeholders before running:

```text
SWEEP_COMMIT=<PUBLISHED_40_HEX_SWEEP_COMMIT>
SWEEP_TREE=<PUBLISHED_40_HEX_SWEEP_TREE>
POD_IMAGE_DIGEST=sha256:<CONTROL_PLANE_64_HEX_IMAGE_DIGEST>
```

Clone the sweep and codec repositories into distinct directories on the
encrypted volume and check out both in detached mode. The codec identity is:

```text
commit e7e0504b15769c925206ad1783d45a9ca0b62207
tree   924d3195122e3a486e2d26e4fbdfe574654ae6c8
```

Confirm the identities before building anything. Every setup subprocess before
the sterile launcher must run without mapped provider/model credentials:

```bash
set -eu
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
verify_source_checkout() {
  local root=$1 commit=$2 tree=$3 signers=$4
  local observed gitdir replace_refs status index_listing tracked relative
  local tree_entry mode tail type expected raw_observed
  test -d "$root/.git" && test ! -L "$root/.git"
  observed=$(/usr/bin/git -C "$root" rev-parse --show-toplevel) || return 1
  test "$observed" = "$root"
  observed=$(/usr/bin/git -C "$root" rev-parse HEAD) || return 1
  test "$observed" = "$commit"
  observed=$(/usr/bin/git -C "$root" rev-parse 'HEAD^{tree}') || return 1
  test "$observed" = "$tree"
  observed=$(/usr/bin/git -C "$root" rev-parse --abbrev-ref HEAD) || return 1
  test "$observed" = HEAD
  observed=$(/usr/bin/git -C "$root" rev-parse --is-shallow-repository) || return 1
  test "$observed" = false
  gitdir=$(/usr/bin/git -C "$root" rev-parse --absolute-git-dir) || return 1
  test -d "$gitdir" && test ! -L "$gitdir"
  test ! -e "$gitdir/shallow" && test ! -e "$gitdir/info/grafts"
  replace_refs=$(/usr/bin/git -C "$root" for-each-ref --format='%(refname)' refs/replace) || return 1
  test -z "$replace_refs"
  status=$(/usr/bin/git -C "$root" -c core.fsmonitor=false \
    -c core.untrackedCache=false status --porcelain=v1 \
    --untracked-files=all --ignored=matching) || return 1
  test -z "$status"
  index_listing=$(/usr/bin/git -C "$root" ls-files -v) || return 1
  ! /usr/bin/grep -E '^[a-zS]' <<<"$index_listing" >/dev/null
  tracked=$(/usr/bin/git -C "$root" ls-tree -r --name-only HEAD) || return 1
  test -n "$tracked"
  while IFS= read -r relative; do
    test -f "$root/$relative" && test ! -L "$root/$relative"
    tree_entry=$(/usr/bin/git -C "$root" ls-tree \
      --format='%(objectmode) %(objecttype) %(objectname)' \
      HEAD -- "$relative") || return 1
    mode=${tree_entry%% *}; tail=${tree_entry#* }
    type=${tail%% *}; tail=${tail#* }; expected=${tail%% *}
    test "$type" = blob
    case "$mode" in 100644|100755) ;; *) return 1 ;; esac
    raw_observed=$(/usr/bin/git -C "$root" hash-object --no-filters -- "$root/$relative") || return 1
    test "$raw_observed" = "$expected"
  done <<<"$tracked"
  test -f "$signers" && test ! -L "$signers"
  observed=$(/usr/bin/sha256sum "$signers" | /usr/bin/awk '{print $1}') || return 1
  test "$observed" = 36fb4a170eee7664be32f2a5d562db209fa4f6f1f24667cf6a3ef0166d155c16
  /usr/bin/git -C "$root" \
    -c gpg.ssh.allowedSignersFile="$signers" \
    -c gpg.ssh.program=/usr/bin/ssh-keygen verify-commit "$commit" \
    >/dev/null 2>&1
}

(
  unset HF_TOKEN HUGGING_FACE_HUB_TOKEN RUNPOD_API_KEY GITHUB_TOKEN \
    AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY SSH_AUTH_SOCK BASH_ENV ENV LD_PRELOAD
  ulimit -c 0
  test "$(ulimit -c)" = 0
  verify_source_checkout "$SWEEP_SOURCE" "$SWEEP_COMMIT" "$SWEEP_TREE" \
    "$SWEEP_SOURCE/v4/signing/allowed_signers"
  verify_source_checkout "$CODEC_SOURCE" \
    e7e0504b15769c925206ad1783d45a9ca0b62207 \
    924d3195122e3a486e2d26e4fbdfe574654ae6c8 \
    "$CODEC_SOURCE/signing/allowed_signers"
)
```

This block is the external trust bootstrap: it is operator-entered and executes
before any worktree program. Keep `verify_source_checkout` in the trusted setup
shell and repeat both calls immediately before the token-bearing launch below.
Do not accept a run in which the function is absent or either repeated call
fails.

Build the private CUDA runtime outside both checkouts. The target must not
already exist:

```bash
set -eu
set +x
export CORELM_SWEEP_EXPECTED_COMMIT="$SWEEP_COMMIT"
export CORELM_SWEEP_EXPECTED_TREE="$SWEEP_TREE"
export CORELM_SWEEP_CODEC_ROOT="$CODEC_SOURCE"
export CORELM_SWEEP_RUNTIME="$PRIVATE_VOLUME/corelm-cuda-runtime"

(
  unset HF_TOKEN HUGGING_FACE_HUB_TOKEN RUNPOD_API_KEY GITHUB_TOKEN \
    AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY SSH_AUTH_SOCK BASH_ENV ENV LD_PRELOAD
  ulimit -c 0
  exec /usr/bin/timeout --signal=TERM --kill-after=60s 7200s \
    "$SWEEP_SOURCE/runpod-adapter-sweep-v1/build_cuda_runtime.sh"
)
```

`build_cuda_runtime.sh` uses the codec's pinned Linux bootstrap and portable
dependency locks plus `torch-linux-cu130-py312.txt`. It installs the exact
CPython 3.12 Linux closure and the hash-pinned `torch==2.13.0+cu130` wheel with
its exact CUDA 13.0/cuDNN/NCCL/Triton distribution closure, runs the
locked-environment verifier, requires one
CUDA device with BF16 support, hardens the owner-only tree, and publishes the
runtime atomically. Do not replace it with an interactive venv or ad-hoc
`pip install`.

Do not create runtime, asset, or result bytes inside either checkout.
`run_on_runpod.sh` rejects a branch, shallow history, grafts, replacement refs,
and every tracked, untracked, or ignored sweep byte. The producer and verifier
separately bind the exact codec files and asset-verification receipt.
Before any model-free test or asset access, the launcher also verifies both
commit signatures against the tracked `allowed_signers` files whose exact
SHA-256 (`36fb4a170eee7664be32f2a5d562db209fa4f6f1f24667cf6a3ef0166d155c16`)
is pinned in the launcher. The resulting signature facts and trust-root digest
are retained in `source-identity.txt`.

## Launch

The output parent must already exist, be owner-controlled and non-writable by
group/world, and live outside source, runtime, and the original home. The final
run root must not exist. Use a new root for every attempt.

Set only these non-secret inputs. `HF_TOKEN` must come from the RunPod Secret
mapping; it may be absent from the SSH session because the exact entrypoint has
the bounded PID 1 fallback described above. The token must not appear in the
command block:

```bash
set +x
export CORELM_SWEEP_EXPECTED_COMMIT="$SWEEP_COMMIT"
export CORELM_SWEEP_EXPECTED_TREE="$SWEEP_TREE"
export CORELM_SWEEP_CODEC_ROOT="$CODEC_SOURCE"
export CORELM_SWEEP_PYTHON="$CORELM_SWEEP_RUNTIME/bin/python"
export CORELM_SWEEP_ROOT="$PRIVATE_VOLUME/corelm-adapter-sweep-attempt-01"
export CORELM_SWEEP_IMAGE_DIGEST="$POD_IMAGE_DIGEST"

cd "$SWEEP_SOURCE"
unset HUGGING_FACE_HUB_TOKEN RUNPOD_API_KEY GITHUB_TOKEN \
  AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY SSH_AUTH_SOCK BASH_ENV ENV LD_PRELOAD
ulimit -c 0
test "$(ulimit -c)" = 0
if [[ ${HF_TOKEN+x} ]]; then
  export -n HF_TOKEN
  HF_TOKEN_WAS_INHERITED=1
else
  HF_TOKEN_WAS_INHERITED=0
fi
verify_source_checkout "$SWEEP_SOURCE" "$SWEEP_COMMIT" "$SWEEP_TREE" \
  "$SWEEP_SOURCE/v4/signing/allowed_signers"
verify_source_checkout "$CODEC_SOURCE" \
  e7e0504b15769c925206ad1783d45a9ca0b62207 \
  924d3195122e3a486e2d26e4fbdfe574654ae6c8 \
  "$CODEC_SOURCE/signing/allowed_signers"
if [[ "$HF_TOKEN_WAS_INHERITED" = 1 ]]; then
  export HF_TOKEN
fi
unset HF_TOKEN_WAS_INHERITED
exec "$CORELM_SWEEP_PYTHON" -I -B \
  ./runpod-adapter-sweep-v1/launch_runpod.py
```

The Python entrypoint must run from the already verified exact runtime. It
copies only the seven registered inputs plus `HOME` into an `execve` environment
and then starts exact `/bin/bash`; exported functions, provider credentials,
proxies, startup hooks, and dynamic-loader variables are not forwarded. The
Bash launcher independently clears and reconstructs its child environment,
creates directories mode 0700 and files mode 0600, and never prints an
environment dump, secret, SSH endpoint, or Pod identifier.
The RunPod control plane and initial login shell are part of the trusted
startup boundary: no script can retroactively prevent a dynamic loader or
shell startup hook from reading a secret that the provider injected before
the script began. The explicit empty-hook checks above, exact `/bin/bash`, and
the launcher's clean child environments prevent those hooks from being
forwarded into the admitted build/model subprocesses.

The current executable command sequence, verified against each CLI's `--help`,
starts by running all three model-free contract test modules on Linux against the
exact codec checkout. It then performs:

1. `prepare_assets.py download --cache C --receipt ASSETS_DOWNLOAD`.
2. Unset `HF_TOKEN`, reject persisted authentication, and set the three offline
   library flags.
3. In a fresh credential-free process, run `prepare_assets.py convert --cache C
   --receipt OPT_CONVERSION`; it opens, verifies, and parses the pinned OPT
   source on one descriptor and records semantic tensor equality.
4. `prepare_assets.py verify --cache C --conversion-receipt OPT_CONVERSION
   --receipt ASSETS`.
5. `run_adapter_sweep.py preflight --codec-root ROOT --cache C --assets ASSETS
   --output PREFLIGHT`.
6. `run_adapter_sweep.py orchestrate --codec-root ROOT --cache C --assets
   ASSETS --preflight PREFLIGHT --run-dir RUN --cell-timeout-seconds 2700`.
7. `verify_adapter_sweep.py verify-run --codec-root ROOT --cache C --assets
   ASSETS --preflight PREFLIGHT --run-dir RUN --output STRUCTURAL`.
8. Seven `verify_adapter_sweep.py replay-cell --codec-root ROOT --cache C
   --assets ASSETS --preflight PREFLIGHT --run-dir RUN --model-id MODEL
   --structural STRUCTURAL --workload-id WORKLOAD --output REPLAY` invocations.

`run-cell` is an internal producer entry point and must not be invoked manually.
`orchestrate` launches exactly 28 real producer cells sequentially in fresh OS
process groups, with direct argv, no shell, and no silent retry. The structural
verifier checks all 28 retained cells. It does not load all 28 models again.

The seven mandatory representative model replays are exactly one per profile:

| Model | Workload |
|---|---|
| `qwen2.5-0.5b` | `tracked-legal-protocol-v1` |
| `smollm2-135m` | `tracked-source-code-v1` |
| `mistral-7b-v0.1` | `tracked-structured-json-v1` |
| `pythia-14m` | `tracked-technical-prose-v1` |
| `distilgpt2` | `tracked-legal-protocol-v1` |
| `opt-125m` | `tracked-source-code-v1` |
| `gemma-2b` | `tracked-structured-json-v1` |

Thus a complete attempt contains **28 structurally verified producer cells and
7 representative model-replay receipts, not 28 model replays**. The replay
processes use the same Pod, cache, source, and runtime and therefore are not an
independent replication.

The launcher bounds asset download at 3,600 seconds, OPT conversion, asset
verification, preflight, and structural verification at 900 seconds each, and
the complete orchestrator at **41,400 seconds**. Each representative replay
binds the selected cell to the already completed full structural receipt and
revalidates that selected cell before loading the model; it does not decode all
28 cells again. Its outer limit is the registered model limit: 1,350 seconds
for Qwen, 900 for SmolLM2, Pythia, DistilGPT2, and OPT, 2,700 for Mistral, and
1,800 for Gemma. Producer
cells use the same registered per-profile limits; the largest is Mistral at
**2,700 seconds**, and the required orchestrator ceiling argument is therefore
2,700. Four workloads across the seven registered limits total 37,800 seconds;
the outer bound reserves another 3,600 seconds for deterministic process-group
cleanup and manifest completion. A timeout, OOM, signal, digest failure, missing
cell, or resource-bound cell makes the attempt incomplete. Never rerun into the
same run root.

The registered builder and launcher ceilings sum to **66,270 seconds
(18:24:30)**: 7,200 seconds for the CUDA runtime builder, 41,400 for the
orchestrator, 120 for the executable-cache CUDA smoke, and 17,550 for download,
conversion, verification, preflight, structural verification, and the seven
replays. The 20-hour provider fuse therefore leaves at most **5,730 seconds
(1:35:30)** for clone/setup, packaging,
retrieval, local transfer checks, and termination. This is operational reserve,
not a promised transfer SLA, and it shrinks from the instant the Pod is created,
not from the start of the builder. Begin retrieval immediately when the launcher
finishes.

## Deterministic archive and retrieval

After structural verification and all seven representative replays, the
launcher privacy-scans the evidence, rejects unsafe filesystem objects and
private paths, and packages only `evidence/`. Model assets, the cache, runtime,
home, and temporary state are excluded.

The export contains:

```text
corelm-runpod-adapter-sweep-v1.tar.gz
SHA256SUMS
```

GNU tar fixes order, time, owner/group and PAX metadata; `gzip -n` removes gzip
timestamp/name variance. Retrieve both files over the pinned SSH channel:

```bash
LOCAL_EVIDENCE_DIR=$(mktemp -d \
  "${TMPDIR:-/tmp}/corelm-runpod-evidence.XXXXXX")
LOCAL_EVIDENCE_DIR=$(cd "$LOCAL_EVIDENCE_DIR" && pwd -P)
scp -P "$SSH_PORT" \
  -i "$EPHEMERAL_SSH_PRIVATE_KEY" \
  -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$PINNED_KNOWN_HOSTS" \
  "root@$SSH_HOST:$REMOTE_EXPORT/corelm-runpod-adapter-sweep-v1.tar.gz" \
  "root@$SSH_HOST:$REMOTE_EXPORT/SHA256SUMS" \
  "$LOCAL_EVIDENCE_DIR/"
```

Verify transfer integrity and reject unsafe archive member names/types before
any extraction:

```bash
set -e
python3 - "$LOCAL_EVIDENCE_DIR" <<'PY'
import os
import pathlib
import re
import stat
import sys

root = pathlib.Path(sys.argv[1])
root_status = root.lstat()
if (
    not stat.S_ISDIR(root_status.st_mode)
    or root_status.st_uid != os.getuid()
    or root_status.st_mode & 0o077
    or root.resolve(strict=True) != root
):
    raise SystemExit("local evidence directory is not private and canonical")
expected = {
    "corelm-runpod-adapter-sweep-v1.tar.gz": 64 * 1024**3,
    "SHA256SUMS": 1024,
}
if {entry.name for entry in root.iterdir()} != set(expected):
    raise SystemExit("local evidence directory inventory differs")
for name, maximum in expected.items():
    status = (root / name).lstat()
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 1
        or status.st_uid != os.getuid()
        or not 0 < status.st_size <= maximum
    ):
        raise SystemExit(f"unsafe transferred file: {name}")
raw = (root / "SHA256SUMS").read_bytes()
if re.fullmatch(
    rb"[0-9a-f]{64}  corelm-runpod-adapter-sweep-v1[.]tar[.]gz\n",
    raw,
) is None:
    raise SystemExit("SHA256SUMS has an unsafe or non-canonical grammar")
PY
chmod 0600 "$LOCAL_EVIDENCE_DIR/corelm-runpod-adapter-sweep-v1.tar.gz" \
  "$LOCAL_EVIDENCE_DIR/SHA256SUMS"
cd "$LOCAL_EVIDENCE_DIR"
sha256sum -c SHA256SUMS
python3 - corelm-runpod-adapter-sweep-v1.tar.gz <<'PY'
import pathlib
import sys
import tarfile

with tarfile.open(sys.argv[1], "r:gz") as archive:
    members = archive.getmembers()
    if not members:
        raise SystemExit("empty archive")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if (
            path.is_absolute()
            or not path.parts
            or path.parts[0] != "evidence"
            or ".." in path.parts
            or not (member.isfile() or member.isdir())
        ):
            raise SystemExit(f"unsafe archive member: {member.name!r}")
PY
```

On macOS, use `shasum -a 256 -c SHA256SUMS` for the checksum step.

This local check proves only that the transferred bytes match the checksum file
retrieved from the same Pod and that the tar inventory is safe to inspect. It is
**not an independent semantic verification or model replay**: the published
archive intentionally excludes the model assets/cache needed by
`verify-run`/`replay-cell`. The structural and seven replay receipts inside the
archive were produced on the original Pod.

After transfer verification, complete lifecycle cleanup, and revocation of all
ephemeral credentials, use the model-free publication builder documented in
[`recorded-runs/README.md`](recorded-runs/README.md) to generate the compact
28-row audit, exact attempt history, and ordinary-user reproduction guide. It
does not promote this same-Pod exploratory regression into scientific evidence
or an independent replication.

If a signed receipt is required, sign the already checked `SHA256SUMS` locally
with an offline key that never entered the Pod:

```bash
ssh-keygen -Y sign \
  -f "$LOCAL_EVIDENCE_SIGNING_KEY" \
  -n corelm-adapter-sweep \
  "$LOCAL_EVIDENCE_DIR/SHA256SUMS"
```

That signature attests only to the bytes the operator retrieved and checked. It
does not attest independent execution and does not turn the exploratory run
into scientific evidence.

## Termination and credential removal

Only after checksum and inventory checks succeed:

1. Terminate the Pod; do not merely stop it.
2. Confirm through the authenticated RunPod control plane that the Pod is
   terminated and its Pod volume is gone.
3. Delete the RunPod Secret mapping and revoke the dedicated Hugging Face token.
4. Remove the ephemeral SSH public key and retire the matching local private key
   according to operator policy.
5. Confirm that no network volume or reusable template contains source, assets,
   runtime, credentials, or evidence.
6. Record termination time, final billed duration/cost, image digest, source
   commit/tree, codec commit/tree, archive SHA-256, and local signature identity;
   never record the token, endpoint, private key, or private remote path.

If retrieval or checksum verification fails, diagnose only through the pinned
channel and never weaken SSH verification or expose a new port. The
provider-side **20-hour** fuse and **USD 35** hard budget remain terminal limits.

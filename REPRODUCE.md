# Public reproduction guide

This guide separates verification of the published V4 development archive from
new regression runs. Neither path authorizes a NIST request or a scientific
one-shot. V4 remains a non-scientific development archive: the tracked NIST
leaf expires before the proposed pulse, so the scientific design must move to
a new suite identity after authoritative replacement trust exists.

## What public keys are required

A reproducer needs the public SSH key and `allowed_signers`, never the private
key. The registered public key is
[`v4/signing/corelm-crossmodel-v4-signing.pub`](v4/signing/corelm-crossmodel-v4-signing.pub):

- SHA-256: `9d299ff032927caef3f1355fb55c01f206ebf27ef35bcb5da547f962168b1274`
- OpenSSH fingerprint: `SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM`
- `allowed_signers` SHA-256:
  `36fb4a170eee7664be32f2a5d562db209fa4f6f1f24667cf6a3ef0166d155c16`

These bytes verify Ivan Tyshchenko's signature. They do not let anyone create
his signature. A private key, `.ssh` directory, GitHub token, model-host token,
or NIST private material must never be copied into this repository, an
artifact, a log, or a container.

Before each `verify-tag` command below, the shell checks both tracked trust
files against these exact out-of-band values. GitHub/Zenodo publication must
repeat the same key fingerprint and hashes; a hash copied only from a modified
checkout is not an independent trust anchor.

## Obtain the exact Python patch version

The bootstrap rejects every interpreter except CPython 3.12.10. The canonical
Linux construction is the pinned GitHub Actions job, which acquires 3.12.10
through the commit-pinned `actions/setup-python` action and inventories the
resulting base/runtime trees. A locally compiled Linux interpreter has distinct
bytes and must not be described as byte-identical to that hosted toolcache.

Official upstream inputs are:

- source: `https://www.python.org/ftp/python/3.12.10/Python-3.12.10.tar.xz`,
  SHA-256
  `07ab697474595e06f06647417d3c7fa97ded07afc1a7e4454c5639919b46eaea`;
- macOS universal2 installer:
  `https://www.python.org/ftp/python/3.12.10/python-3.12.10-macos11.pkg`,
  45,720,356 bytes, SHA-256
  `8373e58da4ea146b3eb1c1f9834f19a319440b6b679b06050b1f9ee3237aa8e4`.

After installing or building it, set an absolute path and verify it before any
bootstrap:

```sh
set -eu
export PYTHON_31210=/absolute/path/to/python3.12
test "$($PYTHON_31210 -I -B -c 'import platform; print(platform.python_version())')" = \
  3.12.10
```

## Verify the immutable V4 development source

The canonical identity is the signed annotated tag, not the moving `main`
branch:

```sh
set -eu
git clone https://github.com/ALLPROTO/core-lm-cross-model-lab.git lab
cd lab
git fetch --force origin \
  refs/tags/corelm-crossmodel-livewiki-v4-development-control:\
refs/tags/corelm-crossmodel-livewiki-v4-development-control

sha256_path() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}
test "$(sha256_path v4/signing/corelm-crossmodel-v4-signing.pub)" = \
  9d299ff032927caef3f1355fb55c01f206ebf27ef35bcb5da547f962168b1274
test "$(sha256_path v4/signing/allowed_signers)" = \
  36fb4a170eee7664be32f2a5d562db209fa4f6f1f24667cf6a3ef0166d155c16
/usr/bin/ssh-keygen -E sha256 -lf v4/signing/corelm-crossmodel-v4-signing.pub \
  | grep -Fq 'SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM'

git -c gpg.format=ssh \
  -c gpg.ssh.program=/usr/bin/ssh-keygen \
  -c gpg.ssh.allowedSignersFile="$PWD/v4/signing/allowed_signers" \
  verify-tag corelm-crossmodel-livewiki-v4-development-control

test "$(git rev-parse corelm-crossmodel-livewiki-v4-development-control)" = \
  767e114baacf864fbeb195b42e9df2be22e6133d
test "$(git rev-list -n 1 corelm-crossmodel-livewiki-v4-development-control)" = \
  f46a5365a585e18f0c198235729fc8259b55abcc
test "$(git rev-parse 'corelm-crossmodel-livewiki-v4-development-control^{tree}')" = \
  1e15fb82aee21b51cd21e6d8a5f5ff21b35ff658
git checkout --detach f46a5365a585e18f0c198235729fc8259b55abcc
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

The immutable release is
[`corelm-crossmodel-livewiki-v4-development-control`](https://github.com/ALLPROTO/core-lm-cross-model-lab/releases/tag/corelm-crossmodel-livewiki-v4-development-control).
It intentionally contains exactly three assets. The canonical server receipt
is retained byte-for-byte for the next design/Zenodo evidence bundle; adding a
fourth file to this immutable release would invalidate its registered
inventory.

The future bundle must publish that receipt under the exact filename
`development-control-archive-receipt.json`. Its current immutable identity is:

- file bytes: `38,972`
- file SHA-256:
  `289afb6ecd20930f80507365a024516fb0904ee66629cc686f1d085be321a53c`
- canonical content SHA-256:
  `413dd15e2798a13fa661030fd88da337985f07898574614321182f47370c3db4`
- GitHub release database ID: `365162563`
- signed release-attestation time: `2026-08-04T21:17:46Z`

The same bundle must also carry the exact public trust bytes under the names
`corelm-crossmodel-v4-signing.pub` (SHA-256
`9d299ff032927caef3f1355fb55c01f206ebf27ef35bcb5da547f962168b1274`)
and `allowed_signers` (SHA-256
`36fb4a170eee7664be32f2a5d562db209fa4f6f1f24667cf6a3ef0166d155c16`).
Merely printing their hashes without preserving the corresponding bytes is not
a durable verification bundle.

Until the design/Zenodo bundle is public, an external user can verify the
signed source tag and the immutable three-asset release but cannot independently
obtain this canonical receipt from the repository. This limitation must remain
explicit; the local receipt is not silently substituted with a new one.

Clone and verify the exact codec separately:

```sh
set -eu
cd ..
git clone https://github.com/ALLPROTO/core-lm-benchmark.git codec-source
cd codec-source
sha256_path() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}
git fetch --force origin \
  refs/tags/corelm-codec-source-2e8d3b-v1:\
refs/tags/corelm-codec-source-2e8d3b-v1
LAB_TRUST_ROOT=$(CDPATH= cd -- ../lab/v4/signing && pwd -P)
test "$(sha256_path "$LAB_TRUST_ROOT/corelm-crossmodel-v4-signing.pub")" = \
  9d299ff032927caef3f1355fb55c01f206ebf27ef35bcb5da547f962168b1274
test "$(sha256_path "$LAB_TRUST_ROOT/allowed_signers")" = \
  36fb4a170eee7664be32f2a5d562db209fa4f6f1f24667cf6a3ef0166d155c16
/usr/bin/ssh-keygen -E sha256 \
  -lf "$LAB_TRUST_ROOT/corelm-crossmodel-v4-signing.pub" \
  | grep -Fq 'SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM'
git -c gpg.format=ssh \
  -c gpg.ssh.program=/usr/bin/ssh-keygen \
  -c gpg.ssh.allowedSignersFile="$LAB_TRUST_ROOT/allowed_signers" \
  verify-tag corelm-codec-source-2e8d3b-v1
test "$(git rev-parse corelm-codec-source-2e8d3b-v1)" = \
  4c5b2bd2caa985506df17b3ea0da074b5022bd2b
test "$(git rev-list -n 1 corelm-codec-source-2e8d3b-v1)" = \
  2e8d3b1591ee4a1ed822310f330317936871ff2b
test "$(git rev-parse 'corelm-codec-source-2e8d3b-v1^{tree}')" = \
  c0bb15784d252cd5036757bc64765c773a5f16e8
git checkout --detach 2e8d3b1591ee4a1ed822310f330317936871ff2b
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

The codec tag is source provenance, not scientific evidence. Its old target
tree intentionally does not contain `signing/`; verification therefore uses
the public trust files already authenticated by the signed lab tag (and may
later use their byte-identical copies from the immutable evidence bundle).
The signed lab release already binds the same codec commit and tree.

## Verify the published post-release evidence

The complete post-release publication chain is:

1. immutable
   [`source identity`](https://github.com/ALLPROTO/core-lm-cross-model-lab/releases/tag/corelm-crossmodel-v4-post-release-regression-v1);
2. immutable signed
   [`metadata correction`](https://github.com/ALLPROTO/core-lm-cross-model-lab/releases/tag/corelm-crossmodel-v4-post-release-identity-correction-v1),
   which replaces only the wrong codec tag name in the first receipt; and
3. immutable
   [`macOS real-model evidence`](https://github.com/ALLPROTO/core-lm-cross-model-lab/releases/tag/corelm-crossmodel-v4-post-release-macos-e2e-evidence-v1).

The evidence release is anchored by a separate signed annotated tag. It points
to the unchanged post-release source tree:

```sh
set -eu
cd ../lab
git fetch --force origin \
  refs/tags/corelm-crossmodel-v4-post-release-macos-e2e-evidence-v1:\
refs/tags/corelm-crossmodel-v4-post-release-macos-e2e-evidence-v1
git -c gpg.format=ssh \
  -c gpg.ssh.program=/usr/bin/ssh-keygen \
  -c gpg.ssh.allowedSignersFile="$PWD/v4/signing/allowed_signers" \
  verify-tag corelm-crossmodel-v4-post-release-macos-e2e-evidence-v1
test "$(git rev-parse corelm-crossmodel-v4-post-release-macos-e2e-evidence-v1)" = \
  a0f0dad22c1d08be2d7739a4ef175ae54c9e7bfc
test "$(git rev-list -n 1 corelm-crossmodel-v4-post-release-macos-e2e-evidence-v1)" = \
  76ee0b0960db8396af0cbf1d3d84c79cffb0a784
test "$(git rev-parse \
  'corelm-crossmodel-v4-post-release-macos-e2e-evidence-v1^{tree}')" = \
  afd7466884dc4d2c49fd70d76b256c00e3f7158b
```

Download and verify all 17 author-supplied assets. The successful archive is
exactly 501,046,366 bytes (about 477.835 MiB); model weights are intentionally
not included:

```sh
set -eu
EVIDENCE_TAG=corelm-crossmodel-v4-post-release-macos-e2e-evidence-v1
EVIDENCE_BASE="https://github.com/ALLPROTO/core-lm-cross-model-lab/releases/download/$EVIDENCE_TAG"
LAB_ROOT=$(CDPATH= cd -- . && pwd -P)
test -d "$LAB_ROOT/.git"
EVIDENCE_ROOT="$LAB_ROOT/../corelm-v4-macos-evidence"
test ! -e "$EVIDENCE_ROOT"
mkdir -m 700 "$EVIDENCE_ROOT"
EVIDENCE_ROOT=$(CDPATH= cd -- "$EVIDENCE_ROOT" && pwd -P)
cd "$EVIDENCE_ROOT"
for FILE in \
  README.md \
  SHA256SUMS \
  allowed_signers \
  corelm-crossmodel-v4-signing.pub \
  evidence-release-receipt.json \
  evidence-release-receipt.json.sig \
  first-host-memory-failure-evidence.tar.gz \
  metrics.json \
  post-release-source-identity-correction.json \
  post-release-source-identity-correction.json.sig \
  post-release-source-identity.json \
  post-release-source-identity.json.sig \
  semantic-verifier-report.json \
  source-identity-chain.tar.gz \
  source-identity-correction-server-receipt.json \
  source-identity-original-server-receipt.json \
  successful-real-model-regression-evidence.tar.gz
do
  curl --fail --location --retry 3 --output "$FILE" "$EVIDENCE_BASE/$FILE"
done
if command -v sha256sum >/dev/null 2>&1; then
  test "$(sha256sum SHA256SUMS | awk '{print $1}')" = \
    734a950f3c2dc04fb863fe6143afd6a55492f9cad9576fd9f2a5ca0e7e28af82
  sha256sum -c SHA256SUMS
else
  test "$(shasum -a 256 SHA256SUMS | awk '{print $1}')" = \
    734a950f3c2dc04fb863fe6143afd6a55492f9cad9576fd9f2a5ca0e7e28af82
  shasum -a 256 -c SHA256SUMS
fi
ssh-keygen -Y verify \
  -f allowed_signers \
  -I ivantyschenko777@gmail.com \
  -n file \
  -s evidence-release-receipt.json.sig \
  < evidence-release-receipt.json
gzip -t first-host-memory-failure-evidence.tar.gz
gzip -t successful-real-model-regression-evidence.tar.gz
gzip -t source-identity-chain.tar.gz
```

GitHub release ID `365490155` is immutable and its platform attestation binds
the annotated tag object and all 17 asset SHA-256 values. The final raw GitHub
API response cannot be embedded in the same immutable release without creating
a recursive dependency; its author-signed copy is reserved for the next
design/Zenodo evidence bundle.

The bundle preserves a host-memory failure before first model inference and a
successful retry over GPT-Neo 125M, SmolLM2 360M, and Tiny-Starcoder-Py on the
real UD English PUD r2.18 test bytes. The successful report contains 96 pages,
12,288 predictions, and 2,048 VTL5 containers. Its status is
`NON_SCIENTIFIC_POST_RELEASE_REAL_MODEL_REGRESSION_PASS`, with
`thresholdsApplied=false`, `countsTowardScientificVerdict=false`, no NIST, and
no future corpus. “Independent replay” means a separate deterministic verifier
execution, not an independent human reviewer.

## Linux x86-64: portable controls, not the macOS E2E

Use exactly CPython 3.12.10. The bootstrap accepts no other patch version and
installs only hash-locked wheels from the exact codec tree:

```sh
set -eu
cd ../lab
: "${PYTHON_31210:?set PYTHON_31210 to an absolute CPython 3.12.10 path}"
sha256_path() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}
git fetch --force origin \
  refs/tags/corelm-crossmodel-v4-post-release-regression-v1:\
refs/tags/corelm-crossmodel-v4-post-release-regression-v1
test "$(sha256_path v4/signing/corelm-crossmodel-v4-signing.pub)" = \
  9d299ff032927caef3f1355fb55c01f206ebf27ef35bcb5da547f962168b1274
test "$(sha256_path v4/signing/allowed_signers)" = \
  36fb4a170eee7664be32f2a5d562db209fa4f6f1f24667cf6a3ef0166d155c16
/usr/bin/ssh-keygen -E sha256 -lf v4/signing/corelm-crossmodel-v4-signing.pub \
  | grep -Fq 'SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM'
git -c gpg.format=ssh \
  -c gpg.ssh.program=/usr/bin/ssh-keygen \
  -c gpg.ssh.allowedSignersFile="$PWD/v4/signing/allowed_signers" \
  verify-tag corelm-crossmodel-v4-post-release-regression-v1
git checkout --detach corelm-crossmodel-v4-post-release-regression-v1
test -z "$(git status --porcelain=v1 --untracked-files=all)"
(
  CORELM_IGNORED_LIST=$(mktemp "${TMPDIR:-/tmp}/corelm-ignored.XXXXXX")
  trap 'rm -f "$CORELM_IGNORED_LIST"' EXIT HUP INT TERM
  git ls-files --others --ignored --exclude-standard -z >"$CORELM_IGNORED_LIST"
  test ! -s "$CORELM_IGNORED_LIST" || {
    echo 'refusing ignored files in the verified lab checkout' >&2
    exit 1
  }
)
CORELM_LAB_ROOT=$(CDPATH= cd -- . && pwd -P)
source_git() {
  /usr/bin/env -i \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    LANG=C LC_ALL=C \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
    /usr/bin/git -C "$CORELM_LAB_ROOT" \
    -c core.worktree="$CORELM_LAB_ROOT" -c core.bare=false \
    -c core.fsmonitor=false -c core.ignoreStat=false \
    -c core.untrackedCache=false "$@"
}
test -d "$CORELM_LAB_ROOT/.git"
test ! -L "$CORELM_LAB_ROOT/.git"
test "$(source_git rev-parse --show-toplevel)" = "$CORELM_LAB_ROOT"
test "$(source_git rev-parse --absolute-git-dir)" = "$CORELM_LAB_ROOT/.git"
test "$(source_git rev-parse --path-format=absolute --git-common-dir)" = \
  "$CORELM_LAB_ROOT/.git"
test -z "$(source_git for-each-ref --format='%(refname)' refs/replace)"
CORELM_GRAFTS=$(source_git rev-parse --path-format=absolute --git-path info/grafts)
test ! -e "$CORELM_GRAFTS"
test ! -L "$CORELM_GRAFTS"
source_git -c gpg.format=ssh \
  -c gpg.ssh.program=/usr/bin/ssh-keygen \
  -c gpg.ssh.allowedSignersFile="$CORELM_LAB_ROOT/v4/signing/allowed_signers" \
  verify-tag corelm-crossmodel-v4-post-release-regression-v1
test "$(source_git rev-list -n 1 corelm-crossmodel-v4-post-release-regression-v1)" = \
  "$(source_git rev-parse HEAD)"
test "$(source_git rev-parse 'corelm-crossmodel-v4-post-release-regression-v1^{tree}')" = \
  "$(source_git rev-parse 'HEAD^{tree}')"
verify_live_entry() {
  CORELM_RELATIVE=$1
  CORELM_EXPECTED_MODE=$2
  test -f "$CORELM_RELATIVE"
  test ! -L "$CORELM_RELATIVE"
  test "$(source_git ls-tree HEAD -- "$CORELM_RELATIVE" | awk '{print $1}')" = \
    "$CORELM_EXPECTED_MODE"
  case "$CORELM_EXPECTED_MODE" in
    100755) test -x "$CORELM_RELATIVE" ;;
    100644) test ! -x "$CORELM_RELATIVE" ;;
    *) return 1 ;;
  esac
  test "$(source_git hash-object --no-filters -- "$CORELM_RELATIVE")" = \
    "$(source_git rev-parse --verify "HEAD:$CORELM_RELATIVE")"
}
verify_live_entry v4/bootstrap_runtime.sh 100755
verify_live_entry v4/run_post_release_regression.py 100644
LINUX_BUILD_ROOT="$PWD/../corelm-v4-linux-$(date -u +%Y%m%dT%H%M%SZ)"
test ! -e "$LINUX_BUILD_ROOT"
mkdir -m 700 "$LINUX_BUILD_ROOT"
LINUX_BUILD_ROOT=$(CDPATH= cd -- "$LINUX_BUILD_ROOT" && pwd -P)
RUNTIME_ROOT="$LINUX_BUILD_ROOT/runtime"
PYCACHE_ROOT="$LINUX_BUILD_ROOT/isolated-python-cache"
mkdir -m 700 "$PYCACHE_ROOT"
./v4/bootstrap_runtime.sh \
  --platform linux \
  --codec-root ../codec-source \
  --runtime "$RUNTIME_ROOT" \
  --python "$PYTHON_31210"

/usr/bin/env -i \
  PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  LANG=C LC_ALL=C PYTHONHASHSEED=0 \
  "$RUNTIME_ROOT/bin/python" -P -s -B \
  -X "pycache_prefix=$PYCACHE_ROOT" \
  v4/run_post_release_regression.py --verify-source-only

"$RUNTIME_ROOT/bin/python" -I -B v4/run_zero_skip_tests.py
"$RUNTIME_ROOT/bin/python" -I -B v4/verify_design.py
"$RUNTIME_ROOT/bin/python" -I -B v4/preflight.py \
  --codec-root ../codec-source
```

Expected design status is development-only and not freezable. Linux verifies
the schemas, state machine, collectors, independent verifiers, source bindings,
and locked runtime. It does **not** reproduce the macOS host gate or claim an
identical floating-point scientific run.

## macOS arm64: full real-model development regression

Requirements are Apple Silicon, macOS, CPython 3.12.10, AC power, a value of at
least 50% from `/usr/bin/memory_pressure -Q` at each child start, and the system
`/usr/bin/sandbox-exec`. The host gate requires at least 12,884,901,888 free
bytes (12 GiB) immediately before output materialization and again before every
child, after the runtime and assets already exist. Begin the clean build with at
least 16 GiB free, plus any additional evidence-growth reserve. Network is used
only while installing locked wheels and downloading the 1,916,375,741-byte
(about 1.785 GiB) pinned model snapshot. Models run sequentially under the
repository's memory and process supervisor.

Always use a new external output directory. Every repeat is a
`post-release development regression`; it is not a second development-control
release, a blind/generalization result, or scientific evidence. The public
regression entrypoint from the signed post-release tag preserves those labels
and cannot create NIST/attempt state or a canonical development-control report.

The runner requires the signed post-release source tag
`corelm-crossmodel-v4-post-release-regression-v1` to point at the current
detached `HEAD`. A moving `main`, an unsigned branch, and a locally edited
checkout all fail closed.

The source tag was created on the exact reviewed, green post-release commit.
Its annotated tag-object ID, target commit, and tree are repeated in the
immutable source-identity release and signed correction linked above. The
separate evidence release repeats the same source binding and adds the complete
macOS receipts. These public records close the earlier out-of-band source pin;
they do not turn the regression into independent or scientific evidence.

```sh
set -eu
cd ../lab
sha256_path() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}
git fetch --force origin \
  refs/tags/corelm-crossmodel-v4-post-release-regression-v1:\
refs/tags/corelm-crossmodel-v4-post-release-regression-v1
test "$(sha256_path v4/signing/corelm-crossmodel-v4-signing.pub)" = \
  9d299ff032927caef3f1355fb55c01f206ebf27ef35bcb5da547f962168b1274
test "$(sha256_path v4/signing/allowed_signers)" = \
  36fb4a170eee7664be32f2a5d562db209fa4f6f1f24667cf6a3ef0166d155c16
/usr/bin/ssh-keygen -E sha256 -lf v4/signing/corelm-crossmodel-v4-signing.pub \
  | grep -Fq 'SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM'
git -c gpg.format=ssh \
  -c gpg.ssh.program=/usr/bin/ssh-keygen \
  -c gpg.ssh.allowedSignersFile="$PWD/v4/signing/allowed_signers" \
  verify-tag corelm-crossmodel-v4-post-release-regression-v1
git checkout --detach corelm-crossmodel-v4-post-release-regression-v1
test -z "$(git status --porcelain=v1 --untracked-files=all)"
(
  CORELM_IGNORED_LIST=$(mktemp "${TMPDIR:-/tmp}/corelm-ignored.XXXXXX")
  trap 'rm -f "$CORELM_IGNORED_LIST"' EXIT HUP INT TERM
  git ls-files --others --ignored --exclude-standard -z >"$CORELM_IGNORED_LIST"
  test ! -s "$CORELM_IGNORED_LIST" || {
    echo 'refusing ignored files in the verified lab checkout' >&2
    exit 1
  }
)
: "${PYTHON_31210:?set PYTHON_31210 to an absolute CPython 3.12.10 path}"
CORELM_LAB_ROOT=$(CDPATH= cd -- . && pwd -P)
source_git() {
  /usr/bin/env -i \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    LANG=C LC_ALL=C \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
    /usr/bin/git -C "$CORELM_LAB_ROOT" \
    -c core.worktree="$CORELM_LAB_ROOT" -c core.bare=false \
    -c core.fsmonitor=false -c core.ignoreStat=false \
    -c core.untrackedCache=false "$@"
}
test -d "$CORELM_LAB_ROOT/.git"
test ! -L "$CORELM_LAB_ROOT/.git"
test "$(source_git rev-parse --show-toplevel)" = "$CORELM_LAB_ROOT"
test "$(source_git rev-parse --absolute-git-dir)" = "$CORELM_LAB_ROOT/.git"
test "$(source_git rev-parse --path-format=absolute --git-common-dir)" = \
  "$CORELM_LAB_ROOT/.git"
test -z "$(source_git for-each-ref --format='%(refname)' refs/replace)"
CORELM_GRAFTS=$(source_git rev-parse --path-format=absolute --git-path info/grafts)
test ! -e "$CORELM_GRAFTS"
test ! -L "$CORELM_GRAFTS"
source_git -c gpg.format=ssh \
  -c gpg.ssh.program=/usr/bin/ssh-keygen \
  -c gpg.ssh.allowedSignersFile="$CORELM_LAB_ROOT/v4/signing/allowed_signers" \
  verify-tag corelm-crossmodel-v4-post-release-regression-v1
test "$(source_git rev-list -n 1 corelm-crossmodel-v4-post-release-regression-v1)" = \
  "$(source_git rev-parse HEAD)"
test "$(source_git rev-parse 'corelm-crossmodel-v4-post-release-regression-v1^{tree}')" = \
  "$(source_git rev-parse 'HEAD^{tree}')"
verify_live_entry() {
  CORELM_RELATIVE=$1
  CORELM_EXPECTED_MODE=$2
  test -f "$CORELM_RELATIVE"
  test ! -L "$CORELM_RELATIVE"
  test "$(source_git ls-tree HEAD -- "$CORELM_RELATIVE" | awk '{print $1}')" = \
    "$CORELM_EXPECTED_MODE"
  case "$CORELM_EXPECTED_MODE" in
    100755) test -x "$CORELM_RELATIVE" ;;
    100644) test ! -x "$CORELM_RELATIVE" ;;
    *) return 1 ;;
  esac
  test "$(source_git hash-object --no-filters -- "$CORELM_RELATIVE")" = \
    "$(source_git rev-parse --verify "HEAD:$CORELM_RELATIVE")"
}
verify_live_entry v4/bootstrap_runtime.sh 100755
verify_live_entry v4/run_post_release_regression.py 100644

REGRESSION_ROOT="$PWD/../corelm-v4-regression-$(date -u +%Y%m%dT%H%M%SZ)"
test ! -e "$REGRESSION_ROOT"
mkdir -m 700 "$REGRESSION_ROOT"
REGRESSION_ROOT=$(CDPATH= cd -- "$REGRESSION_ROOT" && pwd -P)
RUNTIME_ROOT="$REGRESSION_ROOT/runtime"
PYCACHE_ROOT="$REGRESSION_ROOT/isolated-python-cache"
ASSET_ROOT="$REGRESSION_ROOT/assets"
mkdir -m 700 "$PYCACHE_ROOT"
test -x /usr/bin/sandbox-exec
"$PYTHON_31210" -I -B -c '
import shutil, sys
raise SystemExit(0 if shutil.disk_usage(sys.argv[1]).free >= 16 * 1024**3 else 1)
' "$REGRESSION_ROOT"

./v4/bootstrap_runtime.sh \
  --platform macos \
  --codec-root ../codec-source \
  --runtime "$RUNTIME_ROOT" \
  --python "$PYTHON_31210"

/usr/bin/env -i \
  PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  LANG=C LC_ALL=C PYTHONHASHSEED=0 \
  "$RUNTIME_ROOT/bin/python" -P -s -B \
  -X "pycache_prefix=$PYCACHE_ROOT" \
  v4/run_post_release_regression.py --verify-source-only

"$RUNTIME_ROOT/bin/python" -I -B v4/run_zero_skip_tests.py
"$RUNTIME_ROOT/bin/python" -I -B v4/verify_design.py

"$RUNTIME_ROOT/bin/python" -I -B v4/fetch_assets.py \
  --destination "$ASSET_ROOT" \
  --include-development-dataset
"$RUNTIME_ROOT/bin/python" -I -B v4/create_asset_receipt.py \
  --asset-root "$ASSET_ROOT" \
  --output "$REGRESSION_ROOT/model-assets.full-rehash.json"
cmp "$REGRESSION_ROOT/model-assets.full-rehash.json" \
  v4/manifests/model-assets.full-rehash.json

"$RUNTIME_ROOT/bin/python" -I -B v4/preflight.py \
  --codec-root ../codec-source \
  --asset-root "$ASSET_ROOT" \
  --asset-receipt "$REGRESSION_ROOT/model-assets.full-rehash.json"

"$RUNTIME_ROOT/bin/python" -I -B v4/create_runtime_manifest.py \
  --runtime-root "$RUNTIME_ROOT" \
  --requirements-lock ../codec-source/.github/locks/pip-bootstrap.txt \
  --requirements-lock ../codec-source/RealLLM/requirements.lock \
  --codec-root ../codec-source \
  --output "$REGRESSION_ROOT/runtime-manifest.json" \
  --require-clean-git

/usr/bin/env -i \
  PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  LANG=C LC_ALL=C PYTHONHASHSEED=0 \
  "$RUNTIME_ROOT/bin/python" -P -s -B \
  -X "pycache_prefix=$PYCACHE_ROOT" \
  v4/run_post_release_regression.py \
  --asset-root "$ASSET_ROOT" \
  --dataset "$ASSET_ROOT/ud-english-pud-r2.18/en_pud-ud-test.conllu" \
  --codec-root ../codec-source \
  --runtime-manifest "$REGRESSION_ROOT/runtime-manifest.json" \
  --output "$REGRESSION_ROOT/evidence"
```

The preflight is expected to return `status=DEVELOPMENT_PREFLIGHT_ONLY` and
`executionReady=false` because the scientific design and NIST trust remain
blocked. It must nevertheless report the exact codec, verified full local
assets/receipt, macOS arm64, AC power, and the measured memory floor. The
preceding interpreter check, bootstrap, and runtime manifest separately bind
CPython 3.12.10. This development-only status does not turn the regression
into a scientific attempt.

Do not run the NIST one-shot from this guide. The registered V4 certificate
chain is not valid at the proposed `2026-09-25T18:00:00.000Z` pulse, and
replacing it changes the scientific source identity and every dependent
commitment.

## Read-only secret audit

The standalone scanner has no package dependency and never prints matched
bytes:

Run it from the verified post-release tag above. A Linux-only user must fetch,
verify, and detach-checkout that tag before this command; the frozen V4 tag
predates the scanner. No model download or macOS E2E is needed for this audit.

```sh
set -eu
git fetch --no-tags --prune origin \
  '+refs/heads/*:refs/remotes/origin/*'
git fetch --tags --force origin
python3 -I -B -m unittest discover \
  -s security/tests -p 'test*.py' -v
python3 -I -B security/scan_repository_secrets.py
```

CI and the block above fetch the public branch and tag refs visible at fetch
time, then scan the detached `HEAD`, worktree, index, ref/path names, and every
blob, commit, and annotated tag reachable from those local refs. Deleted,
unreachable, server-private, pull-request-only, or other un-fetched refs are
outside this claim. The repository policy forbids scanned worktree, index, or
reachable blob/commit/tag objects larger than 8 MiB; the scanner fails closed
on one instead of silently skipping it. Large model/data assets remain external
and are authenticated by their separate manifests. Passing this control means
no supported high-confidence secret shape was found; it is defense in depth,
not a proof that arbitrary credentials cannot exist in an unrecognized,
encoded, encrypted, or nested format. A PR must not be allowed to weaken its
own required workflow: branch protection or an organization ruleset must keep
this check and review policy outside unilateral contributor control.

# Release signing identity

All six blind-v1 annotated release tags (development-control, design,
snapshot, public execution reservation, evidence, and non-verdict closeout)
must use the single SSH signing
identity committed here. The public-key file SHA-256 is
`9d299ff032927caef3f1355fb55c01f206ebf27ef35bcb5da547f962168b1274` and its
OpenSSH SHA-256 fingerprint is
`SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM`.

This is the author's existing release-signing key previously used for V4; the
original `core-lm-cross-model-v4 signing` OpenSSH comment is intentionally
preserved because changing a comment changes the public-key file bytes. Key
reuse authenticates the same author only. It does not reuse V4's suite,
design, corpus, pulse, evidence, or scientific identity.

The private key is deliberately outside the repository and must never be
packaged as an artifact. Before the design freeze, the public key must be
registered on GitHub as a **signing key**, not merely an authentication key.
The Git author email must belong to the signing account. A signed tag is valid
only when both GitHub's immutable receipt and an offline verification against
[`allowed_signers`](allowed_signers) bind the exact tag object, commit, tree,
message, and key fingerprint.

Recommended repository-local Git configuration (never global):

```sh
git config gpg.format ssh
git config user.signingkey /absolute/private/key/path
git config gpg.ssh.allowedSignersFile blind_v1/signing/allowed_signers
```

The development-control, design, snapshot, public execution-reservation,
evidence, and closeout tags are separate signed objects. A successful rehearsal
tag does not satisfy any publication gate.

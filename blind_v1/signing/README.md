# Release signing identity (retired Blind V1 specification)

> **TERMINAL STATUS — DO NOT EXECUTE BLIND V1**
>
> Blind V1 is `CHECKPOINT_MISSED_TERMINAL_DRAFT`. It was retired without a
> scientific run and is not freezable, publishable, or executable. Every
> command and procedure in this document is preserved only as a historical,
> counterfactual specification and **MUST NOT be executed for Blind V1**. Any
> successor experiment requires a new suite ID and a fully rescheduled timeline.

The abandoned design specified that all six blind-v1 annotated release tags
(development-control, design, snapshot, public execution reservation,
evidence, and non-verdict closeout) would use the single SSH signing identity
committed here. The public-key file SHA-256 is
`9d299ff032927caef3f1355fb55c01f206ebf27ef35bcb5da547f962168b1274` and its
OpenSSH SHA-256 fingerprint is
`SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM`.

This is the author's existing release-signing key previously used for V4; the
original `core-lm-cross-model-v4 signing` OpenSSH comment is intentionally
preserved because changing a comment changes the public-key file bytes. Key
reuse authenticates the same author only. It does not reuse V4's suite,
design, corpus, pulse, evidence, or scientific identity.

The private key is deliberately outside the repository and must never be
packaged as an artifact. Had V1 remained eligible, its public key would have
needed registration on GitHub as a **signing key**, not merely an authentication
key, and the Git author email would have needed to belong to the signing
account. A V1 signed tag would only have been valid when both GitHub's immutable
receipt and an offline verification against
[`allowed_signers`](allowed_signers) bind the exact tag object, commit, tree,
message, and key fingerprint.

Historical repository-local Git configuration example (never global; do not
run for V1):

```sh
git config gpg.format ssh
git config user.signingkey /absolute/private/key/path
git config gpg.ssh.allowedSignersFile blind_v1/signing/allowed_signers
```

The development-control, design, snapshot, public execution-reservation,
evidence, and closeout tags are separate signed objects. A successful rehearsal
tag does not satisfy any publication gate.

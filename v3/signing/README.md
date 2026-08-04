# Release signing identity

All five blind-v3 annotated release tags (development-control, design,
snapshot, evidence, and non-verdict closeout) must use the single SSH signing
identity committed here. The public-key file SHA-256 is
`beac537f2979026cd85facd195132979a5a3a77da65f87d563ffb6253d408ea2` and its
OpenSSH SHA-256 fingerprint is
`SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM`.

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
git config gpg.ssh.allowedSignersFile v3/signing/allowed_signers
```

The development-control, design, snapshot, evidence, and closeout tags are
separate signed objects. A successful rehearsal tag does not satisfy any
publication gate.

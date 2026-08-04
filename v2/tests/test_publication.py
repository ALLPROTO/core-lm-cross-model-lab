from __future__ import annotations

import base64
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from v2.publication import (
    PublicationError,
    SOURCE_POLICY,
    SSH_KEYGEN,
    _digest_path,
    _read_regular,
    _require_exact_role_paths,
    require_frozen_lab_publication_source,
    verify_archived_ssh_tag_signature,
    verify_ssh_signing_key,
)
from v2.release_receipt import REQUIRED_ASSET_ROLES


class PublicationSignatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private_key = self.root / "signing-key"
        completed = subprocess.run(
            [
                str(SSH_KEYGEN),
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "corelm-v2-test",
                "-f",
                str(self.private_key),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.public_key = self.private_key.with_suffix(".pub")
        fingerprint = subprocess.run(
            [str(SSH_KEYGEN), "-lf", str(self.public_key), "-E", "sha256"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        ).stdout.decode("ascii").split()[1]
        self.fingerprint = fingerprint
        self.public_sha256 = hashlib.sha256(self.public_key.read_bytes()).hexdigest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def signed_receipt(self) -> dict[str, object]:
        payload = (
            b"object " + b"1" * 40 + b"\n"
            b"type commit\n"
            b"tag corelm-crossmodel-livewiki-v2-design\n"
            b"tagger Test <test@example.invalid> 1785600000 +0000\n\n"
            b"registered design\n"
        )
        payload_path = self.root / "tag-payload"
        payload_path.write_bytes(payload)
        completed = subprocess.run(
            [
                str(SSH_KEYGEN),
                "-Y",
                "sign",
                "-f",
                str(self.private_key),
                "-n",
                "git",
                str(payload_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        signature = payload_path.with_suffix(".sig").read_bytes()
        archived = payload + signature
        return {
            "annotatedTag": {
                "rawPayload": {
                    "dataBase64": base64.b64encode(archived).decode("ascii")
                }
            }
        }

    def test_exact_public_key_and_archived_tag_signature_verify(self) -> None:
        key_line = verify_ssh_signing_key(
            self.public_key,
            expected_sha256=self.public_sha256,
            expected_fingerprint=self.fingerprint,
        )
        verify_archived_ssh_tag_signature(
            self.signed_receipt(), public_key_line=key_line
        )

    def test_wrong_key_digest_and_tampered_signed_payload_fail(self) -> None:
        with self.assertRaisesRegex(PublicationError, "bytes differ"):
            verify_ssh_signing_key(
                self.public_key,
                expected_sha256="0" * 64,
                expected_fingerprint=self.fingerprint,
            )
        key_line = verify_ssh_signing_key(
            self.public_key,
            expected_sha256=self.public_sha256,
            expected_fingerprint=self.fingerprint,
        )
        receipt = self.signed_receipt()
        encoded = receipt["annotatedTag"]["rawPayload"]["dataBase64"]
        raw = bytearray(base64.b64decode(encoded))
        raw[10] ^= 1
        receipt["annotatedTag"]["rawPayload"]["dataBase64"] = base64.b64encode(
            raw
        ).decode("ascii")
        with self.assertRaisesRegex(PublicationError, "not valid"):
            verify_archived_ssh_tag_signature(receipt, public_key_line=key_line)

    def test_semantic_binding_must_reopen_every_release_role(self) -> None:
        roles = REQUIRED_ASSET_ROLES["design"]
        records = {role: {"role": role} for role in roles}
        paths = {role: self.root / role for role in roles}
        _require_exact_role_paths("design", records, paths)

        incomplete = dict(paths)
        incomplete.pop("linux-ci-artifact")
        with self.assertRaisesRegex(PublicationError, "roles differ"):
            _require_exact_role_paths("design", records, incomplete)

        extra = dict(paths)
        extra["unregistered"] = self.root / "unregistered"
        with self.assertRaisesRegex(PublicationError, "roles differ"):
            _require_exact_role_paths("design", records, extra)

    def test_parent_symlink_is_rejected_for_reads_and_digests(self) -> None:
        real_parent = self.root / "real-parent"
        real_parent.mkdir()
        payload = real_parent / "payload.bin"
        payload.write_bytes(b"publication evidence\n")
        linked_parent = self.root / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        hostile_path = linked_parent / payload.name

        with self.assertRaisesRegex(PublicationError, "parent component"):
            _read_regular(hostile_path, maximum_bytes=1024, label="hostile input")
        with self.assertRaisesRegex(PublicationError, "parent component"):
            _digest_path(hostile_path, label="hostile input")

    def test_every_release_source_is_bound_to_frozen_lab_source(self) -> None:
        commit, tree = "a" * 40, "b" * 40
        design = {
            "labSource": {
                "status": "FROZEN_BOUND",
                "commit": commit,
                "tree": tree,
            },
            "snapshotRelease": {"sourcePolicy": SOURCE_POLICY},
        }
        publication = SimpleNamespace(source_commit=commit, source_tree=tree)
        require_frozen_lab_publication_source(
            publication,
            design,
            kind="snapshot",
        )

        publication.source_tree = "f" * 40
        with self.assertRaisesRegex(PublicationError, "frozen lab commit/tree"):
            require_frozen_lab_publication_source(
                publication,
                design,
                kind="snapshot",
            )
        design["snapshotRelease"]["sourcePolicy"] = "ALLOW_LATER_COMMIT"
        with self.assertRaisesRegex(PublicationError, "source policy differs"):
            require_frozen_lab_publication_source(
                SimpleNamespace(source_commit=commit, source_tree=tree),
                design,
                kind="snapshot",
            )


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Offline, fail-closed verification for the registered NIST Beacon pulse.

The implementation follows the official NIST Beacon 2.0 schema and draft
reference.  It reconstructs the signed bytes, verifies RSA PKCS#1 v1.5 with
SHA-512, recomputes ``outputValue``, binds the exact time endpoint/timestamp,
and resolves the signing certificate only from a pre-frozen offline bundle.

Primary references:

* https://csrc.nist.gov/Projects/interoperable-randomness-beacons/beacon-20
* https://csrc.nist.gov/csrc/media/Projects/interoperable-randomness-beacons/documents/certificate/beacon-2.0.xsd
* https://doi.org/10.6028/NIST.IR.8213-draft

No online certificate returned with a pulse is trusted.  A normative bundle
must contain the exact PEM and DER commitments and a complete, cryptographically
verified RSA X.509 chain to a pinned root.  A leaf-only mode exists solely for
committed historical known-answer unit fixtures and is rejected by default.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from blind_v1.mediawiki_snapshot import (
    ArchivedHTTPResponse,
    SnapshotError,
    _validate_response,
    load_archived_response,
    response_date,
)
from blind_v1.protocol import canonical_json_bytes, load_json_strict_bytes, sha256_bytes


TARGET_UNIX_MILLISECONDS = 1787335200000
TARGET_TIMESTAMP = "2026-08-21T18:00:00.000Z"
TARGET_ENDPOINT = (
    "https://beacon.nist.gov/beacon/2.0/pulse/time/1787335200000"
)
TRUST_SCHEMA = "corelm-blind-crossmodel-v1-nist-trust-bundle-v2"
VERIFY_SCHEMA = "corelm-blind-crossmodel-v1-nist-verification-v1"
TRUST_CANDIDATE_STATUS = "CANDIDATE_OFFLINE_TRUST_BUNDLE"
TRUST_FROZEN_STATUS = "FROZEN_OFFLINE_TRUST_BUNDLE"
TRUST_FIXTURE_STATUS = "KNOWN_ANSWER_FIXTURE_ONLY"
TRUST_REVOCATION_POLICY = "EXACT_CERTIFICATE_PIN_NO_REVOCATION_CHECK"
TRUST_REVOCATION_RESIDUAL_RISK = (
    "A pinned certificate that is revoked or compromised before the target pulse "
    "can still be accepted; no contemporaneous OCSP or CRL status is checked or "
    "claimed."
)
TRUST_ROTATION_POLICY = "NO_ROTATION_AFTER_FREEZE"
TRUST_ACCEPTED_LEAF_EXTENDED_KEY_USAGES = (
    "1.3.6.1.5.5.7.3.1",  # id-kp-serverAuth
    "1.3.6.1.5.5.7.3.2",  # id-kp-clientAuth
)
PRODUCTION_PULSE_VERSION = "2.0"
HISTORICAL_FIXTURE_PULSE_VERSION = "Version 2.0"
PULSE_CIPHER_SUITE = 0
PULSE_PERIOD_MILLISECONDS = 60000
NIST_TRUST_ROOT_DER_SHA256 = (
    "cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f"
)
HEX_64 = re.compile(r"[0-9a-fA-F]{128}\Z")
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
HEX_SIGNATURE = re.compile(r"(?:[0-9a-fA-F]{2})+\Z")
MILLISECONDS_UTC = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\Z"
)
RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1"
RSA_SIGNATURE_OIDS = {
    "1.2.840.113549.1.1.5": ("sha1", bytes.fromhex("3021300906052b0e03021a05000414")),
    "1.2.840.113549.1.1.11": (
        "sha256",
        bytes.fromhex("3031300d060960864801650304020105000420"),
    ),
    "1.2.840.113549.1.1.12": (
        "sha384",
        bytes.fromhex("3041300d060960864801650304020205000430"),
    ),
    "1.2.840.113549.1.1.13": (
        "sha512",
        bytes.fromhex("3051300d060960864801650304020305000440"),
    ),
}
PULSE_DIGEST_INFO_PREFIX = RSA_SIGNATURE_OIDS["1.2.840.113549.1.1.13"][1]


class BeaconVerificationError(ValueError):
    """Raised for any unverified or ambiguous NIST pulse condition."""


@dataclass(frozen=True)
class DERNode:
    tag: int
    start: int
    content_start: int
    end: int

    def encoded(self, source: bytes) -> bytes:
        return source[self.start : self.end]

    def content(self, source: bytes) -> bytes:
        return source[self.content_start : self.end]


@dataclass(frozen=True)
class RSAPublicKey:
    modulus: int
    exponent: int

    @property
    def bytes(self) -> int:
        return (self.modulus.bit_length() + 7) // 8


@dataclass(frozen=True)
class ParsedCertificate:
    der: bytes
    tbs: bytes
    signature_oid: str
    signature: bytes
    issuer: bytes
    subject: bytes
    not_before: datetime
    not_after: datetime
    public_key: RSAPublicKey
    basic_constraints_present: bool
    is_ca: bool
    path_length: int | None
    key_usage_present: bool
    digital_signature: bool
    key_cert_sign: bool
    extended_key_usages: tuple[str, ...]
    dns_names: tuple[str, ...]


@dataclass(frozen=True)
class TrustRecord:
    certificate_id: str
    pem_bytes: bytes
    chain: tuple[ParsedCertificate, ...]
    chain_verified: bool
    chain_policy: str

    @property
    def leaf(self) -> ParsedCertificate:
        return self.chain[0]


@dataclass(frozen=True)
class OfflineTrustBundle:
    manifest_sha256: str
    fixture_only: bool
    records: Mapping[str, TrustRecord]


def _read_der_node(source: bytes, offset: int) -> tuple[DERNode, int]:
    if offset < 0 or offset >= len(source):
        raise BeaconVerificationError("DER node is truncated")
    start = offset
    tag = source[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        raise BeaconVerificationError("high-tag-number DER is unsupported")
    if offset >= len(source):
        raise BeaconVerificationError("DER length is truncated")
    first = source[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        width = first & 0x7F
        if width == 0 or width > 4 or offset + width > len(source):
            raise BeaconVerificationError("DER length is indefinite/oversized")
        raw = source[offset : offset + width]
        if raw[0] == 0:
            raise BeaconVerificationError("DER length is not minimally encoded")
        length = int.from_bytes(raw, "big")
        if length < 0x80:
            raise BeaconVerificationError("DER long length is not minimal")
        offset += width
    end = offset + length
    if end > len(source):
        raise BeaconVerificationError("DER content is truncated")
    return DERNode(tag, start, offset, end), end


def _children(source: bytes, node: DERNode) -> list[DERNode]:
    result: list[DERNode] = []
    offset = node.content_start
    while offset < node.end:
        child, offset = _read_der_node(source, offset)
        result.append(child)
    if offset != node.end:
        raise BeaconVerificationError("DER child framing differs")
    return result


def _single_root(source: bytes, *, tag: int = 0x30) -> DERNode:
    root, end = _read_der_node(source, 0)
    if root.tag != tag or end != len(source):
        raise BeaconVerificationError("DER root framing differs")
    return root


def _der_integer(source: bytes, node: DERNode) -> int:
    value = node.content(source)
    if node.tag != 0x02 or not value or value[0] & 0x80:
        raise BeaconVerificationError("DER INTEGER is invalid/negative")
    if len(value) > 1 and value[0] == 0 and not value[1] & 0x80:
        raise BeaconVerificationError("DER INTEGER is not minimal")
    return int.from_bytes(value, "big")


def _der_boolean(source: bytes, node: DERNode) -> bool:
    value = node.content(source)
    if node.tag != 0x01 or len(value) != 1 or value[0] not in (0x00, 0xFF):
        raise BeaconVerificationError("DER BOOLEAN is not canonical")
    return value[0] == 0xFF


def _oid(source: bytes, node: DERNode) -> str:
    value = node.content(source)
    if node.tag != 0x06 or not value:
        raise BeaconVerificationError("DER OID is invalid")
    first = value[0]
    components = [min(first // 40, 2), first - min(first // 40, 2) * 40]
    current = 0
    active = False
    for byte in value[1:]:
        if not active and byte == 0x80:
            raise BeaconVerificationError("DER OID is not minimally encoded")
        active = True
        current = (current << 7) | (byte & 0x7F)
        if byte & 0x80 == 0:
            components.append(current)
            current = 0
            active = False
    if active:
        raise BeaconVerificationError("DER OID is truncated")
    return ".".join(str(item) for item in components)


def _algorithm_oid(source: bytes, node: DERNode) -> str:
    if node.tag != 0x30:
        raise BeaconVerificationError("certificate algorithm is not a SEQUENCE")
    values = _children(source, node)
    if not values:
        raise BeaconVerificationError("certificate algorithm is empty")
    return _oid(source, values[0])


def _der_time(source: bytes, node: DERNode) -> datetime:
    try:
        text = node.content(source).decode("ascii")
    except UnicodeDecodeError as error:
        raise BeaconVerificationError("certificate validity is not ASCII") from error
    try:
        if node.tag == 0x17 and re.fullmatch(r"\d{12}Z", text):
            year = int(text[:2])
            year += 2000 if year < 50 else 1900
            return datetime.strptime(str(year) + text[2:], "%Y%m%d%H%M%SZ").replace(
                tzinfo=timezone.utc
            )
        if node.tag == 0x18 and re.fullmatch(r"\d{14}Z", text):
            return datetime.strptime(text, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise BeaconVerificationError("certificate validity is not a real time") from error
    raise BeaconVerificationError("certificate validity format is unsupported")


def _parse_certificate_extensions(
    source: bytes, wrapper: DERNode
) -> tuple[
    bool,
    bool,
    int | None,
    bool,
    bool,
    bool,
    tuple[str, ...],
    tuple[str, ...],
]:
    wrapped = _children(source, wrapper)
    if wrapper.tag != 0xA3 or len(wrapped) != 1 or wrapped[0].tag != 0x30:
        raise BeaconVerificationError("X.509 extensions wrapper differs")
    extensions = _children(source, wrapped[0])
    if not extensions:
        raise BeaconVerificationError("X.509 extension list is empty")
    seen: set[str] = set()
    basic_present = False
    is_ca = False
    path_length: int | None = None
    key_usage_present = False
    digital_signature = False
    key_cert_sign = False
    extended_key_usages: tuple[str, ...] = ()
    dns_names: tuple[str, ...] = ()
    understood = {"2.5.29.19", "2.5.29.15", "2.5.29.37", "2.5.29.17"}
    for extension in extensions:
        if extension.tag != 0x30:
            raise BeaconVerificationError("X.509 extension is not a SEQUENCE")
        fields = _children(source, extension)
        if len(fields) not in {2, 3}:
            raise BeaconVerificationError("X.509 extension fields differ")
        oid = _oid(source, fields[0])
        if oid in seen:
            raise BeaconVerificationError("duplicate X.509 extension")
        seen.add(oid)
        critical = False
        value_index = 1
        if len(fields) == 3:
            critical = _der_boolean(source, fields[1])
            if not critical:
                raise BeaconVerificationError(
                    "explicit false X.509 critical flag is non-canonical"
                )
            value_index = 2
        value_node = fields[value_index]
        if value_node.tag != 0x04:
            raise BeaconVerificationError("X.509 extnValue is not OCTET STRING")
        encoded_value = value_node.content(source)
        if critical and oid not in understood:
            raise BeaconVerificationError(
                f"unsupported critical X.509 extension: {oid}"
            )
        if oid == "2.5.29.19":
            basic_present = True
            items = _children(encoded_value, _single_root(encoded_value))
            if len(items) > 2:
                raise BeaconVerificationError("BasicConstraints fields differ")
            offset = 0
            if items and items[0].tag == 0x01:
                is_ca = _der_boolean(encoded_value, items[0])
                offset = 1
            if len(items) > offset:
                path_length = _der_integer(encoded_value, items[offset])
                offset += 1
            if offset != len(items) or path_length is not None and not is_ca:
                raise BeaconVerificationError("BasicConstraints is inconsistent")
        elif oid == "2.5.29.15":
            key_usage_present = True
            bit_node = _single_root(encoded_value, tag=0x03)
            bits = bit_node.content(encoded_value)
            if len(bits) < 2 or bits[0] > 7:
                raise BeaconVerificationError("KeyUsage BIT STRING differs")
            unused = bits[0]
            payload = bits[1:]
            if unused and payload[-1] & ((1 << unused) - 1):
                raise BeaconVerificationError("KeyUsage unused bits are nonzero")
            digital_signature = bool(payload[0] & 0x80)
            key_cert_sign = bool(payload[0] & 0x04)
        elif oid == "2.5.29.37":
            sequence = _children(encoded_value, _single_root(encoded_value))
            if not sequence:
                raise BeaconVerificationError("ExtendedKeyUsage is empty")
            extended_key_usages = tuple(_oid(encoded_value, item) for item in sequence)
            if len(set(extended_key_usages)) != len(extended_key_usages):
                raise BeaconVerificationError("ExtendedKeyUsage repeats an OID")
        elif oid == "2.5.29.17":
            names = _children(encoded_value, _single_root(encoded_value))
            observed_dns: list[str] = []
            for name in names:
                if name.tag == 0x82:
                    try:
                        dns_name = name.content(encoded_value).decode(
                            "ascii", errors="strict"
                        ).lower()
                    except UnicodeDecodeError as error:
                        raise BeaconVerificationError(
                            "SubjectAltName dNSName is not ASCII"
                        ) from error
                    if (
                        not dns_name
                        or "*" in dns_name
                        or re.fullmatch(
                            r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?",
                            dns_name,
                        )
                        is None
                    ):
                        raise BeaconVerificationError(
                            "SubjectAltName dNSName is invalid"
                        )
                    observed_dns.append(dns_name)
            if len(set(observed_dns)) != len(observed_dns):
                raise BeaconVerificationError("SubjectAltName repeats a dNSName")
            dns_names = tuple(observed_dns)
    return (
        basic_present,
        is_ca,
        path_length,
        key_usage_present,
        digital_signature,
        key_cert_sign,
        extended_key_usages,
        dns_names,
    )


def parse_certificate_der(der: bytes) -> ParsedCertificate:
    if not isinstance(der, bytes) or len(der) > 1024 * 1024:
        raise BeaconVerificationError("certificate DER is missing/oversized")
    root = _single_root(der)
    certificate = _children(der, root)
    if len(certificate) != 3 or certificate[0].tag != 0x30 or certificate[2].tag != 0x03:
        raise BeaconVerificationError("X.509 certificate framing differs")
    tbs_node, outer_algorithm, signature_node = certificate
    signature_content = signature_node.content(der)
    if not signature_content or signature_content[0] != 0:
        raise BeaconVerificationError("certificate signature BIT STRING is invalid")
    signature_oid = _algorithm_oid(der, outer_algorithm)
    tbs_children = _children(der, tbs_node)
    if not tbs_children or tbs_children[0].tag != 0xA0:
        raise BeaconVerificationError("X.509 v3 version field is absent")
    version_fields = _children(der, tbs_children[0])
    if len(version_fields) != 1 or _der_integer(der, version_fields[0]) != 2:
        raise BeaconVerificationError("certificate is not X.509 v3")
    index = 1
    # serial, signature, issuer, validity, subject, subjectPublicKeyInfo
    if len(tbs_children) < index + 6:
        raise BeaconVerificationError("TBSCertificate fields are incomplete")
    _der_integer(der, tbs_children[index])
    inner_signature_oid = _algorithm_oid(der, tbs_children[index + 1])
    if inner_signature_oid != signature_oid:
        raise BeaconVerificationError("certificate signature algorithms disagree")
    issuer_node = tbs_children[index + 2]
    validity_node = tbs_children[index + 3]
    subject_node = tbs_children[index + 4]
    spki_node = tbs_children[index + 5]
    validity = _children(der, validity_node)
    if validity_node.tag != 0x30 or len(validity) != 2:
        raise BeaconVerificationError("certificate validity fields differ")
    spki = _children(der, spki_node)
    if spki_node.tag != 0x30 or len(spki) != 2 or _algorithm_oid(der, spki[0]) != RSA_ENCRYPTION_OID:
        raise BeaconVerificationError("certificate public key is not RSA")
    bit_string = spki[1].content(der)
    if spki[1].tag != 0x03 or not bit_string or bit_string[0] != 0:
        raise BeaconVerificationError("certificate RSA key BIT STRING is invalid")
    rsa_source = bit_string[1:]
    rsa_root = _single_root(rsa_source)
    rsa_values = _children(rsa_source, rsa_root)
    if len(rsa_values) != 2:
        raise BeaconVerificationError("certificate RSA key fields differ")
    public_key = RSAPublicKey(
        _der_integer(rsa_source, rsa_values[0]),
        _der_integer(rsa_source, rsa_values[1]),
    )
    if public_key.modulus.bit_length() < 2048 or public_key.exponent < 3 or public_key.exponent % 2 == 0:
        raise BeaconVerificationError("certificate RSA key is too small/invalid")
    trailing = tbs_children[index + 6 :]
    extension_nodes = [item for item in trailing if item.tag == 0xA3]
    if len(extension_nodes) != 1 or any(
        item.tag not in {0x81, 0x82, 0xA3} for item in trailing
    ):
        raise BeaconVerificationError("certificate extension framing differs")
    extension_state = _parse_certificate_extensions(der, extension_nodes[0])
    return ParsedCertificate(
        der=der,
        tbs=tbs_node.encoded(der),
        signature_oid=signature_oid,
        signature=signature_content[1:],
        issuer=issuer_node.encoded(der),
        subject=subject_node.encoded(der),
        not_before=_der_time(der, validity[0]),
        not_after=_der_time(der, validity[1]),
        public_key=public_key,
        basic_constraints_present=extension_state[0],
        is_ca=extension_state[1],
        path_length=extension_state[2],
        key_usage_present=extension_state[3],
        digital_signature=extension_state[4],
        key_cert_sign=extension_state[5],
        extended_key_usages=extension_state[6],
        dns_names=extension_state[7],
    )


def _rsa_pkcs1_verify_digest(
    public_key: RSAPublicKey,
    signature: bytes,
    digest: bytes,
    digest_info_prefix: bytes,
) -> None:
    if len(signature) != public_key.bytes:
        raise BeaconVerificationError("RSA signature length differs from the key")
    value = int.from_bytes(signature, "big")
    if value >= public_key.modulus:
        raise BeaconVerificationError("RSA signature representative is out of range")
    encoded = pow(value, public_key.exponent, public_key.modulus).to_bytes(
        public_key.bytes, "big"
    )
    trailer = digest_info_prefix + digest
    padding_length = len(encoded) - len(trailer) - 3
    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + trailer
    if padding_length < 8 or not hmac.compare_digest(encoded, expected):
        raise BeaconVerificationError("RSA PKCS#1 v1.5 signature verification failed")


def _verify_certificate_signature(
    certificate: ParsedCertificate, issuer_key: RSAPublicKey
) -> None:
    algorithm = RSA_SIGNATURE_OIDS.get(certificate.signature_oid)
    if algorithm is None:
        raise BeaconVerificationError("certificate signature algorithm is unsupported")
    digest_name, prefix = algorithm
    digest = hashlib.new(digest_name, certificate.tbs).digest()
    _rsa_pkcs1_verify_digest(issuer_key, certificate.signature, digest, prefix)


def _pem_to_der(pem: bytes) -> bytes:
    try:
        text = pem.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise BeaconVerificationError("certificate PEM is not ASCII") from error
    match = re.fullmatch(
        r"\s*-----BEGIN CERTIFICATE-----\s*"
        r"([A-Za-z0-9+/=\r\n]+?)"
        r"\s*-----END CERTIFICATE-----\s*",
        text,
    )
    if match is None:
        raise BeaconVerificationError("certificate PEM must contain exactly one certificate")
    try:
        return base64.b64decode("".join(match.group(1).split()), validate=True)
    except (ValueError, binascii.Error) as error:
        raise BeaconVerificationError("certificate PEM base64 is invalid") from error


def _safe_relative(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise BeaconVerificationError("trust bundle path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise BeaconVerificationError("trust bundle path is unsafe")
    return path


def _read_commitment(root: Path, value: Any, *, sha512_required: bool) -> bytes:
    fields = {"relativePath", "bytes", "sha256"}
    if sha512_required:
        fields.add("sha512")
    if not isinstance(value, dict) or set(value) != fields:
        raise BeaconVerificationError("trust file commitment fields differ")
    path = _safe_relative(value["relativePath"])
    if root.is_symlink():
        raise BeaconVerificationError("trust bundle root is a symlink")
    resolved_root = root.resolve(strict=True)
    current = resolved_root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise BeaconVerificationError("trust bundle path contains a symlink")
    if not current.is_file() or current.is_symlink():
        raise BeaconVerificationError("trust bundle file is missing/not regular")
    content = current.read_bytes()
    if type(value["bytes"]) is not int or value["bytes"] != len(content):
        raise BeaconVerificationError("trust bundle byte count differs")
    if value["sha256"] != sha256_bytes(content):
        raise BeaconVerificationError("trust bundle SHA-256 differs")
    if sha512_required and value["sha512"] != hashlib.sha512(content).hexdigest():
        raise BeaconVerificationError("trust bundle SHA-512 differs")
    return content


def _verify_leaf_policy(leaf: ParsedCertificate) -> None:
    if not leaf.basic_constraints_present or leaf.is_ca:
        raise BeaconVerificationError(
            "NIST signing leaf BasicConstraints is absent/not CA=false"
        )
    if not leaf.key_usage_present or not leaf.digital_signature or leaf.key_cert_sign:
        raise BeaconVerificationError(
            "NIST signing leaf KeyUsage does not permit only an end-entity signature"
        )
    if leaf.dns_names != ("engine.beacon.nist.gov",):
        raise BeaconVerificationError(
            "NIST signing leaf is not exactly bound to engine.beacon.nist.gov"
        )
    if (
        leaf.extended_key_usages
        != TRUST_ACCEPTED_LEAF_EXTENDED_KEY_USAGES
    ):
        raise BeaconVerificationError(
            "NIST signing leaf ExtendedKeyUsage differs from the exact "
            "serverAuth+clientAuth policy"
        )


def _verify_chain(chain: Sequence[ParsedCertificate], at_time: datetime) -> None:
    if len(chain) < 2:
        raise BeaconVerificationError("normative trust chain has no issuer/root")
    _verify_leaf_policy(chain[0])
    for index, certificate in enumerate(chain):
        if not (certificate.not_before <= at_time <= certificate.not_after):
            raise BeaconVerificationError("certificate is not valid at pulse time")
        if index >= 1:
            if (
                not certificate.basic_constraints_present
                or not certificate.is_ca
                or not certificate.key_usage_present
                or not certificate.key_cert_sign
            ):
                raise BeaconVerificationError(
                    "certificate issuer lacks CA/keyCertSign authority"
                )
            subordinate_ca_count = sum(item.is_ca for item in chain[1:index])
            if (
                certificate.path_length is not None
                and subordinate_ca_count > certificate.path_length
            ):
                raise BeaconVerificationError(
                    "certificate pathLenConstraint is exceeded"
                )
        if index + 1 < len(chain):
            issuer = chain[index + 1]
            if certificate.issuer != issuer.subject:
                raise BeaconVerificationError("certificate issuer/subject chain differs")
            _verify_certificate_signature(certificate, issuer.public_key)
        else:
            if certificate.issuer != certificate.subject:
                raise BeaconVerificationError("trust anchor is not self-issued")
            _verify_certificate_signature(certificate, certificate.public_key)


def _validate_trust_policy(
    value: Any, certificates: Any
) -> tuple[str, ...]:
    fields = {
        "allowedCertificateIds",
        "rotationPolicy",
        "revocationPolicy",
        "revocationChecked",
        "revocationResidualRisk",
        "acceptedLeafExtendedKeyUsages",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise BeaconVerificationError("NIST trust policy fields differ")
    allowed = value["allowedCertificateIds"]
    if (
        not isinstance(allowed, list)
        or len(allowed) != 1
        or not isinstance(allowed[0], str)
        or re.fullmatch(r"[0-9a-f]{128}", allowed[0]) is None
    ):
        raise BeaconVerificationError(
            "NIST trust policy must allow exactly one lowercase certificate ID"
        )
    if value["rotationPolicy"] != TRUST_ROTATION_POLICY:
        raise BeaconVerificationError("NIST certificate rotation policy differs")
    if value["revocationPolicy"] != TRUST_REVOCATION_POLICY:
        raise BeaconVerificationError("NIST certificate revocation policy differs")
    if value["revocationChecked"] is not False:
        raise BeaconVerificationError(
            "NIST no-revocation-check policy must declare revocationChecked=false"
        )
    if value["revocationResidualRisk"] != TRUST_REVOCATION_RESIDUAL_RISK:
        raise BeaconVerificationError("NIST revocation residual-risk disclosure differs")
    accepted_eku = value["acceptedLeafExtendedKeyUsages"]
    if (
        not isinstance(accepted_eku, list)
        or tuple(accepted_eku) != TRUST_ACCEPTED_LEAF_EXTENDED_KEY_USAGES
    ):
        raise BeaconVerificationError(
            "NIST accepted leaf ExtendedKeyUsage policy differs"
        )
    if (
        not isinstance(certificates, dict)
        or len(certificates) != 1
        or tuple(certificates) != tuple(allowed)
    ):
        raise BeaconVerificationError(
            "NIST certificate map differs from singleton allowedCertificateIds"
        )
    return tuple(allowed)


def load_offline_trust_bundle(
    manifest_path: Path,
    *,
    expected_time: datetime,
    expected_manifest_sha256: str | None = None,
    expected_root_der_sha256: Sequence[str] | None = None,
    allow_fixture: bool = False,
    allow_candidate: bool = False,
) -> OfflineTrustBundle:
    if not isinstance(expected_time, datetime) or expected_time.tzinfo is None:
        raise BeaconVerificationError("NIST trust verification time must be timezone-aware")
    expected_time = expected_time.astimezone(timezone.utc)
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise BeaconVerificationError("NIST trust manifest is missing/not regular")
    manifest_bytes = manifest_path.read_bytes()
    manifest_sha256 = sha256_bytes(manifest_bytes)
    if expected_manifest_sha256 is not None:
        if (
            not isinstance(expected_manifest_sha256, str)
            or HEX_SHA256.fullmatch(expected_manifest_sha256) is None
            or not hmac.compare_digest(manifest_sha256, expected_manifest_sha256)
        ):
            raise BeaconVerificationError(
                "NIST trust manifest differs from its preregistered SHA-256"
            )
    manifest = load_json_strict_bytes(manifest_bytes, label="NIST trust bundle")
    if type(allow_fixture) is not bool or type(allow_candidate) is not bool:
        raise BeaconVerificationError("NIST trust loader policy flags are invalid")
    fields = {
        "schemaVersion",
        "status",
        "fixtureOnly",
        "trustPolicy",
        "certificates",
    }
    if not isinstance(manifest, dict) or set(manifest) != fields:
        raise BeaconVerificationError("NIST trust bundle fields differ")
    if canonical_json_bytes(manifest) != manifest_bytes:
        raise BeaconVerificationError("NIST trust bundle is not canonical JSON")
    if manifest["schemaVersion"] != TRUST_SCHEMA:
        raise BeaconVerificationError("unexpected NIST trust bundle schema")
    fixture_only = manifest["fixtureOnly"]
    if type(fixture_only) is not bool:
        raise BeaconVerificationError("NIST trust fixture flag is invalid")
    if fixture_only and not allow_fixture:
        raise BeaconVerificationError("fixture-only NIST trust bundle is forbidden")
    if not fixture_only and expected_manifest_sha256 is None:
        raise BeaconVerificationError(
            "normative NIST trust bundle requires a preregistered manifest SHA-256"
        )
    if fixture_only:
        if manifest["status"] != TRUST_FIXTURE_STATUS:
            raise BeaconVerificationError("NIST trust bundle status differs")
    elif manifest["status"] == TRUST_CANDIDATE_STATUS:
        if not allow_candidate:
            raise BeaconVerificationError(
                "candidate NIST trust bundle is not freeze-ready"
            )
    elif manifest["status"] != TRUST_FROZEN_STATUS:
        raise BeaconVerificationError("NIST trust bundle status differs")
    certificates = manifest["certificates"]
    _validate_trust_policy(manifest["trustPolicy"], certificates)
    records: dict[str, TrustRecord] = {}
    root = manifest_path.parent
    for certificate_id, specification in certificates.items():
        if not isinstance(certificate_id, str) or HEX_64.fullmatch(certificate_id) is None:
            raise BeaconVerificationError("NIST certificate ID is invalid")
        if not isinstance(specification, dict) or set(specification) != {"chainPolicy", "pem", "chain"}:
            raise BeaconVerificationError("NIST certificate specification fields differ")
        pem = _read_commitment(root, specification["pem"], sha512_required=False)
        chain_specs = specification["chain"]
        if not isinstance(chain_specs, list) or not chain_specs:
            raise BeaconVerificationError("NIST certificate chain is empty")
        chain_der = [
            _read_commitment(root, item, sha512_required=True) for item in chain_specs
        ]
        if len({hashlib.sha512(item).digest() for item in chain_der}) != len(chain_der):
            raise BeaconVerificationError("NIST certificate chain repeats a certificate")
        if _pem_to_der(pem) != chain_der[0]:
            raise BeaconVerificationError("NIST PEM and leaf DER differ")
        if hashlib.sha512(chain_der[0]).hexdigest() != certificate_id.lower():
            raise BeaconVerificationError("NIST certificateId differs from leaf DER SHA-512")
        chain = tuple(parse_certificate_der(item) for item in chain_der)
        _verify_leaf_policy(chain[0])
        policy = specification["chainPolicy"]
        if fixture_only:
            if policy != "fixture-leaf-pin-only" or len(chain) != 1:
                raise BeaconVerificationError("NIST fixture chain policy differs")
            if not (chain[0].not_before <= expected_time <= chain[0].not_after):
                raise BeaconVerificationError("fixture certificate is not valid at pulse time")
            chain_verified = False
        else:
            if policy != "offline-x509-rsa-pkcs1" or len(chain) < 2:
                raise BeaconVerificationError("normative NIST chain policy differs")
            if (
                not isinstance(expected_root_der_sha256, Sequence)
                or isinstance(expected_root_der_sha256, (str, bytes))
                or not expected_root_der_sha256
            ):
                raise BeaconVerificationError(
                    "normative NIST chain requires preregistered trust-root pins"
                )
            root_pins: list[str] = []
            for root_pin in expected_root_der_sha256:
                if not isinstance(root_pin, str) or HEX_SHA256.fullmatch(root_pin) is None:
                    raise BeaconVerificationError("NIST trust-root pin is invalid")
                root_pins.append(root_pin.lower())
            if len(set(root_pins)) != len(root_pins):
                raise BeaconVerificationError("NIST trust-root pins repeat")
            actual_root_pin = hashlib.sha256(chain_der[-1]).hexdigest()
            if not any(
                hmac.compare_digest(actual_root_pin, root_pin)
                for root_pin in root_pins
            ):
                raise BeaconVerificationError(
                    "NIST trust anchor is absent from preregistered root pins"
                )
            _verify_chain(chain, expected_time)
            chain_verified = True
        normalized = certificate_id.lower()
        if normalized in records:
            raise BeaconVerificationError("duplicate NIST certificate ID")
        records[normalized] = TrustRecord(
            normalized, pem, chain, chain_verified, policy
        )
    return OfflineTrustBundle(
        manifest_sha256, fixture_only, MappingProxyType(records)
    )


def _hex64(value: Any, *, label: str) -> bytes:
    if not isinstance(value, str) or HEX_64.fullmatch(value) is None:
        raise BeaconVerificationError(f"{label} must contain exactly 64 hex bytes")
    return bytes.fromhex(value)


def _u32(value: Any, *, label: str) -> bytes:
    if type(value) is not int or not 0 <= value < 2**32:
        raise BeaconVerificationError(f"{label} is outside uint32")
    return struct.pack(">I", value)


def _u64(value: Any, *, label: str) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        raise BeaconVerificationError(f"{label} is outside uint64")
    return struct.pack(">Q", value)


def _length_prefixed(value: bytes) -> bytes:
    if len(value) >= 2**32:
        raise BeaconVerificationError("NIST field exceeds uint32 length")
    return struct.pack(">I", len(value)) + value


def _string(value: Any, *, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise BeaconVerificationError(f"{label} must be a non-empty string")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise BeaconVerificationError(f"{label} is not strict UTF-8") from error
    return _length_prefixed(encoded)


def _parse_pulse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or MILLISECONDS_UTC.fullmatch(value) is None:
        raise BeaconVerificationError("NIST timeStamp must have exact UTC milliseconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise BeaconVerificationError("NIST timeStamp is not a real time") from error


def serialize_unsigned_pulse(
    pulse: Mapping[str, Any], *, expected_version: str = PRODUCTION_PULSE_VERSION
) -> bytes:
    expected_fields = {
        "uri", "version", "cipherSuite", "period", "certificateId", "chainIndex",
        "pulseIndex", "timeStamp", "localRandomValue", "external", "listValues",
        "precommitmentValue", "statusCode", "signatureValue", "outputValue",
    }
    if not isinstance(pulse, dict) or set(pulse) != expected_fields:
        raise BeaconVerificationError("NIST pulse fields differ from Beacon 2.0")
    if expected_version not in {
        PRODUCTION_PULSE_VERSION,
        HISTORICAL_FIXTURE_PULSE_VERSION,
    }:
        raise BeaconVerificationError("unregistered NIST pulse version profile")
    if (
        pulse["version"] != expected_version
        or pulse["cipherSuite"] != PULSE_CIPHER_SUITE
        or pulse["period"] != PULSE_PERIOD_MILLISECONDS
    ):
        raise BeaconVerificationError("NIST version/cipherSuite/period differs")
    parsed_uri = urlsplit(pulse["uri"] if isinstance(pulse["uri"], str) else "")
    expected_path = f"/beacon/2.0/chain/{pulse['chainIndex']}/pulse/{pulse['pulseIndex']}"
    if (
        parsed_uri.scheme != "https"
        or parsed_uri.hostname != "beacon.nist.gov"
        or parsed_uri.port not in (None, 443)
        or parsed_uri.username is not None
        or parsed_uri.password is not None
        or parsed_uri.path != expected_path
        or parsed_uri.query
        or parsed_uri.fragment
    ):
        raise BeaconVerificationError("NIST pulse URI differs from its chain/index")
    _parse_pulse_timestamp(pulse["timeStamp"])
    certificate_id = _hex64(pulse["certificateId"], label="certificateId")
    local_random = _hex64(pulse["localRandomValue"], label="localRandomValue")
    external = pulse["external"]
    if not isinstance(external, dict) or set(external) != {"sourceId", "statusCode", "value"}:
        raise BeaconVerificationError("NIST external fields differ")
    source_id = _hex64(external["sourceId"], label="external.sourceId")
    external_value = _hex64(external["value"], label="external.value")
    list_values = pulse["listValues"]
    expected_types = ("previous", "hour", "day", "month", "year")
    if not isinstance(list_values, list) or len(list_values) != len(expected_types):
        raise BeaconVerificationError("NIST listValues count differs")
    encoded_list: list[bytes] = []
    for item, expected_type in zip(list_values, expected_types):
        if not isinstance(item, dict) or set(item) != {"uri", "type", "value"}:
            raise BeaconVerificationError("NIST listValue fields differ")
        if item["type"] != expected_type or (item["uri"] is not None and not isinstance(item["uri"], str)):
            raise BeaconVerificationError("NIST listValue order/type differs")
        encoded_list.append(
            _length_prefixed(_hex64(item["value"], label=f"listValue.{expected_type}"))
        )
    precommitment = _hex64(pulse["precommitmentValue"], label="precommitmentValue")
    return b"".join(
        (
            _string(pulse["uri"], label="uri"),
            _string(pulse["version"], label="version"),
            _u32(pulse["cipherSuite"], label="cipherSuite"),
            _u32(pulse["period"], label="period"),
            _length_prefixed(certificate_id),
            _u64(pulse["chainIndex"], label="chainIndex"),
            _u64(pulse["pulseIndex"], label="pulseIndex"),
            _string(pulse["timeStamp"], label="timeStamp"),
            _length_prefixed(local_random),
            _length_prefixed(source_id),
            _u32(external["statusCode"], label="external.statusCode"),
            _length_prefixed(external_value),
            *encoded_list,
            _length_prefixed(precommitment),
            _u32(pulse["statusCode"], label="statusCode"),
        )
    )


def verify_nist_pulse_response(
    *,
    response: ArchivedHTTPResponse,
    trust_bundle: OfflineTrustBundle,
    expected_unix_milliseconds: int = TARGET_UNIX_MILLISECONDS,
    allow_fixture: bool = False,
) -> dict[str, Any]:
    if type(expected_unix_milliseconds) is not int or expected_unix_milliseconds < 0:
        raise BeaconVerificationError("expected NIST milliseconds are invalid")
    expected_endpoint = (
        "https://beacon.nist.gov/beacon/2.0/pulse/time/"
        + str(expected_unix_milliseconds)
    )
    try:
        _validate_response(response, expected_uri=expected_endpoint)
    except SnapshotError as error:
        raise BeaconVerificationError(f"invalid archived NIST response: {error}") from error
    expected_time = datetime.fromtimestamp(
        expected_unix_milliseconds // 1000, tz=timezone.utc
    ) + timedelta(milliseconds=expected_unix_milliseconds % 1000)
    expected_timestamp = expected_time.strftime("%Y-%m-%dT%H:%M:%S.") + f"{expected_unix_milliseconds % 1000:03d}Z"
    try:
        server_date = response_date(response)
    except SnapshotError as error:
        raise BeaconVerificationError(f"invalid archived NIST Date: {error}") from error
    if server_date < expected_time:
        raise BeaconVerificationError("NIST HTTP Date precedes the requested pulse time")
    value = load_json_strict_bytes(response.body, label="NIST Beacon pulse")
    if not isinstance(value, dict) or set(value) != {"pulse"} or not isinstance(value["pulse"], dict):
        raise BeaconVerificationError("NIST response must contain exactly one pulse")
    pulse = value["pulse"]
    if trust_bundle.fixture_only and not allow_fixture:
        raise BeaconVerificationError("fixture NIST trust bundle is forbidden")
    fixture_profile = trust_bundle.fixture_only and allow_fixture
    unsigned = serialize_unsigned_pulse(
        pulse,
        expected_version=(
            HISTORICAL_FIXTURE_PULSE_VERSION
            if fixture_profile
            else PRODUCTION_PULSE_VERSION
        ),
    )
    if pulse["statusCode"] != 0 and not (
        fixture_profile and pulse["statusCode"] == 1
    ):
        raise BeaconVerificationError("NIST pulse statusCode is not zero/normal")
    pulse_time = _parse_pulse_timestamp(pulse["timeStamp"])
    if pulse["timeStamp"] != expected_timestamp or pulse_time != expected_time:
        raise BeaconVerificationError("NIST endpoint returned a non-exact/nearest pulse")
    certificate_id = pulse["certificateId"].lower()
    record = trust_bundle.records.get(certificate_id)
    if record is None:
        raise BeaconVerificationError("NIST certificate is absent from the frozen bundle")
    if not record.chain_verified and not allow_fixture:
        raise BeaconVerificationError("NIST certificate chain was not verified offline")
    if not (record.leaf.not_before <= pulse_time <= record.leaf.not_after):
        raise BeaconVerificationError("NIST signing certificate is invalid at pulse time")
    _verify_leaf_policy(record.leaf)
    signature_value = pulse["signatureValue"]
    if (
        not isinstance(signature_value, str)
        or len(signature_value) > 8192
        or HEX_SIGNATURE.fullmatch(signature_value) is None
    ):
        raise BeaconVerificationError("NIST signatureValue is invalid")
    signature = bytes.fromhex(signature_value)
    digest = hashlib.sha512(unsigned).digest()
    _rsa_pkcs1_verify_digest(
        record.leaf.public_key, signature, digest, PULSE_DIGEST_INFO_PREFIX
    )
    computed_output = hashlib.sha512(unsigned + signature).hexdigest()
    output = _hex64(pulse["outputValue"], label="outputValue")
    if not hmac.compare_digest(computed_output, output.hex()):
        raise BeaconVerificationError("NIST outputValue construction differs")
    return {
        "schemaVersion": VERIFY_SCHEMA,
        "status": "VERIFIED_KNOWN_ANSWER_FIXTURE" if trust_bundle.fixture_only else "VERIFIED_FROZEN_NIST_PULSE",
        "countsTowardScientificVerdict": not trust_bundle.fixture_only,
        "requestURI": response.request_uri,
        "responseDate": server_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "responseHeadersSHA256": sha256_bytes(response.header_bytes),
        "responseBodyBytes": len(response.body),
        "responseBodySHA256": sha256_bytes(response.body),
        "expectedUnixMilliseconds": expected_unix_milliseconds,
        "pulseURI": pulse["uri"],
        "timeStamp": pulse["timeStamp"],
        "pulseVersion": pulse["version"],
        "cipherSuite": pulse["cipherSuite"],
        "periodMilliseconds": pulse["period"],
        "certificateId": certificate_id,
        "certificateChainVerified": record.chain_verified,
        "trustBundleManifestSHA256": trust_bundle.manifest_sha256,
        "signedBytesSHA512": digest.hex(),
        "outputValue": output.hex().upper(),
        "signatureVerified": True,
        "outputConstructionVerified": True,
        "exactTimestampVerified": True,
        "responseDateNotBeforePulseVerified": True,
    }


def canonical_verification_bytes(value: Mapping[str, Any]) -> bytes:
    fields = {
        "schemaVersion", "status", "countsTowardScientificVerdict", "requestURI",
        "responseDate", "responseHeadersSHA256", "responseBodyBytes",
        "responseBodySHA256", "expectedUnixMilliseconds", "pulseURI", "timeStamp",
        "pulseVersion", "cipherSuite", "periodMilliseconds",
        "certificateId", "certificateChainVerified", "trustBundleManifestSHA256",
        "signedBytesSHA512", "outputValue", "signatureVerified",
        "outputConstructionVerified", "exactTimestampVerified",
        "responseDateNotBeforePulseVerified",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise BeaconVerificationError("NIST verification record fields differ")
    if value["schemaVersion"] != VERIFY_SCHEMA:
        raise BeaconVerificationError("unexpected NIST verification record")
    fixture = value["status"] == "VERIFIED_KNOWN_ANSWER_FIXTURE"
    if value["status"] not in {
        "VERIFIED_KNOWN_ANSWER_FIXTURE", "VERIFIED_FROZEN_NIST_PULSE"
    }:
        raise BeaconVerificationError("NIST verification status differs")
    expected_version = (
        HISTORICAL_FIXTURE_PULSE_VERSION if fixture else PRODUCTION_PULSE_VERSION
    )
    if (
        value["pulseVersion"] != expected_version
        or value["cipherSuite"] != PULSE_CIPHER_SUITE
        or value["periodMilliseconds"] != PULSE_PERIOD_MILLISECONDS
    ):
        raise BeaconVerificationError("NIST verification pulse profile differs")
    if (
        value["countsTowardScientificVerdict"] is not (not fixture)
        or value["certificateChainVerified"] is not (not fixture)
        or any(
            value[field] is not True
            for field in (
                "signatureVerified", "outputConstructionVerified",
                "exactTimestampVerified", "responseDateNotBeforePulseVerified",
            )
        )
    ):
        raise BeaconVerificationError("NIST verification truth flags differ")
    milliseconds = value["expectedUnixMilliseconds"]
    if type(milliseconds) is not int or milliseconds < 0:
        raise BeaconVerificationError("NIST verification milliseconds are invalid")
    expected_request = (
        "https://beacon.nist.gov/beacon/2.0/pulse/time/" + str(milliseconds)
    )
    expected_time = datetime.fromtimestamp(
        milliseconds // 1000, tz=timezone.utc
    ) + timedelta(milliseconds=milliseconds % 1000)
    expected_timestamp = expected_time.strftime("%Y-%m-%dT%H:%M:%S.") + f"{milliseconds % 1000:03d}Z"
    if value["requestURI"] != expected_request or value["timeStamp"] != expected_timestamp:
        raise BeaconVerificationError("NIST verification request/timestamp differs")
    if type(value["responseBodyBytes"]) is not int or value["responseBodyBytes"] < 0:
        raise BeaconVerificationError("NIST verification body byte count is invalid")
    for field in (
        "responseHeadersSHA256", "responseBodySHA256", "trustBundleManifestSHA256"
    ):
        if not isinstance(value[field], str) or HEX_SHA256.fullmatch(value[field]) is None:
            raise BeaconVerificationError("NIST verification SHA-256 field is invalid")
    for field in ("certificateId", "signedBytesSHA512"):
        if not isinstance(value[field], str) or re.fullmatch(r"[0-9a-f]{128}", value[field]) is None:
            raise BeaconVerificationError("NIST verification SHA-512 field is invalid")
    if not isinstance(value["outputValue"], str) or re.fullmatch(r"[0-9A-F]{128}", value["outputValue"]) is None:
        raise BeaconVerificationError("NIST verification outputValue is invalid")
    if not isinstance(value["pulseURI"], str) or not isinstance(value["responseDate"], str):
        raise BeaconVerificationError("NIST verification URI/Date field is invalid")
    return canonical_json_bytes(dict(value))


def verify_archived_nist_pulse(
    *,
    root: Path,
    archive: Mapping[str, Any],
    trust_bundle: OfflineTrustBundle,
    expected_unix_milliseconds: int = TARGET_UNIX_MILLISECONDS,
    allow_fixture: bool = False,
) -> dict[str, Any]:
    """Load exact committed HTTP bytes and run the fail-closed verifier."""

    if not isinstance(archive, dict) or set(archive) != {
        "requestURI", "serverDate", "requestURIFile", "responseHeaders",
        "responseBody",
    }:
        raise BeaconVerificationError("archived NIST response fields differ")
    if type(expected_unix_milliseconds) is not int or expected_unix_milliseconds < 0:
        raise BeaconVerificationError("expected NIST milliseconds are invalid")
    expected_endpoint = (
        "https://beacon.nist.gov/beacon/2.0/pulse/time/"
        + str(expected_unix_milliseconds)
    )
    try:
        response = load_archived_response(
            root, archive, expected_uri=expected_endpoint
        )
    except SnapshotError as error:
        raise BeaconVerificationError(
            f"invalid committed NIST response: {error}"
        ) from error
    return verify_nist_pulse_response(
        response=response,
        trust_bundle=trust_bundle,
        expected_unix_milliseconds=expected_unix_milliseconds,
        allow_fixture=allow_fixture,
    )


__all__ = [
    "BeaconVerificationError",
    "HISTORICAL_FIXTURE_PULSE_VERSION",
    "OfflineTrustBundle",
    "PRODUCTION_PULSE_VERSION",
    "PULSE_CIPHER_SUITE",
    "PULSE_PERIOD_MILLISECONDS",
    "TARGET_ENDPOINT",
    "TARGET_TIMESTAMP",
    "TARGET_UNIX_MILLISECONDS",
    "TRUST_ACCEPTED_LEAF_EXTENDED_KEY_USAGES",
    "TRUST_CANDIDATE_STATUS",
    "TRUST_FIXTURE_STATUS",
    "TRUST_FROZEN_STATUS",
    "TRUST_REVOCATION_POLICY",
    "TRUST_REVOCATION_RESIDUAL_RISK",
    "TRUST_ROTATION_POLICY",
    "TRUST_SCHEMA",
    "TrustRecord",
    "VERIFY_SCHEMA",
    "canonical_verification_bytes",
    "load_offline_trust_bundle",
    "NIST_TRUST_ROOT_DER_SHA256",
    "parse_certificate_der",
    "serialize_unsigned_pulse",
    "verify_archived_nist_pulse",
    "verify_nist_pulse_response",
]

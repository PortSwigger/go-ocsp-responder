"""Ask the responder about each test certificate and verify every answer.

For each answer this checks the OCSP status, that the response is signed by
the responder certificate, that the responder certificate was issued by the
test CA for OCSP signing, and that its key is the KMS key, so the signature
must have come through aws_kms_pkcs11.so.
"""

import base64
import sys
import time
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

URL = "http://responder:8080"
WORK = "/work"
STARTUP_TIMEOUT = 600


def load(name):
    with open(f"{WORK}/{name}", "rb") as f:
        return f.read()


def wait_for_responder():
    deadline = time.time() + STARTUP_TIMEOUT
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{URL}/healthcheck", timeout=5) as r:
                if r.status == 200:
                    return
        except OSError:
            pass
        time.sleep(3)
    sys.exit(f"FAIL: responder did not answer /healthcheck within {STARTUP_TIMEOUT}s")


def ask(cert, issuer, algorithm, method):
    der = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(cert, issuer, algorithm)
        .build()
        .public_bytes(serialization.Encoding.DER)
    )
    if method == "GET":
        req = urllib.request.Request(f"{URL}/{base64.b64encode(der).decode()}")
    else:
        req = urllib.request.Request(
            URL, data=der, headers={"Content-Type": "application/ocsp-request"}
        )
    with urllib.request.urlopen(req, timeout=60) as r:
        return ocsp.load_der_ocsp_response(r.read())


def verify(resp, cert, ca, kms_public, expected):
    problems = []
    if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return [f"response status {resp.response_status}"]
    if resp.certificate_status != expected:
        problems.append(f"status {resp.certificate_status.name}, expected {expected.name}")
    if resp.serial_number != cert.serial_number:
        problems.append("serial number mismatch")
    if expected == ocsp.OCSPCertStatus.REVOKED and resp.revocation_time_utc is None:
        problems.append("revoked answer without a revocation time")
    if resp.next_update_utc is None:
        problems.append("no nextUpdate")

    if not resp.certificates:
        return problems + ["no responder certificate in response"]
    signer = resp.certificates[0]
    try:
        signer.public_key().verify(
            resp.signature,
            resp.tbs_response_bytes,
            padding.PKCS1v15(),
            resp.signature_hash_algorithm,
        )
    except Exception as e:  # noqa: BLE001
        problems.append(f"response signature does not verify: {e}")
    try:
        ca.public_key().verify(
            signer.signature,
            signer.tbs_certificate_bytes,
            padding.PKCS1v15(),
            signer.signature_hash_algorithm,
        )
    except Exception as e:  # noqa: BLE001
        problems.append(f"responder certificate not issued by the test CA: {e}")
    eku = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    if ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
        problems.append("responder certificate lacks OCSP signing EKU")
    if signer.public_key().public_numbers() != kms_public.public_numbers():
        problems.append("responder key is not the KMS key")
    return problems


def main():
    wait_for_responder()
    ca = x509.load_pem_x509_certificate(load("ca.pem"))
    kms_public = serialization.load_pem_public_key(load("kms-public.pem"))
    # The "unknown" leaf is issued by the test CA but has no certsquirt record.
    # Existing behaviour is to answer GOOD for it, because main.go leaves the
    # status at its zero value (ocsp.Good) when the lookup finds nothing. This
    # test checks the image for unchanged behaviour, so it asserts what the
    # responder does today; answering UNKNOWN instead is a separate fix.
    cases = [
        ("good", ocsp.OCSPCertStatus.GOOD, hashes.SHA1(), "POST"),
        ("good", ocsp.OCSPCertStatus.GOOD, hashes.SHA256(), "GET"),
        ("revoked", ocsp.OCSPCertStatus.REVOKED, hashes.SHA1(), "POST"),
        ("unknown", ocsp.OCSPCertStatus.GOOD, hashes.SHA1(), "POST"),
    ]
    failed = False
    for label, expected, algorithm, method in cases:
        cert = x509.load_pem_x509_certificate(load(f"leaf-{label}.pem"))
        try:
            problems = verify(ask(cert, ca, algorithm, method), cert, ca, kms_public, expected)
        except Exception as e:  # noqa: BLE001
            problems = [f"request failed: {e}"]
        result = "PASS" if not problems else "FAIL"
        failed |= bool(problems)
        detail = "; ".join(problems) if problems else f"{expected.name}, signature verified"
        print(f"{result}: {label:8} {method:4} {algorithm.name:6} {detail}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

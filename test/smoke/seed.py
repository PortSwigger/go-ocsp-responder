"""Seed moto and write throwaway certificates for the OCSP smoke test.

Creates, all for one test run only:
  * a TLS CA and server certificate for the AWS hostnames nginx answers on
  * an OCSP test CA and a delegated OCSP responder certificate for the fake
    KMS signing key (RSA 4096, as in production)
  * good, revoked and unknown leaf certificates
  * the SSM parameters startup.sh reads and the DynamoDB records the
    responder looks up
"""

import datetime
import json
import time

import boto3
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REGION = "eu-west-1"
WORK = "/work"
TABLE = "certsquirt-smoke"
TOKEN_LABEL = "ocsp-smoke"
NOW = datetime.datetime.now(datetime.timezone.utc)


def client(service):
    return boto3.client(
        service,
        region_name=REGION,
        endpoint_url="http://moto:5000",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def write(name, data):
    with open(f"{WORK}/{name}", "w") as f:
        f.write(data)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def ca_cert(cn, key):
    return (
        x509.CertificateBuilder()
        .subject_name(name(cn))
        .issuer_name(name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )


def issue(ca, ca_key, cn, public_key, extensions=()):
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(cn))
        .issuer_name(ca.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    for ext, critical in extensions:
        builder = builder.add_extension(ext, critical=critical)
    return builder.sign(ca_key, hashes.SHA256())


# TLS front end for ssm, kms and dynamodb on their real hostnames.
tls_ca_key = new_key()
tls_ca = ca_cert("OCSP smoke test TLS CA", tls_ca_key)
tls_key = new_key()
hosts = [f"{svc}.{REGION}.amazonaws.com" for svc in ("ssm", "kms", "dynamodb")]
tls_cert = issue(
    tls_ca,
    tls_ca_key,
    hosts[0],
    tls_key.public_key(),
    [
        (x509.SubjectAlternativeName([x509.DNSName(h) for h in hosts]), False),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False),
    ],
)
write("tls-ca.pem", pem(tls_ca))
write("tls.crt", pem(tls_cert))
write(
    "tls.key",
    tls_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode(),
)

# OCSP test CA and the KMS backed responder key.
ca_key = new_key()
ca = ca_cert("OCSP smoke test CA", ca_key)

kms = boto3.client(
    "kms",
    region_name=REGION,
    endpoint_url="http://kms-fake:8000",
    aws_access_key_id="testing",
    aws_secret_access_key="testing",
)
for _ in range(60):  # the fake generates its RSA 4096 key at start up
    try:
        key_id = kms.list_keys()["Keys"][0]["KeyId"]
        break
    except Exception:  # noqa: BLE001
        time.sleep(2)
else:
    raise SystemExit("fake KMS did not start")
kms_public_der = kms.get_public_key(KeyId=key_id)["PublicKey"]
kms_public = serialization.load_der_public_key(kms_public_der)
kms_public_pem = kms_public.public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

responder = issue(
    ca,
    ca_key,
    "ocsp.smoke.test",
    kms_public,
    [
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), False),
        (
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            True,
        ),
        (x509.OCSPNoCheck(), False),
    ],
)

leaves = {}
for label in ("good", "revoked", "unknown"):
    leaves[label] = issue(ca, ca_key, f"{label}.smoke.test", new_key().public_key())
    write(f"leaf-{label}.pem", pem(leaves[label]))
write("ca.pem", pem(ca))
write("responder.pem", pem(responder))
write("kms-public.pem", kms_public_pem)

# SSM parameters, in the same shape startup.sh expects in production.
ssm = client("ssm")
params = {
    "ocsp-test-aws-kms-config": json.dumps(
        {"slots": [{"label": TOKEN_LABEL, "kms_key_id": key_id, "aws_region": REGION}]}
    ),
    "ocsp-test-pkcs11-config": json.dumps(
        {"Path": "/usr/local/lib/aws_kms_pkcs11.so", "TokenLabel": TOKEN_LABEL, "Pin": "unused"}
    ),
    "ocsp-test-publickey": kms_public_pem,
    "ocsp-test-ca-certificate": pem(ca),
    "ocsp-test-certificate": pem(responder),
}
for param, value in params.items():
    ssm.put_parameter(Name=param, Value=value, Type="String", Overwrite=True)

# certsquirt style records. The unknown leaf is deliberately absent.
ddb = client("dynamodb")
ddb.create_table(
    TableName=TABLE,
    AttributeDefinitions=[{"AttributeName": "SerialNumber", "AttributeType": "S"}],
    KeySchema=[{"AttributeName": "SerialNumber", "KeyType": "HASH"}],
    BillingMode="PAY_PER_REQUEST",
)
for label, status in (("good", "V"), ("revoked", "R")):
    cert = leaves[label]
    item = {
        "SerialNumber": {"S": str(cert.serial_number)},
        "Status": {"S": status},
        "Subject": {"S": cert.subject.rfc4514_string()},
        "NotBefore": {"S": cert.not_valid_before_utc.isoformat().replace("+00:00", "Z")},
        "NotAfter": {"S": cert.not_valid_after_utc.isoformat().replace("+00:00", "Z")},
    }
    if status == "R":
        item["RevokedOn"] = {"S": NOW.replace(microsecond=0).isoformat().replace("+00:00", "Z")}
    ddb.put_item(TableName=TABLE, Item=item)

print(f"seeded KMS key {key_id}, {len(params)} SSM parameters and 2 DynamoDB records")

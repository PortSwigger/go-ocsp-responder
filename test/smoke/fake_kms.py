"""Minimal AWS KMS fake for the OCSP smoke test.

moto does not implement Sign with MessageType=DIGEST, which is the only way
aws_kms_pkcs11.so calls KMS, so this serves the handful of KMS operations the
module uses with real KMS semantics. One RSA 4096 SIGN_VERIFY key, generated at
start up and discarded on exit.
"""

import base64
import json
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

REGION = "eu-west-1"
ACCOUNT = "000000000000"
KEY_ID = str(uuid.uuid4())
KEY_ARN = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/{KEY_ID}"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=4096)
PUBLIC_DER = KEY.public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
)
ALGORITHMS = {
    "RSASSA_PKCS1_V1_5_SHA_256": (padding.PKCS1v15(), hashes.SHA256()),
    "RSASSA_PKCS1_V1_5_SHA_384": (padding.PKCS1v15(), hashes.SHA384()),
    "RSASSA_PKCS1_V1_5_SHA_512": (padding.PKCS1v15(), hashes.SHA512()),
}
METADATA = {
    "AWSAccountId": ACCOUNT,
    "KeyId": KEY_ID,
    "Arn": KEY_ARN,
    "Enabled": True,
    "KeyState": "Enabled",
    "KeyUsage": "SIGN_VERIFY",
    "KeySpec": "RSA_4096",
    "CustomerMasterKeySpec": "RSA_4096",
    "SigningAlgorithms": list(ALGORITHMS),
    "Origin": "AWS_KMS",
    "KeyManager": "CUSTOMER",
}


class ClientError(Exception):
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


def check_key(body):
    if body.get("KeyId") not in (KEY_ID, KEY_ARN):
        raise ClientError("NotFoundException", f"Key {body.get('KeyId')} not found")


def get_public_key(body):
    check_key(body)
    return {
        "KeyId": KEY_ARN,
        "PublicKey": base64.b64encode(PUBLIC_DER).decode(),
        "KeySpec": "RSA_4096",
        "CustomerMasterKeySpec": "RSA_4096",
        "KeyUsage": "SIGN_VERIFY",
        "SigningAlgorithms": list(ALGORITHMS),
    }


def sign(body):
    check_key(body)
    algorithm = body.get("SigningAlgorithm")
    if algorithm not in ALGORITHMS:
        raise ClientError("InvalidKeyUsageException", f"unsupported algorithm {algorithm}")
    pad, digest = ALGORITHMS[algorithm]
    message = base64.b64decode(body["Message"])
    message_type = body.get("MessageType", "RAW")
    if message_type == "DIGEST":
        if len(message) != digest.digest_size:
            raise ClientError("ValidationException", "digest length does not match algorithm")
        signature = KEY.sign(message, pad, utils.Prehashed(digest))
    else:
        signature = KEY.sign(message, pad, digest)
    print(f"Sign MessageType={message_type} SigningAlgorithm={algorithm}", flush=True)
    return {"KeyId": KEY_ARN, "Signature": base64.b64encode(signature).decode(), "SigningAlgorithm": algorithm}


OPERATIONS = {
    "GetPublicKey": get_public_key,
    "Sign": sign,
    "DescribeKey": lambda body: (check_key(body), {"KeyMetadata": METADATA})[1],
    "ListKeys": lambda body: {"Keys": [{"KeyId": KEY_ID, "KeyArn": KEY_ARN}], "Truncated": False},
}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        target = self.headers.get("X-Amz-Target", "")
        operation = target.split(".")[-1]
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        try:
            if operation not in OPERATIONS:
                raise ClientError("UnsupportedOperationException", f"{operation} not implemented")
            status, payload = 200, OPERATIONS[operation](body)
        except ClientError as e:
            status, payload = 400, {"__type": e.kind, "message": str(e)}
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/x-amz-json-1.1")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        print(f"{self.headers.get('X-Amz-Target', '-')} {fmt % args}", flush=True)


if __name__ == "__main__":
    print(f"fake KMS ready with key {KEY_ID}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()

#!/usr/bin/env bash
# End to end smoke test for a go-ocsp-responder image.
#
# Runs the image's real entrypoint (startup.sh) against moto, a local fake of
# SSM, KMS and DynamoDB. moto is reached over HTTPS on the real AWS hostnames
# through an nginx TLS front end, so nothing in the image is pointed at a
# different endpoint. That exercises the AWS CLI, gencsr, aws_kms_pkcs11.so with
# its libcurl and OpenSSL, crypto11, the DynamoDB lookup and the OCSP signing
# path, then checks a good, a revoked and an unknown certificate.
#
# Nothing here talks to AWS. Every key, certificate and record is generated for
# the run and discarded afterwards.
#
# Usage: test/smoke/run.sh <image>

set -euo pipefail

IMAGE="${1:?usage: $0 <image>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
RUN_ID="ocsp-smoke-$$"
WORK="$(mktemp -d)"
REGION=eu-west-1

MOTO_IMAGE=motoserver/moto:5.2.5@sha256:59a1965d845249b04def37a0e2565f9cc6c44543cb89b68e90f28f344b3b0d1a
NGINX_IMAGE=nginx:1.31.8-alpine@sha256:713fc2ebfd92e8217db451477182ee91944b123d2b1ee9fd5a8c6e91ca6c3a11
PYTHON_IMAGE=python:3.13.18-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72

cleanup() {
  docker rm -f "$RUN_ID-moto" "$RUN_ID-kms" "$RUN_ID-tls" "$RUN_ID-responder" >/dev/null 2>&1 || true
  docker network rm "$RUN_ID" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# The harness scripts are copied into the work directory so only a temp
# directory is bind mounted (Docker Desktop may not share the checkout path).
mkdir -p "$WORK/harness"
cp "$HERE/seed.py" "$HERE/check.py" "$HERE/fake_kms.py" "$WORK/harness/"

py() {
  docker run --rm --network "$RUN_ID" -v "$WORK":/work \
    -e PYTHONPATH=/work/pydeps "$PYTHON_IMAGE" python -P "$@"
}

echo "== image under test: $IMAGE"
docker network create "$RUN_ID" >/dev/null
docker run -d --name "$RUN_ID-moto" --network "$RUN_ID" --network-alias moto "$MOTO_IMAGE" >/dev/null

echo "== installing harness dependencies"
docker run --rm -v "$WORK":/work "$PYTHON_IMAGE" \
  pip install --quiet --disable-pip-version-check --root-user-action=ignore --target /work/pydeps \
  boto3==1.43.126 cryptography==50.0.2

# moto stands in for SSM and DynamoDB. KMS is a small local fake because moto
# does not implement Sign with MessageType=DIGEST, which the module relies on.
docker run -d --name "$RUN_ID-kms" --network "$RUN_ID" --network-alias kms-fake -v "$WORK":/work \
  -e PYTHONPATH=/work/pydeps "$PYTHON_IMAGE" python -P /work/harness/fake_kms.py >/dev/null

echo "== seeding test PKI, KMS key, SSM parameters and DynamoDB records"
py /work/harness/seed.py

# Trust the test TLS CA through the image's own system bundle, which is the
# file the AWS CLI, Go and the module's libcurl all read.
docker run --rm --platform linux/amd64 --entrypoint cat "$IMAGE" /etc/ssl/certs/ca-certificates.crt > "$WORK/ca-certificates.crt"
cat "$WORK/tls-ca.pem" >> "$WORK/ca-certificates.crt"

cat > "$WORK/nginx.conf" <<'EOF'
events {}
http {
  ssl_certificate     /work/tls.crt;
  ssl_certificate_key /work/tls.key;
  server {
    listen 443 ssl default_server;
    location / {
      proxy_pass http://moto:5000;
      proxy_set_header Host $host;
      proxy_http_version 1.1;
    }
  }
  server {
    listen 443 ssl;
    server_name kms.eu-west-1.amazonaws.com;
    location / {
      proxy_pass http://kms-fake:8000;
      proxy_set_header Host $host;
      proxy_http_version 1.1;
    }
  }
}
EOF
docker run -d --name "$RUN_ID-tls" --network "$RUN_ID" \
  --network-alias "ssm.$REGION.amazonaws.com" \
  --network-alias "kms.$REGION.amazonaws.com" \
  --network-alias "dynamodb.$REGION.amazonaws.com" \
  -v "$WORK":/work:ro -v "$WORK/nginx.conf":/etc/nginx/nginx.conf:ro "$NGINX_IMAGE" >/dev/null

echo "== starting responder (real entrypoint)"
# Same environment as the ECS task definitions, with throwaway values.
docker run -d --name "$RUN_ID-responder" --platform linux/amd64 --network "$RUN_ID" --network-alias responder \
  --tmpfs /depot \
  -v "$WORK/ca-certificates.crt":/etc/ssl/certs/ca-certificates.crt:ro \
  -e AWS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
  -e AWS_ACCESS_KEY_ID=testing -e AWS_SECRET_ACCESS_KEY=testing \
  -e AWS_REGION="$REGION" \
  -e SM_PKCS11_CONF=ocsp-test-pkcs11-config \
  -e SM_KMS_CONFIG=ocsp-test-aws-kms-config \
  -e SM_PUBKEY=ocsp-test-publickey \
  -e SM_CA_CERTFILE=ocsp-test-ca-certificate \
  -e SM_RESPONSE_CERTFILE=ocsp-test-certificate \
  -e DEPOT=/depot -e REGION="$REGION" -e PORT=8080 -e ENDPOINT=ocsp.smoke.test \
  -e AWS_KMS_PKCS11_DEBUG=1 -e DB_TABLE_NAME=certsquirt-smoke \
  "$IMAGE" >/dev/null

echo "== checking OCSP answers"
status=0
py /work/harness/check.py || status=$?

docker logs "$RUN_ID-responder" > "$WORK/responder.log" 2>&1 || true
docker logs "$RUN_ID-kms" > "$WORK/kms.log" 2>&1 || true
# The module's own debug output goes to a block buffered stdout and is not
# reliably flushed, so count the Sign calls at the KMS end instead: one from
# gencsr, one from the responder's start up self test and one per OCSP answer.
signs=$(grep -c 'Sign MessageType=DIGEST SigningAlgorithm=RSASSA_PKCS1_V1_5_SHA_256' "$WORK/kms.log" || true)
if [ "$signs" -ge 6 ]; then
  echo "PASS: aws_kms_pkcs11.so made $signs KMS Sign calls over TLS"
else
  echo "FAIL: expected at least 6 KMS Sign calls from aws_kms_pkcs11.so, saw $signs"
  status=1
fi
csr_lines=$(awk '/BEGIN CERTIFICATE REQUEST/{f=1;next} /END CERTIFICATE REQUEST/{f=0} f' "$WORK/responder.log" | wc -l)
if [ "$csr_lines" -gt 0 ]; then
  echo "PASS: gencsr produced a CSR signed through the module"
else
  echo "FAIL: gencsr produced an empty CSR"
  status=1
fi
if [ "$status" -ne 0 ]; then
  echo "== responder log"
  cat "$WORK/responder.log"
fi
exit "$status"

Changed to support reading records from a certsquirt DynamoDB table, and to use KMS keys via PKCS11.

If you're interested in using this, raise an issue and we will add some documentation / guidance :-)

## Building

The Dockerfile builds everything from pinned sources, including the AWS SDK for C++ and the aws-kms-pkcs11 module, so a local build matches CI:

```
docker buildx build --platform linux/amd64 --load -t go-ocsp-responder:local .
```

## Smoke test

`test/smoke/run.sh` starts the image with its real entrypoint against local fakes of SSM, KMS and DynamoDB, then checks signed OCSP answers for good, revoked and unknown test certificates. It needs only Docker and talks to nothing outside the machine.

```
test/smoke/run.sh go-ocsp-responder:local
```

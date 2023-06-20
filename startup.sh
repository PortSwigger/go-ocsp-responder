#!/bin/bash

PKCS11CONF=${DEPOT}/pkcs11-config.json
PUBKEY=${DEPOT/}/servicekey.pub
#REGION=eu-west-1
# things that should exist in parameter store manager and be available to us via env variables
#SM_PKCS11_CONF=""     # an ARN of the config used by scepserver -pkcs11-config argument
#SM_KMS_CONFIG=""      # an ARN of the config file used by the pkcs11 shim to be stored in /etc/aws-kms-pkcs11/config.json

# takes secret arn, secret name. returns just the secret.
getsecretvalue() {
        aws ssm get-parameter --name $1 --with-decryption |  jq --raw-output '.Parameter.Value'
}

# takes secretarn, filename to write contents to
getsecretblob() {
        aws ssm get-parameter --name $1 --region=${REGION} | jq --raw-output '.Parameter.Value' > $2
        echo grabbing $1 saving to $2
}

# First up, check to see if our pkcs11 config file exists, and grab it if not.
if [ ! -f ${PKCS11CONF} ]; then
        getsecretblob ${SM_PKCS11_CONF} ${PKCS11CONF}
fi

# next, we need to grab our aws-kms-pkcs11 config.
# this test is redundant but makes it look pretty :-)
if [ ! -f /etc/aws-kms-pkcs11/config.json ]; then
        mkdir -p /etc/aws-kms-pkcs11/
        getsecretblob ${SM_KMS_CONFIG} /etc/aws-kms-pkcs11/config.json
fi

if [ ! -f ${PUBKEY} ]; then
        getsecretblob ${SM_PUBKEY} ${PUBKEY}
fi

# generate a CSR bassed on our key and name
/usr/bin/gencsr -fqdn ${ENDPOINT} -config ${PKCS11CONF} -pubkey ${PUBKEY}
# we should be able to start now.
echo "attempting to start server"
/usr/bin/go-ocsp-responder -stdout -port ${PORT} -cacert ${CACERT} -p11conf ${PKCS11CONF}
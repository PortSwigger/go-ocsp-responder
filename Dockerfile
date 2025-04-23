FROM ubuntu:latest

# Install aws kms dependencies
RUN apt update && apt install --no-install-recommends -y libjson-c5 jq

# Install dependencies
RUN apt-get update && \
    apt-get install -y curl unzip less groff jq python3 libjson-c5 && \
    apt-get clean

# aws clie isn't in apt repo's anymore....
# Install AWS CLI v2
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip" && \
    unzip /tmp/awscliv2.zip -d /tmp && \
    /tmp/aws/install && \
    rm -rf /tmp/aws /tmp/awscliv2.zip

# Verify installation
RUN aws --version

### add required libs for pkcs11 provider
# ignore symlinks.
COPY vcpkg/installed/x64-linux-dynamic/lib/ /usr/local/lib/

# Install aws kms (depends on aws-sdk-cpp libs
COPY aws-kms-pkcs11/aws_kms_pkcs11.so /usr/local/lib/
# create required symlinks for above libs
RUN /usr/sbin/ldconfig

# Copy OCSP server images
COPY go-ocsp-responder/go-ocsp-responder /usr/bin/go-ocsp-responder
COPY go-ocsp-responder/gencsr/gencsr /usr/bin/gencsr
# Copy fake config so we can write to the filesystem.  FIXME hardcoded depot location.
RUN mkdir -p /etc/aws-kms-pkcs11/ && ln -s /depot/aws-kms-config.json /etc/aws-kms-pkcs11/config.json

# Add startup.sh
COPY go-ocsp-responder/startup.sh /startup.sh
RUN chmod 0755 /startup.sh
EXPOSE 8080

ENTRYPOINT ["/startup.sh"]

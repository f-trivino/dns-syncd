# You need a Red Hat subscription to build this container image.
# You can register your host by following this KCS: https://access.redhat.com/solutions/253273
#
# podman build -f Containerfile .

FROM registry.access.redhat.com/ubi9:9.2-755

ENV LC_ALL C.UTF-8

# Podmanfile for deploying ipa-tuura in production mode, using Apache HTTPS server
LABEL org.opencontainers.image.description="UBI9 RHEL based DNS Integrated Service"
LABEL org.opencontainers.image.source=https://github.com/f-trivino/dns-syncd

# Install system dependencies
RUN dnf -y update && dnf clean all
RUN dnf -y install bind-utils bind && dnf clean all

# copy cfg files:
ADD ./cfg_files/named.conf /etc/named/named.conf
RUN mkdir /root/scripts -p
ADD ./cfg_files/root/scripts/init.sh /root/scripts/init.sh
RUN chmod +x /root/scripts/init.sh

# init env
RUN /root/scripts/init.sh

# start services:
CMD /usr/sbin/named -u named -f

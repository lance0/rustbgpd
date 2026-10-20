# M126 lab image: the rustbgpd dev image plus the official FastNetMon
# Community binary package and tcpreplay.
#
# FastNetMon dials its GoBGP API at a hard-coded localhost:50051, so the
# detector, rustbgpd-gobgp-bridge and rustbgpd share one node, as FastNetMon
# and gobgpd do in a stock install.
#
# The vendor package is unpacked, not installed: its maintainer scripts start
# a systemd unit. Only /opt/fastnetmon-community is kept; the package's
# bundled gobgpd is never started.
#
#   docker build --build-arg BASE=rustbgpd:dev -t rustbgpd-fnm:m126 \
#       tests/interop/m126-fastnetmon-rtbh

ARG BASE=rustbgpd:dev
FROM ${BASE}

ARG FNM_VERSION=1.2.9
ARG FNM_URL=https://storage.googleapis.com/community_packages/1.2.9/debian/12/fastnetmon_1.2.9_amd64.deb
ARG FNM_SHA256=108585308b91b8478a06741dbae179164467cc5ca5e0e45143ac5ed70c032448

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl libnsl2 tcpreplay; \
    curl --fail --location --silent --show-error --connect-timeout 10 \
        --max-time 600 -o /tmp/fastnetmon.deb "${FNM_URL}"; \
    echo "${FNM_SHA256}  /tmp/fastnetmon.deb" | sha256sum -c -; \
    dpkg-deb --field /tmp/fastnetmon.deb Version | grep -qx "${FNM_VERSION}"; \
    dpkg-deb --fsys-tarfile /tmp/fastnetmon.deb | tar -x -C / ./opt/fastnetmon-community; \
    rm /tmp/fastnetmon.deb; \
    apt-get purge -y curl; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*; \
    /opt/fastnetmon-community/app/bin/fastnetmon --version

COPY fastnetmon.conf /etc/fastnetmon.conf
COPY networks_list /etc/networks_list
RUN touch /etc/networks_whitelist && mkdir -p /var/log/fastnetmon_attacks

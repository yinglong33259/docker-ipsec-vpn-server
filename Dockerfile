FROM debian:stretch
LABEL maintainer="nerv"

ENV REFRESHED_AT 2020-03-30
ENV SWAN_VER 3.29
ENV L2TP_VER 1.3.14

WORKDIR /opt/src

RUN apt-get -yqq update && apt-get -y install rsyslog curl\
    && apt-get -yqq --no-install-recommends install \
         wget dnsutils openssl ca-certificates kmod \
         iproute gawk grep sed net-tools iptables \
         bsdmainutils libcurl3-nss \
         libnss3-tools libevent-dev libcap-ng0 xl2tpd \
         libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
         libcap-ng-dev libcap-ng-utils libselinux1-dev \
         libcurl4-nss-dev libpcap0.8-dev \
         flex bison gcc make \
    && wget -t 3 -T 300 -O libreswan.tar.gz "https://github.com/libreswan/libreswan/archive/v${SWAN_VER}.tar.gz" \
    && tar xzf libreswan.tar.gz \
    && rm -f libreswan.tar.gz \
    && cd "libreswan-${SWAN_VER}" \
    && printf 'WERROR_CFLAGS =\nUSE_DNSSEC = false\nUSE_DH31 = false\n' > Makefile.inc.local \
    && printf 'USE_NSS_AVA_COPY = true\nUSE_NSS_IPSEC_PROFILE = false\n' >> Makefile.inc.local \
    && printf 'USE_GLIBC_KERN_FLIP_HEADERS = true\nUSE_SYSTEMD_WATCHDOG = false\n' >> Makefile.inc.local \
    && make -s base \
    && make -s install-base \
    && cd /opt/src \
    && rm -rf "/opt/src/libreswan-${SWAN_VER}" \
    && wget -t 3 -T 300  -O xl2tpd.tar.gz "https://github.com/xelerance/xl2tpd/archive/v${L2TP_VER}.tar.gz" \
    && tar xzf xl2tpd.tar.gz \
    && rm -f xl2tpd.tar.gz \
    && cd "xl2tpd-${L2TP_VER}" \
    && make -s \
    && PREFIX=/usr make -s install \
    && cd /opt/src \
    && rm -rf "/opt/src/xl2tpd-${L2TP_VER}" \
    && apt-get -yqq remove \
         libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
         libcap-ng-dev libcap-ng-utils libselinux1-dev \
         libcurl4-nss-dev libpcap0.8-dev flex bison gcc make \
         perl-modules perl \
    && apt-get -yqq autoremove \
    && apt-get -y clean \
    && rm -rf /var/lib/apt/lists/*

COPY ./run.sh /opt/src/run.sh
RUN chmod 755 /opt/src/run.sh

EXPOSE 500/udp 4500/udp 17/udp 1701/udp 

CMD ["/opt/src/run.sh"]

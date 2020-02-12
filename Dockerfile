FROM centos:7
LABEL maintainer="hxs"

ENV REFRESHED_AT 2020-01-12
ENV SWAN_VER 3.29
ENV L2TP_VER 1.3.12

WORKDIR /opt/src

RUN yum install -y epel-release xl2tpd libreswan lsof iptables
         
COPY ./run.sh /opt/src/run.sh
RUN chmod 755 /opt/src/run.sh

EXPOSE 500/udp 4500/udp

CMD ["/opt/src/run.sh"]

FROM centos:centos7

ENV SUPERVISOR_VERSION=4.0.4
ENV OVS_VERSION 2.4.0
RUN \
  rpm --rebuilddb && yum clean all; \
  yum install -y epel-release; \
  yum update -y; \
  yum install -y \
    iproute \
    python-setuptools \
    hostname \
    inotify-tools \
    yum-utils \
    which \
    jq \
    rsync \
    telnet \
    htop \
    atop \
    iotop \
    mtr \
    wget \
    openssl-devel \
    kernel-devel \
    python-pip \
    supervisor \
    vim && \
  yum clean all && rm -rf /tmp/yum*; 

#RUN yum -y groupinstall "Development Tools"

#RUN mkdir -p ~/rpmbuild/SOURCES \
#    cd ~/rpmbuild/SOURCES \
#    wget https://www.openvswitch.org/releases/openvswitch-2.3.1.tar.gz \
#    tar xfz openvswitch-$OVS_VERSION.tar.gz
    
#RUN sed 's/openvswitch-kmod, //g' openvswitch-2.3.1/rhel/openvswitch.spec > openvswitch-2.3.1/rhel/openvswitch_no_kmod.spec

#RUN rpmbuild -bb --nocheck ~/openvswitch-2.3.1/rhel/openvswitch_no_kmod.spec

VOLUME ["/var/log/openvswitch", "/var/lib/openvswitch", "/var/run/openvswitch", "/etc/openvswitch"]

#RUN yum -y localinstall /home/ovswitch/rpmbuild/RPMS/x86_64/openvswitch-2.3.1-1.x86_64.rpm
#RUN mkdir /etc/openvswitch
#RUN semanage fcontext -a -t openvswitch_rw_t "/etc/openvswitch(/.*)?"
#RUN restorecon -Rv /etc/openvswitch
#RUN service openvswitch start
#RUN chkconfig openvswitch on

ADD supervisord.conf /etc/supervisord.conf

#VOLUME ["/data"]

CMD ["/usr/bin/supervisord"]

#EXPOSE 9111
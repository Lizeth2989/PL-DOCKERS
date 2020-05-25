FROM la_dpdk:1.0.1
 
RUN apt-get update && apt-get install -y --no-install-recommends \
  autoconf automake libtool openssl libssl-dev python \
  && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
 
ENV OVS_DIR=/usr/src/ovs
 
RUN wget https://www.openvswitch.org/releases/openvswitch-2.11.1.tar.gz | tar -xz; \
  mv openvswitch-2.11.1 ${OVS_DIR}
 
#RUN . ${RTE_SDK}/dpdk_eliz.sh; \
RUN export RTE_TARGET=x86_64-native-linuxapp-gcc; \
  cd ${OVS_DIR} \
  && ./boot.sh \
  && ./configure --with-dpdk=${RTE_SDK}/${RTE_TARGET} \
  && make install CFLAGS='-O3 -march=native' \
  && make clean
 
# create database configuration
RUN ovsdb-tool create /usr/local/etc/openvswitch/conf.db /usr/local/share/openvswitch/vswitch.ovsschema
#COPY run_ovs.sh run_ovs.sh
#RUN chmod +x run_ovs.sh
#CMD ["./run_ovs.sh"]
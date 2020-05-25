FROM ubuntu:16.04
RUN apt-get update -y
RUN apt-get install -y numactl
WORKDIR /root/dpdk
COPY dpdk-stable-16.11.1 /root/dpdk/.
ENV PATH "$PATH:/root/dpdk/x86_64-native-linuxapp-gcc/app/"

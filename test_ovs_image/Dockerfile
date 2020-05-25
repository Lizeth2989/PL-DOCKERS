FROM ryu_ovs:2.1.0 
COPY supervisord.conf /etc/supervisord.conf
COPY configure-ovs.sh /usr/local/share/openvswitch/configure-ovs.sh
CMD ["/usr/bin/supervisord"]
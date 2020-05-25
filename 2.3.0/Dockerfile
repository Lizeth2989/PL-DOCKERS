FROM pritom_liz:2.0
RUN apt-get install -y openssh-server apache2 supervisor
#RUN /usr/bin/ovsdb-tool create /etc/openvswitch/conf.db /usr/local/share/openvswitch/vswitch.ovsschema
RUN mkdir -p /var/run/openvswitch
RUN mkdir -p /var/lock/apache2 /var/run/apache2 /var/run/sshd /var/log/supervisor
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
CMD ["/usr/bin/supervisord"]
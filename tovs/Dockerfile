FROM tovs:1.1.0
RUN apt-get install -y supervisor net-tools
RUN mkdir -p /var/log/supervisor
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
ENV PATH "$PATH:/usr/local/share/openvswitch/scripts"
CMD ["/usr/bin/supervisord"]
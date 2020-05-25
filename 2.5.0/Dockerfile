FROM pritom_liz:2.4.5
RUN apt-get update
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
ENV PATH "$PATH:/usr/local/share/openvswitch/scripts"
CMD ["/usr/bin/supervisord"]
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#version: 28 nov 2019

from ryu.base import app_manager
from ryu.controller import ofp_event, dpset, ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4, tcp, udp
from ryu.lib.packet.packet import Packet
from ryu.topology.api import get_switch, get_link, get_host
from ryu.topology import event, switches
import networkx as nx
from ryu.app.ofctl.api import get_datapath
from ryu.lib import hub
from collections import defaultdict
import time
import json
import logging
import requests




DEFAULT_WEIGHT = 1
NUMBER_OF_SWITCH_PORTS = 6              # To be set according to the topology
MAGNITUDE_MEGA_BYTES = 10**6
MAG_STR = "MByte"
MAX_RTT_ADMITTED = 1000
MAX_PING_TIME_ADMITTED = 10000
MAX_PKT_SRC = 3
MAX_PKT_DST = 1
ETH_HDR_SIZE = 18 # bytes


class LoadBalancingSwitch(app_manager.RyuApp):
        OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
        _CONTEXTS = {'wsgi': WSGIApplication}


        def __init__(self, *args, **kwargs):

                super(LoadBalancingSwitch, self).__init__(*args, **kwargs)
                wsgi = kwargs['wsgi']
                self.topology_api_app = self
                self.net = nx.DiGraph()
                self.datapaths = {}
                self.mac_to_port = {}
                self.mac_to_dpid = {}
                self.port_to_mac = {}
                self.ip_to_mac = {}
                self.port_occupied = defaultdict(lambda: defaultdict(int))
                self.packet_counter = {}
                self.monitor_thread = hub.spawn(self._monitor)
                self.cos = {'control': 0, 'VoIP': 1, 'video': 2, 'critical': 3, 'signaling': 4, 'OAM': 5, 'transaction': 6,
                       'bulk': 7, 'p2p': 8, 'default': 9}
        def _monitor(self):

                # When a new flow arrives, an entry is added to the dictionary.
                # When the flow reacahed 5 pkts, the flow entry is added to the switch
                # When the flow etry is removed from the switch, the entry in the dictionary is canceled
                # When the flow etry is removed from the switch, the entry in the dictionary is canceled
                # If the flow is never added because it never reaches 5 pkts, it will be never deleted from the dictionary
                # This occurs when we use iperf because a connection is set up first using one port for few pkts and then
                # using another port for the REAL connection

                black_list = []
                while True:
                        for flow, value in self.packet_counter.items():
                                if flow in black_list:
                                        del self.packet_counter[flow]
                                elif value[0] <= MAX_PKT_SRC:
                                        black_list.append(flow)
                        # print "\n", self.packet_counter, "\n"
                        hub.sleep(10)


        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def switch_features_handler(self, ev):
                datapath = ev.msg.datapath
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                self.datapaths[datapath.id] = datapath
                self.mac_to_port.setdefault(datapath.id, {})
                match = parser.OFPMatch()
                actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
                self.add_flow(datapath, 0, match, actions, 0, ())
                self.logger.debug("Installed table-miss on switch %s", datapath.id)


        def add_flow(self, datapath, priority, match, actions, idle_timeout, path, buffer_id=None):
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                if len(actions)>1:
                        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions[0]), parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions[1])]
                else:
                        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                flags = (ofproto.OFPFF_RESET_COUNTS | ofproto.OFPFF_SEND_FLOW_REM)
                if buffer_id:
                        mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idle_timeout,
                                                                        buffer_id=buffer_id, priority=priority, flags = flags,
                                                                        match=match, instructions=inst)
                else:
                        mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idle_timeout,
                                                                        priority=priority, flags = flags, match=match, instructions=inst)
                datapath.send_msg(mod)

        def send_arp(self, datapath, opcode, src_mac, src_ip, dst_mac, dst_ip, out_port):
                if opcode == 1:         # ARP request
                        target_mac = "00:00:00:00:00:00"
                        target_ip = dst_ip
                elif opcode == 2:       # ARP reply
                        target_mac = dst_mac
                        target_ip = dst_ip

                e = ethernet.ethernet(dst_mac, src_mac, ether.ETH_TYPE_ARP)
                a = arp.arp(1, 0x0800, 6, 4, opcode, src_mac, src_ip, target_mac, target_ip)
                p = Packet()
                p.add_protocol(e)
                p.add_protocol(a)
                p.serialize()

                actions = [datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
                out = datapath.ofproto_parser.OFPPacketOut(
                                datapath=datapath,
                                buffer_id=0xffffffff,
                                in_port=datapath.ofproto.OFPP_CONTROLLER,
                                actions=actions,
                                data=p.data)
                datapath.send_msg(out)

        def _mac_learning(self, dpid_src, src, in_port):
                """MAC learning, called in the `_packet_in_handler`."""
                self.mac_to_port.setdefault(dpid_src, {})
                self.port_to_mac.setdefault(dpid_src, {})
                self.mac_to_port[dpid_src][src] = in_port
                self.mac_to_dpid[src] = dpid_src
                self.port_to_mac[dpid_src][in_port] = src


        def _handle_arp_packets(self, switches, datapath, dpid_src, pkt, src, dst, in_port):
                """Handling of an ARP packet."""
                arp_packet = pkt.get_protocol(arp.arp)
                arp_src_ip = arp_packet.src_ip
                arp_dst_ip = arp_packet.dst_ip

                if arp_packet.opcode == 1:
                        #self.logger.info("ARP request")
                        if arp_dst_ip in self.ip_to_mac:
                                #self.logger.info("The address is inside the IP TO MAC table")
                                src_ip = arp_dst_ip
                                dst_ip = arp_src_ip
                                src_mac = self.ip_to_mac[arp_dst_ip]
                                dst_mac = src
                                out_port = in_port
                                # Send an ARP reply
                                opcode = 2
                                self.send_arp(datapath, opcode, src_mac, src_ip, dst_mac, dst_ip, out_port)
                                #self.logger.info("Packet in %s %s %s %s", src_mac, src_ip, dst_mac, dst_ip)
                        else:
                                #self.logger.info("The address is NOT inside the IP TO MAC table")
                                src_ip = arp_src_ip
                                dst_ip = arp_dst_ip
                                src_mac = src
                                dst_mac = dst
                                self.ip_to_mac.setdefault(src_ip, {})
                                self.ip_to_mac[src_ip] = src_mac
                                opcode = 1
                                for id_switch in switches:
                                        datapath_dst = get_datapath(self, id_switch)
                                        for port in range(1, NUMBER_OF_SWITCH_PORTS+1):
                                                if self.port_occupied[id_switch][port] == 0:
                                                        out_port = port
                                                        if id_switch == dpid_src:
                                                                if out_port != in_port:
                                                                        self.send_arp(datapath_dst, opcode, src_mac, src_ip, dst_mac, dst_ip, out_port)
                                                        else:
                                                                self.send_arp(datapath_dst, opcode, src_mac, src_ip, dst_mac, dst_ip, out_port)
                else:
                        #self.logger.info("ARP reply")
                        src_ip = arp_src_ip
                        dst_ip = arp_dst_ip
                        src_mac = src
                        dst_mac = dst
                        if arp_dst_ip in self.ip_to_mac:
                                self.ip_to_mac.setdefault(src_ip, {})
                                self.ip_to_mac[src_ip] = src_mac
                        opcode = 2
                        out_port = self.mac_to_port[self.mac_to_dpid[dst_mac]][dst_mac]
                        datapath_dst = get_datapath(self, self.mac_to_dpid[dst_mac])
                        self.send_arp(datapath_dst, opcode, src_mac, src_ip, dst_mac, dst_ip, out_port)


        def _handle_ipv4_packets(self, pkt, ip4_pkt, ofproto, parser, datapath, dpid_src, src, dst):
                """Handling of an IPv4 packet."""
                src_ip = ip4_pkt.src
                dst_ip = ip4_pkt.dst
                src_mac = src
                dst_mac = dst
                proto = ip4_pkt.proto
                sport = 0
                dport = 0
                tos = ip4_pkt.tos
                length = ip4_pkt.total_length

                if proto == 6:
                        tcp_pkt = pkt.get_protocol(tcp.tcp)
                        sport = tcp_pkt.src_port
                        dport = tcp_pkt.dst_port

                if proto == 17:
                        udp_pkt = pkt.get_protocol(udp.udp)
                        sport = udp_pkt.src_port
                        dport = udp_pkt.dst_port


                self.logger.info("\n--- Packet_in switch: {}, source IP: {}, destination IP: {}, port_src {} and port_dst {}, with ToS {}, layer 4 protocol: {} and total packet length of {} Bytes".format( dpid_src, src_ip, dst_ip, sport, dport, tos, proto, length))
                #self.logger.info("--- Packet_in switch: %s, source MAC: %s, destination MAC: %s, From the port: %s", dpid_src, src_mac, dst_mac, in_port)

                datapath_dst = get_datapath(self, self.mac_to_dpid[dst_mac])
                dpid_dst = datapath_dst.id
                self.logger.info(" --- Destination present on switch: %s", dpid_dst)
                print ("path ", self.net.nodes(), self.net.edges(), dpid_src, dpid_dst)
                path = nx.shortest_path(self.net, dpid_src, dpid_dst, weight='weight')
            
                self.logger.info(" --- Shortest path: %s\n", path)

                # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                if len(path) == 1:
                        in_port_src = self.mac_to_port[dpid_src][src_mac]
                        out_port_src = in_port_dst = self.mac_to_port[dpid_dst][dst_mac]
                        if proto == 6:
                                actions_1_src = [datapath.ofproto_parser.OFPActionOutput(out_port_src)]
                                match_1_src = parser.OFPMatch(eth_type=0x0800,
                                                                                                ipv4_src=src_ip,
                                                                                                ipv4_dst=dst_ip,
                                                                                                ip_dscp=tos/4,
                                                                                                tcp_src=sport,
                                                                                                tcp_dst=dport,
                                                                                                ip_proto=proto)
                                if (self.check_threshold(match_1_src, dpid_src, length, dst_ip, src_ip, dport, sport, proto)[0]):
                                        set_queue = self.check_threshold(match_1_src, dpid_src, length, dst_ip, src_ip, dport, sport, proto)[1]
                                        actions_grp = self.send_group_mod(datapath, out_port_src, set_queue)
                                        self.add_flow(datapath, 3, match_1_src, actions_grp, MAX_RTT_ADMITTED, path)
                                        self.logger.info("Install TCP 5-tuple flow on switch %s", path[0])
                        elif proto == 17:
                                actions_1_src = [datapath.ofproto_parser.OFPActionOutput(out_port_src)]
                                match_1_src = parser.OFPMatch(eth_type=0x0800,
                                                                                                ipv4_src=src_ip,
                                                                                                ipv4_dst=dst_ip,
                                                                                                ip_dscp=tos/4,
                                                                                                udp_src=sport,
                                                                                                udp_dst=dport,
                                                                                                ip_proto=proto)
                                if (self.check_threshold(match_1_src, dpid_src, length, dst_ip, src_ip, dport, sport, proto)[0]):
                                        set_queue = self.check_threshold(match_1_src, dpid_src, length, dst_ip, src_ip, dport, sport,
                                                       proto)[1]
                                        actions_grp = self.send_group_mod(datapath, out_port_src, set_queue)
                                        self.add_flow(datapath, 3, match_1_src, actions_grp, MAX_RTT_ADMITTED, path)
                                        self.logger.info("Install UDP 5-tuple flow on switch %s", path[0])
                        else:
                                actions_1_src = [datapath.ofproto_parser.OFPActionOutput(out_port_src)]
                                match_1_src = parser.OFPMatch(eth_type=0x0800,
                                                                                                ipv4_src=src_ip,
                                                                                                ipv4_dst=dst_ip)

                                if (self.check_threshold(match_1_src, dpid_src, length, dst_ip, src_ip, dport, sport, proto)[0]):
                                        set_queue = self.check_threshold(match_1_src, dpid_src, length, dst_ip, src_ip, dport, sport, proto)[1]
                                        actions_grp = self.send_group_mod(datapath, out_port_src, set_queue)
                                        self.add_flow(datapath, 1, match_1_src, actions_grp, MAX_RTT_ADMITTED, path)
                                        self.logger.info("Install IP-fwd flow on switch %s", path[0])
                                match = parser.OFPMatch(eth_type=0x0800,
                                                                                ip_proto=6)
                                actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                                                ofproto.OFPCML_NO_BUFFER)]
                                self.add_flow(datapath, 2, match, actions, MAX_PING_TIME_ADMITTED, path)
                                self.logger.info("Install TCP-send flow on switch %s", path[0])
                                match = parser.OFPMatch(eth_type=0x0800,
                                                                                ip_proto=17)
                                actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                                                ofproto.OFPCML_NO_BUFFER)]
                                self.add_flow(datapath, 2, match, actions, MAX_PING_TIME_ADMITTED, path)
                                self.logger.info("Install UDP-send flow on switch %s", path[0])
                elif len(path) >= 2:
                        if (len(path) > 2):
                                for i in range(1, len(path)-1):
                                        output_port = self.net[path[i]][path[i + 1]]['port']
                                        dp = get_datapath(self, path[i])
                                        actions_1 = [dp.ofproto_parser.OFPActionOutput(output_port)]
                                        if proto == 6:
                                                match_1 = parser.OFPMatch(eth_type=0x0800,
                                                                                                ipv4_src=src_ip,
                                                                                                ipv4_dst=dst_ip,
                                                                                                ip_dscp=tos/4,
                                                                                                tcp_dst=dport,
                                                                                                tcp_src=sport,
                                                                                                ip_proto=proto)

                                                set_queue = \
                                                        self.check_threshold(match_1, dpid_src, length , dst_ip, src_ip,
                                                                            dport, sport,
                                                                            proto)[
                                                                1]
                                                actions_grp = self.send_group_mod(dp, output_port, set_queue)
                                                self.add_flow(dp, 3, match_1, actions_grp, MAX_RTT_ADMITTED, path)
                                                self.logger.info("Install TCP 5-tuple flow on switch %s", path[i])
                                        elif proto == 17:
                                                match_1 = parser.OFPMatch(eth_type=0x0800,
                                                                                                ipv4_src=src_ip,
                                                                                                ipv4_dst=dst_ip,
                                                                                                ip_dscp=tos/4,
                                                                                                udp_dst=dport,
                                                                                                udp_src=sport,
                                                                                                ip_proto=proto)
                                                set_queue = \
                                                        self.check_threshold(match_1, dpid_src, length, dst_ip, src_ip,
                                                                            dport, sport,
                                                                            proto)[
                                                                1]
                                                actions_grp = self.send_group_mod(dp, output_port, set_queue)
                                                self.add_flow(dp, 3, match_1, actions_grp, MAX_RTT_ADMITTED, path)
                                                self.logger.info("Install UDP 5-tuple flow on switch %s", path[i])
                                        else:
                                                match_1 = parser.OFPMatch(eth_type=0x0800,
                                                                                                ipv4_src=src_ip,
                                                                                                ipv4_dst=dst_ip)
                                                set_queue = self.check_threshold(match_1, dpid_src, length, dst_ip, src_ip,
                                                                    dport, sport, proto)[1]
                                                actions_grp = self.send_group_mod(dp, output_port, set_queue)
                                                self.add_flow(dp, 1, match_1, actions_grp, MAX_RTT_ADMITTED, path)
                                                self.logger.info("Install IP-fwd flow on switch %s", path[i])
                        datapath_src = get_datapath(self, path[0])
                        datapath_dst = get_datapath(self, path[len(path) - 1])
                        dpid_src = datapath_src.id
                        #self.logger.info("dpid_src  %s", dpid_src)
                        dpid_dst = datapath_dst.id
                        #self.logger.info("dpid_dst  %s", dpid_dst)
                        in_port_src = self.mac_to_port[dpid_src][src_mac]
                        #self.logger.info("in_port_src  %s", in_port_src)
                        out_port_src = self.net[path[0]][path[1]]['port']
                        #self.logger.info("out_port_src  %s", out_port_src)
                        in_port_dst = self.mac_to_port[dpid_dst][dst_mac]
                        #self.logger.info("in_port_dst  %s", in_port_dst)
                        if proto == 6:
                                actions_1_dst = [datapath.ofproto_parser.OFPActionOutput(in_port_dst)]
                                match_1_dst = parser.OFPMatch(eth_type=0x0800,
                                                                                                ipv4_src=src_ip,
                                                                                                ipv4_dst=dst_ip,
                                                                                                ip_dscp=tos/4, # DSCP value is the first 6-bit of ToS field in IP header. N.B. I valori di ToS ammissibili sono solo 0, 32, 40, 56, 72, 88, 96, ..., 224. Pertanto se imponiamo --tos 0x23, iperf assegnera' 32, se --tos 0x24 assegna 36 e cosi' via
                                                                                                tcp_dst=dport,
                                                                                                tcp_src=sport,
                                                                                                ip_proto=proto)
                                set_queue = \
                                        self.check_threshold(match_1_dst, dpid_src, length, dst_ip, src_ip, dport, sport,
                                                            proto)[
                                                1]
                                actions_grp = self.send_group_mod(datapath_dst, in_port_dst, set_queue)
                                self.add_flow(datapath_dst, 3, match_1_dst, actions_grp, MAX_RTT_ADMITTED, path)
                                self.logger.info("Install TCP 5-tuple flow on switch %s", path[len(path) - 1])
                                actions_1_src = [datapath.ofproto_parser.OFPActionOutput(out_port_src)]
                                match_1_src = parser.OFPMatch(eth_type=0x0800,
                                                                                                ipv4_src=src_ip,
                                                                                                ipv4_dst=dst_ip,
                                                                                                ip_dscp=tos/4,
                                                                                                tcp_src=sport,
                                                                                                tcp_dst=dport,
                                                                                                ip_proto=proto)

                                if (self.check_threshold(match_1_src, dpid_src, length, dst_ip, src_ip, dport, sport, proto)[0]):
                                        set_queue = \
                                        self.check_threshold(match_1_src, dpid_src, length, dst_ip, src_ip, dport, sport,
                                                       proto)[1]
                                        actions_grp = self.send_group_mod(datapath_src, out_port_src, set_queue)
                                        self.add_flow(datapath_src, 3, match_1_src, actions_grp, MAX_RTT_ADMITTED, path)
                                        self.logger.info("Install TCP 5-tuple flow on switch %s", path[0])


                        elif proto == 17:
                                actions_1_dst = [datapath.ofproto_parser.OFPActionOutput(in_port_dst)]
                                match_1_dst = parser.OFPMatch(eth_type=0x0800,
                                                                                                ipv4_src=src_ip,
                                                                                                ipv4_dst=dst_ip,
                                                                                                ip_dscp=tos/4,
                                                                                                udp_src=sport,
                                                                                                udp_dst=dport,
                                                                                                ip_proto=proto)
                                set_queue = \
                                        self.check_threshold(match_1_dst, dpid_src, length, dst_ip, src_ip, dport, sport,
                                                            proto)[
                                                1]
                                actions_grp = self.send_group_mod(datapath_dst, in_port_dst, set_queue)
                                self.add_flow(datapath_dst, 3, match_1_dst, actions_grp, MAX_RTT_ADMITTED, path)
                                self.logger.info("Install UDP 5-tuple flow on switch %s", path[len(path) - 1])
                                actions_1_src = [datapath.ofproto_parser.OFPActionOutput(out_port_src)]
                                match_1_src = parser.OFPMatch(eth_type=0x0800,
                                                                                                ipv4_src=src_ip,
                                                                                                ipv4_dst=dst_ip,
                                                                                                ip_dscp=tos/4,
                                                                                                udp_src=sport,
                                                                                                udp_dst=dport,
                                                                                                ip_proto=proto)

                                if (self.check_threshold(match_1_src, dpid_src, length, dst_ip, src_ip, dport, sport, proto)[0]):
                                        set_queue = \
                                                self.check_threshold(match_1_src, dpid_src, length, dst_ip, src_ip,
                                                                    dport, sport,
                                                                    proto)[
                                                        1]
                                        actions_grp = self.send_group_mod(datapath_src, out_port_src, set_queue)
                                        self.add_flow(datapath_src, 3, match_1_src, actions_grp, MAX_RTT_ADMITTED, path)
                                        self.logger.info("Install UDP 5-tuple flow on switch %s", path[0])
                        else:
                                actions_1_dst = [datapath.ofproto_parser.OFPActionOutput(in_port_dst)]
                                match_1_dst = parser.OFPMatch(eth_type=0x0800,
                                                                                                ipv4_src=src_ip,
                                                                                                ipv4_dst=dst_ip)
                                set_queue = \
                                        self.check_threshold(match_1_dst, dpid_src, length, dst_ip, src_ip, dport, sport,
                                                            proto)[
                                                1]
                                actions_grp = self.send_group_mod(datapath_dst, in_port_dst, set_queue)
                                self.add_flow(datapath_dst, 1, match_1_dst, actions_grp, MAX_RTT_ADMITTED, path)
                                self.logger.info("DESTINATION Install IP-fwd flow on switch %s", path[len(path) - 1])


                                actions_1_src = [datapath.ofproto_parser.OFPActionOutput(out_port_src)]
                                match_1_src = parser.OFPMatch(eth_type=0x0800,
                                                                                                ipv4_src=src_ip,
                                                                                                ipv4_dst=dst_ip)
                                if (self.check_threshold(match_1_src, dpid_src, length, dst_ip, src_ip, dport, sport, proto)[0]):
                                #print(set_queue, datapath.ofproto_parser.OFPActionOutput(out_port_src), datapath.ofproto_parser.OFPQueueStatsRequest(datapath, 0, port_no=out_port_src, queue_id=set_queue), out_port_src)
                                    #print(out_port_src, dpid_src, self.check_threshold(match_1_src, dpid_src, length, dst_ip, src_ip, dport, sport, proto)[0]) 
                                    set_queue = self.check_threshold(match_1_src, dpid_src, length, dst_ip, src_ip,
                                                                        dport, sport,
                                                                        proto)[
                                                            1]
                                    actions_grp = self.send_group_mod(datapath_src, out_port_src, set_queue)
                                    #print(set_queue, actions_grp, out_port_src)
                                    self.add_flow(datapath_src, 1, match_1_src, actions_grp, MAX_RTT_ADMITTED, path)
                                    self.logger.info("SOURCE Install IP-fwd flow on switch %s", path[0])


                                match = parser.OFPMatch(eth_type=0x0800,
                                                                                ip_proto=6)
                                actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                                                ofproto.OFPCML_NO_BUFFER)]
                                self.add_flow(datapath_src, 2, match, actions, MAX_PING_TIME_ADMITTED, path)
                                self.logger.info("Install TCP-send flow on switch %s", path[0])
                                match = parser.OFPMatch(eth_type=0x0800,
                                                                                ip_proto=17)
                                actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                                                ofproto.OFPCML_NO_BUFFER)]
                                self.add_flow(datapath_src, 2, match, actions, MAX_PING_TIME_ADMITTED, path)
                                self.logger.info("Install UDP-send flow on switch %s", path[0])
                if len(path) == 1:
                        out_port = self.mac_to_port[dpid_src][dst_mac]
                else:
                        out_port = self.net[path[0]][path[1]]['port']
                actions = [parser.OFPActionOutput(out_port)]
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
                datapath.send_msg(out)


        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def _packet_in_handler(self, ev):
                if ev.msg.msg_len < ev.msg.total_len:
                        self.logger.debug("Packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
                msg = ev.msg
                datapath = msg.datapath
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                in_port = msg.match['in_port']
                pkt = packet.Packet(msg.data)
                eth = pkt.get_protocols(ethernet.ethernet)[0]
                if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                        # Ignore lldp packets
                        return
                src = eth.src
                dst = eth.dst
                dpid_src = datapath.id
                print ("SOURCE:",src)
                if self.mac_to_dpid.get(src) is not None and self.mac_to_dpid.get(src) != datapath.id:
                        print("Pkt discarded because the switch {} is not directly attached to the host {}. Write the code such that the pkt is sent back to the queue because the flow rule is already in.").format(datapath.id, src)
                        print ("SOURCE MAC:", self.mac_to_dpid.get(src))
                        return
                # TOPOLOGY DISCOVERY----------------------------------------------------------------------
                switches = self.get_topology_data(1)

                # MAC LEARNING----------------------------------------------------------------------------
                self._mac_learning(dpid_src, src, in_port)

                # HANDLE ARP PACKETS----------------------------------------------------------------------
                if eth.ethertype == ether_types.ETH_TYPE_ARP:
                        self._handle_arp_packets(switches, datapath, dpid_src, pkt, src, dst, in_port)

                # HANDLE IP PACKETS-----------------------------------------------------------------------
                ip4_pkt = pkt.get_protocol(ipv4.ipv4)
                if ip4_pkt:
                        self._handle_ipv4_packets(pkt, ip4_pkt, ofproto, parser, datapath, dpid_src, src, dst)

        @set_ev_cls(event.EventSwitchEnter)
        def get_topology_data(self, ev):
                switch_list = get_switch(self.topology_api_app, None)
                switches = [switch.dp.id for switch in switch_list]
                self.net.add_nodes_from(switches)
                links_list = get_link(self.topology_api_app, None)

                for link in links_list:
                        self.net.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no, weight=DEFAULT_WEIGHT)
                        self.net.add_edge(link.dst.dpid, link.src.dpid, port=link.dst.port_no, weight=DEFAULT_WEIGHT)


                if ev == 1:
                        links_ = [(link.dst.dpid, link.src.dpid, link.dst.port_no) for link in links_list]
                        for l in links_:
                                self.port_occupied[l[0]][l[2]] = 1
                        #print json.dumps(self.port_occupied)
                        return switches



        @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
        def flow_removed_handler(self, ev):
                """Deletes the flow entry from the `match_to_stats` dictionary of each link."""
                msg = ev.msg
                dp = msg.datapath
                ofp = dp.ofproto
                if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
                        reason = 'IDLE TIMEOUT'
                elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
                        reason = 'HARD TIMEOUT'
                elif msg.reason == ofp.OFPRR_DELETE:
                        reason = 'DELETE'
                elif msg.reason == ofp.OFPRR_GROUP_DELETE:
                        reason = 'GROUP DELETE'
                else:
                        reason = 'unknown'
                match_tuple = self.OFPMatch_to_tuple(msg.match)
                try:
                        del self.packet_counter[(msg.datapath.id,match_tuple)]
                        # print "deleted flow :"
                        # print msg.datapath.id,match_tuple
                except:
                        # print "The remove flow is of a switch which is not the first one in the path. No need to remove the flow."
                        # print msg.datapath.id,match_tuple
                        pass

        def OFPMatch_to_tuple(self, match):
                """Returns `match` as a tuple of tuples.

                Example of what is returned:
                (
                        ('eth_type', 2048),
                        ('ipv4_src', '10.0.0.2'),
                        ('ipv4_dst', '10.0.0.1'),
                        ('ip_dscp', 14),
                        ('ip_proto', 6),
                        ('tcp_src', 48744),
                        ('tcp_dst', 4000),
                )

                """
                parsed_match = [('eth_type', 0), ('ipv4_src', 0), ('ipv4_dst', 0), ('ip_dscp', 0), ('ip_proto', 0), ('udp_src', 0), ('udp_dst', 0)]
                for field in match._fields2:
                        if field[0] == 'eth_type':
                                parsed_match[0] = (field[0], field[1]) # field[1] type int
                        elif field[0] == 'ipv4_src':
                                parsed_match[1] = (field[0], field[1]) # field[1] type str
                        elif field[0] == 'ipv4_dst':
                                parsed_match[2] = (field[0], field[1]) # field[1] type str
                        elif field[0] == 'ip_dscp':
                                parsed_match[3] = (field[0], field[1]) # field[1] type int
                        elif field[0] == 'ip_proto': # se trovi nella tupla la striga dell' ip_proto
                                parsed_match[4] = (field[0], field[1]) # field[1] type int
                        elif field[0] == 'udp_src' or field[0] == 'tcp_src':
                                parsed_match[5] = (field[0], field[1]) # field[1] type int
                        elif field[0] == 'udp_dst' or field[0] == 'tcp_dst':
                                parsed_match[6] = (field[0], field[1]) # field[1] type int
                return tuple(parsed_match)


        def increment_pkt_ctr(self, dp_id, flow_key, length):
                if self.packet_counter.get((dp_id,flow_key)) is not None:
                        pkt_count = self.packet_counter[(dp_id,flow_key)][0] + 1
                        cumulative_length = self.packet_counter[(dp_id, flow_key)][1] + length + ETH_HDR_SIZE
                        self.packet_counter[(dp_id, flow_key)] = (pkt_count, cumulative_length)
                else:
                        self.packet_counter[(dp_id, flow_key)] = (1, length)
                # print (self.packet_counter[(dp_id, flow_key)])
                # for flow in self.packet_counter.iterkeys():
                #       number_of_pkts = self.packet_counter.get(flow)[0]
                #       number_of_bytes = self.packet_counter.get(flow)[1]
                #       print "IP_src {}, IP_dst {}, port_src {}, port_dst {}, tos {}, packets {}, bytes {}".format(flow[1][1][1], flow[1][2][1], flow[1][5][1], flow[1][6][1], flow[1][3][1], number_of_pkts, number_of_bytes)


        def check_threshold(self, match_1_src, dpid_src, length, dst_ip, src_ip, dport, sport, proto):
                dict_key = self.OFPMatch_to_tuple(match_1_src)
                self.increment_pkt_ctr(dpid_src, dict_key, length)
                if self.packet_counter[(dpid_src, dict_key)][0] == MAX_PKT_SRC:
                        src_to_dst_pkts = self.packet_counter[(dpid_src, dict_key)][0]
                        src_to_dst_bytes = self.packet_counter[(dpid_src, dict_key)][1]
                        dst_to_src_pkts = 0
                        dst_to_src_bytes = 0
                        if proto == 1:
                                proto = 0 # when parsedwith OFPMATCH, proto 1 becomes proto == 0
                        for flow in self.packet_counter.iterkeys():
                                if (flow[1][1][1] == dst_ip and flow[1][2][1] == src_ip and flow[1][5][1] == dport and flow[1][6][1] == sport and flow[1][4][1] == proto):
                                        dst_to_src_pkts = self.packet_counter.get(flow)[0]
                                        dst_to_src_bytes = self.packet_counter.get(flow)[1]
                        print(
                                [str(proto), str(sport), str(dport), str(src_to_dst_pkts), str(src_to_dst_bytes), str(dst_to_src_pkts),
                                        str(dst_to_src_bytes)])
                        print("Flow is "+requests.get(
                                "http://127.0.0.1:5000/class?protocol=" + str(proto) + "&src_port=" + str(sport) + "&dst_port=" + str(
                                        dport) + "&src_packet=" + str(src_to_dst_pkts) + "&src_bytes=" + str(
                                        src_to_dst_bytes) + "&dst_packet=" + str(dst_to_src_pkts) + "&dst_bytes=" + str(
                                        dst_to_src_bytes)).content)
                        flow = requests.get(
                                "http://127.0.0.1:5000/class?protocol=" + str(proto) + "&src_port=" + str(sport) + "&dst_port=" + str(
                                        dport) + "&src_packet=" + str(src_to_dst_pkts) + "&src_bytes=" + str(
                                        src_to_dst_bytes) + "&dst_packet=" + str(dst_to_src_pkts) + "&dst_bytes=" + str(
                                        dst_to_src_bytes)).content
                        self.logger.info("src ip: %s, dst ip: %s, protocol: %s, src port: %s, dst port: %s, src_dst_pkts: %s, src_dst_byte: %s, dst_src_pkts: %s, dst_src_bytes: %s, %s", src_ip, dst_ip ,str(proto), str(sport), str(dport), str(src_to_dst_pkts), str(src_to_dst_bytes), str(dst_to_src_pkts),str(dst_to_src_bytes), flow)
                        print("\n\n\npredicted: ")
                        return 1, self.cos.get(str(flow))
                return 0, 9

        def send_group_mod(self, datapath, port, queue_id):
                #function to match the destination port and an specific queue
                ofp = datapath.ofproto
                ofp_parser = datapath.ofproto_parser
                port_1=ofp_parser.OFPActionOutput(port) #destination port
                queue_1=ofp_parser.OFPActionSetQueue(queue_id) #associated queue
                actions_1 = [queue_1,port_1] #matching port and queue
                weight_1 = 100 #in case of load balancing, porcentage of the traffic by this link 
                watch_port = ofproto_v1_3.OFPP_ANY
                watch_group = ofproto_v1_3.OFPQ_ALL

                buckets = [
                        ofp_parser.OFPBucket(weight_1, watch_port, watch_group, actions_1)] #buckets 

                group_id = port*10 + queue_id # the first number of the identifier identifies the port, the second one the queue
                req = ofp_parser.OFPGroupMod(
                        datapath, ofp.OFPFC_ADD,
                        ofp.OFPGT_SELECT, group_id, buckets) #definition of the groupMod with the action buckets. 

                datapath.send_msg(req)

                return [datapath.ofproto_parser.OFPActionGroup(group_id)] 


app_manager.require_app('ryu.app.ws_topology')
app_manager.require_app('ryu.app.ofctl_rest')
app_manager.require_app('ryu.app.gui_topology.gui_topology')


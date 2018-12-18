#!/bin/bash
# https://github.com/rishikeshadusumilli/TCP-based-Round-Robin-Load-Balancer/blob/master/loadBalancer13.py
# Code adopted and implemented from Nippon Telegraph and Telephone Corporation.
# Code adopted and implemented from simple_switch_13.py

# Copyright Rishikesh Adusumilli

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import random
from ryu.lib import dpid as dpid_lib
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib import mac as mac_lib
from ryu.lib import ip as ip_lib
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet.ether_types import ETH_TYPE_IP, ETH_TYPE_ARP
from ryu.ofproto import ether, inet
from ryu.lib.packet import tcp
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ether_types
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3


class LoadBalancerHw(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    VIRTUAL_IP = "10.0.0.100"
    VIRTUAL_MAC = "11:22:33:44:55:66"

    def __init__(self, *args, **kwargs):
        super(LoadBalancerHw, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # Assigning IP address to TCP servers (H1, H2, and H3)

        self.server_ip1 = "10.0.0.1"
        self.server_mac1 = "00:00:00:00:00:01"
        self.server_ip2 = "10.0.0.2"
        self.server_mac2 = "00:00:00:00:00:02"

        # Count to indicate which server to use for TCP session. H1=1, H2=2, H3=3

        self.server_count = 1

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    # Generate ARP reply packet for ARP request to controller (IP: self.VIRTUAL_IP).
    # srcMac can be any value to set controller MAC address for controller IP address.

    def arp_reply_generate(self, dst_mac, dst_ip):
        src_mac = self.VIRTUAL_MAC
        src_ip = self.VIRTUAL_IP

        packet_reply = packet.Packet()
        ether_reply = ethernet.ethernet(dst_mac, src_mac, ETH_TYPE_ARP)
        arp_reply = arp.arp(1, ETH_TYPE_IP, 6, 4, 2, src_mac, src_ip, dst_mac, dst_ip)
        packet_reply.add_protocol(ether_reply)
        packet_reply.add_protocol(arp_reply)
        packet_reply.serialize()

        return packet_reply

    # Module to receive Packet-In

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("\n packet truncated: only %s of %s bytes", ev.msg.msg_len,
                              ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("Packet-In - DPID: %s SMAC: %s DMAC: %s InPort: %s", dpid, src_mac,
                         dst_mac,
                         in_port)

        # ARP Reply handling
        # Send ARP reply for ARP request to controller (IP: self.VIRTUAL_IP)

        if eth.ethertype == ETH_TYPE_ARP:

            self.logger.info("Reached inside of first ARP type check-------->")
            arp_contents = pkt.get_protocols(arp.arp)[0]
            if arp_contents.dst_ip == self.VIRTUAL_IP and arp_contents.opcode == 1:  # 1 = request
                self.logger.info("Reached inside of ARP reply for self.VIRTUAL_IP-------->")

                packet_reply = self.arp_reply_generate(arp_contents.src_mac, arp_contents.src_ip)

                actions_server = [parser.OFPActionOutput(in_port)]

                arp_server = parser.OFPPacketOut(
                    datapath=datapath,
                    in_port=ofproto.OFPP_ANY,
                    data=packet_reply.data,
                    actions=actions_server,
                    buffer_id=0xffffffff
                )

                self.logger.info(
                    "ARP Response Packet - DPID: %s SMAC: %s DMAC: %s OutPort: %s",
                    dpid, self.VIRTUAL_MAC, src_mac, in_port)

                datapath.send_msg(arp_server)
            return

        # TCP Host to Server
        # Assign TCP server to the host request depending on the count of the TCP request
        # Entire TCP session is assigned and handled by a single server based on count
        # S1 or H1 is used as server for count of 1
        # S2 or H2 is used as server for count of 2

        self.logger.info("Reached inside of first TCP type check-------->")

        server_ip = server_mac = port = None

        if self.server_count == 1:
            server_ip = self.server_ip1
            server_mac = self.server_mac1
            port = 1
        elif self.server_count == 2:
            server_ip = self.server_ip2
            server_mac = self.server_mac2
            port = 2

        if eth.ethertype == ETH_TYPE_IP:
            ip_contents = pkt.get_protocols(ipv4.ipv4)[0]
            if ip_contents.dst == self.VIRTUAL_IP and ip_contents.proto == 0x06:
                tcp_contents = pkt.get_protocols(tcp.tcp)[0]

                # Perform TCP action only if matching TCP properties
                match1 = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=eth.ethertype,
                    eth_src=src_mac,
                    eth_dst=dst_mac,
                    ip_proto=ip_contents.proto,
                    ipv4_src=ip_contents.src,
                    ipv4_dst=ip_contents.dst,
                    tcp_src=tcp_contents.src_port,
                    tcp_dst=tcp_contents.dst_port
                )

                # Send host TCP segments to destination server using destination server port connected to controller
                actions1 = [
                    parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP),
                    parser.OFPActionSetField(eth_dst=server_mac),
                    parser.OFPActionSetField(ipv4_dst=server_ip),
                    parser.OFPActionOutput(port)
                ]

                ip_inst1 = [
                    parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions1)
                ]

                cookie1 = random.randint(0, 0xffffffffffffffff)

                # Create flow for incoming TCP segments from host to server through controller (IP: self.VIRTUAL_IP)
                flow_mod1 = parser.OFPFlowMod(
                    datapath=datapath,
                    match=match1,
                    idle_timeout=7,
                    instructions=ip_inst1,
                    buffer_id=msg.buffer_id,
                    cookie=cookie1
                )

                self.logger.info("Added flow for Host to Server condition------->")
                self.logger.info(
                    "Application on server" + str(self.server_count) + " - IP: " + str(
                        server_ip) + " Mac: " + str(server_mac))

                self.logger.info(
                    "Client-LB - SIP: " + str(ip_contents.src) + " DIP: " + str(ip_contents.dst))

                self.logger.info("LB-Server - SIP: %s DIP: %s" % (self.VIRTUAL_IP, server_ip))

                # Add flow in the flow table of the virtual switch

                datapath.send_msg(flow_mod1)

                # TCP Server to Host

                # Perform TCP action only if matching TCP properties
                match2 = parser.OFPMatch(
                    port,
                    eth_type=eth.ethertype,
                    eth_src=server_mac,
                    eth_dst=self.VIRTUAL_MAC,
                    ip_proto=ip_contents.proto,
                    ipv4_src=server_ip,
                    ipv4_dst=self.VIRTUAL_IP,
                    tcp_src=tcp_contents.dst_port,
                    tcp_dst=tcp_contents.src_port
                )

                # Send server TCP segments to host using source host port connected to controller
                actions2 = [
                    parser.OFPActionSetField(eth_src=self.VIRTUAL_MAC),
                    parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP),
                    parser.OFPActionSetField(eth_dst=eth.src),
                    parser.OFPActionSetField(ipv4_dst=ip_contents.src),
                    parser.OFPActionOutput(in_port)
                ]

                ip_inst2 = [
                    parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions2)
                ]

                cookie2 = random.randint(0, 0xffffffffffffffff)

                # Create flow for TCP segments from server to host through controller (IP: self.VIRTUAL_IP)

                flow_mod2 = parser.OFPFlowMod(
                    datapath=datapath,
                    match=match2,
                    idle_timeout=7,
                    instructions=ip_inst2,
                    cookie=cookie2
                )

                self.logger.info(
                    "Server-LB - SIP: " + server_ip + " DIP: %s" % self.VIRTUAL_IP)

                self.logger.info(
                    "LB-Client - SIP: %s DIP: %s" % (self.VIRTUAL_IP, str(ip_contents.src)))

                # Add flow in the flow table of the virtual switch
                datapath.send_msg(flow_mod2)

                self.logger.info("Added flow for Server to Host condition------->")

        # Server Count increment
        # Increase count so the next server will serve the next TCP connection from different or same host (When it completes the current TCP session with current TCP server)

        self.server_count += 1
        if self.server_count > 2:
            self.server_count = 1

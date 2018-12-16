# https://github.com/exploitthesystem/Ryu-SDN-Load-Balancer/blob/master/LoadBalancer.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.addrconv import ipv4
from ryu.lib.mac import haddr_to_int
from ryu.lib.packet.arp import ARP_HW_TYPE_ETHERNET, ARP_REPLY
from ryu.lib.packet.ether_types import ETH_TYPE_IP
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, tcp
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.ofproto.ofproto_v1_3 import OFPIT_APPLY_ACTIONS


class LoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]  # Specify the use of OpenFlow v13
    VIRTUAL_IP = '10.0.0.100'  # The virtual server IP
    VIRTUAL_MAC = "AB:BC:CD:EF:AB:BC"  # Virtual Load Balancer MAC Address

    H1_ip = '10.0.0.1'  # Host 1's IP
    H2_ip = '10.0.0.2'  # Host 2's IP
    H1_mac = '00:00:00:00:00:01'  # Host 1's mac
    H2_mac = '00:00:00:00:00:02'  # Host 2's mac

    ip_to_port = {
        H1_ip: 1,
        H2_ip: 2
    }

    ip_to_mac = {
        '10.0.0.1': '00:00:00:00:00:01',
        '10.0.0.2': '00:00:00:00:00:02',
        '10.0.0.3': '00:00:00:00:00:03',
        '10.0.0.4': '00:00:00:00:00:04',
        '10.0.0.5': '00:00:00:00:00:05',
        '10.0.0.6': '00:00:00:00:00:06'
    }

    def __init__(self, *args, **kwargs):
        super(LoadBalancer, self).__init__(*args, **kwargs)

    # This function is called when a packet arrives from the switch
    # after the initial handshake has been completed.
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        ether_frame = pkt.get_protocol(ethernet.ethernet)

        # If the packet is an ARP packet, create new flow table
        # entries and send an ARP response.

        print "received packet "

        if ether_frame.ethertype == ether_types.ETH_TYPE_ARP:
            self.add_flow(dp, pkt, ofp_parser, ofp, in_port)
            self.arp_response(dp, pkt, ether_frame, ofp_parser, ofp, in_port)
            # return
        #
        # datapath = msg.datapath
        #
        # parser = datapath.ofproto_parser
        #
        # ip_header = pkt.get_protocols(ipv4.ipv4)[0]
        # # print("IP_Header", ip_header)
        # tcp_header = pkt.get_protocols(tcp.tcp)[0]
        # # print("TCP_Header", tcp_header)
        # eth = pkt.get_protocols(ethernet.ethernet)[0]
        #
        # # Route to server
        # match = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype, eth_src=eth.src,
        #                         eth_dst=eth.dst, ip_proto=ip_header.proto,
        #                         ipv4_src=ip_header.src,
        #                         ipv4_dst=ip_header.dst, tcp_src=tcp_header.src_port,
        #                         tcp_dst=tcp_header.dst_port)
        #
        # if ip_header.src == "10.0.0.3" or ip_header.src == "10.0.0.5":
        #     server_mac_selected = '00:00:00:00:00:01'
        #     server_ip_selected = '10.0.0.1'
        #     server_outport_selected = 1
        # else:
        #     server_mac_selected = '00:00:00:00:00:02'
        #     server_ip_selected = '10.0.0.2'
        #     server_outport_selected = 2
        #
        # actions = [parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP),
        #            parser.OFPActionSetField(eth_src=self.VIRTUAL_MAC),
        #            parser.OFPActionSetField(eth_dst=server_mac_selected),
        #            parser.OFPActionSetField(ipv4_dst=server_ip_selected),
        #            parser.OFPActionOutput(server_outport_selected)]
        # inst = [parser.OFPInstructionActions(OFPIT_APPLY_ACTIONS, actions)]
        # flow_mod = parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=7,
        #                              instructions=inst, buffer_id=msg.buffer_id)
        # datapath.send_msg(flow_mod)
        # print("<========Packet sent from Client :" + str(ip_header.src) + " to Server: " + str(
        #     server_ip_selected) + ", MAC: " + str(
        #     server_mac_selected) + " and on switch port: " + str(
        #     server_outport_selected) + "========>")
        #
        # # Reverse route from server
        # match = parser.OFPMatch(in_port=server_outport_selected, eth_type=eth.ethertype,
        #                         eth_src=server_mac_selected, eth_dst=self.VIRTUAL_MAC,
        #                         ip_proto=ip_header.proto, ipv4_src=server_ip_selected,
        #                         ipv4_dst=self.VIRTUAL_IP, tcp_src=tcp_header.dst_port,
        #                         tcp_dst=tcp_header.src_port)
        # actions = [parser.OFPActionSetField(eth_src=self.VIRTUAL_MAC),
        #            parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP),
        #            parser.OFPActionSetField(ipv4_dst=ip_header.src),
        #            parser.OFPActionSetField(eth_dst=eth.src), parser.OFPActionOutput(in_port)]
        # inst2 = [parser.OFPInstructionActions(OFPIT_APPLY_ACTIONS, actions)]
        # flow_mod2 = parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=7,
        #                               instructions=inst2)
        # datapath.send_msg(flow_mod2)
        # print("<++++++++Reply sent from server having IP: " + str(
        #     server_ip_selected) + ", MAC: " + str(server_mac_selected) + " to client:" + str(
        #     ip_header.src) + " via load balancer :" + str(self.VIRTUAL_IP) + "++++++++>")

    # Sends an ARP response to the contacting host with the
    # real MAC address of a server.
    def arp_response(self, datapath, pkt, ether_frame, ofp_parser, ofp, in_port):
        arp_packet = pkt.get_protocol(arp.arp)
        dst_ip = arp_packet.src_ip
        src_ip = arp_packet.dst_ip
        dst_mac = ether_frame.src

        # If the ARP request isn't from one of the two servers,
        # choose the target/source MAC address from one of the servers;
        # else the target MAC address is set to the one corresponding
        # to the target host's IP.
        if dst_ip != self.H1_ip and dst_ip != self.H2_ip:
            src_mac = self.VIRTUAL_MAC

            # if self.next_server == self.H1_ip:
            #     src_mac = self.H1_mac
            #     self.next_server = self.H2_ip
            # else:
            #     src_mac = self.H2_mac
            #     self.next_server = self.H1_ip
        else:
            src_mac = self.ip_to_mac[src_ip]

        print "arp_response -> src_mac : %s" % src_mac

        eth_header = ethernet.ethernet(dst_mac, src_mac, ether_types.ETH_TYPE_ARP)

        arp_reply_packet = arp.arp(
            hwtype=ARP_HW_TYPE_ETHERNET,
            proto=ETH_TYPE_IP, hlen=6,
            plen=4,
            opcode=ARP_REPLY,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac=dst_mac,
            dst_ip=dst_ip
        )

        print "arp_response -> src_mac : %s" % src_mac
        print "arp_response -> src_ip : %s" % src_ip
        print "arp_response -> dst_mac : %s" % dst_mac
        print "arp_response -> dst_ip : %s" % dst_ip

        pkt = Packet(protocols=[eth_header, arp_reply_packet])
        pkt.serialize()

        # ARP action list
        actions = [
            ofp_parser.OFPActionOutput(ofp.OFPP_IN_PORT)
        ]

        # ARP output message
        out = ofp_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=pkt.data
        )

        datapath.send_msg(out)  # Send out ARP reply

    def get_expected_dest_address(self, src_mac):
        return self.H1_ip if haddr_to_int(src_mac) % 2 == 1 else self.H2_ip

        # Sets up the flow table in the switch to map IP addresses correctly.

    def add_flow(self, datapath, pkt, ofp_parser, ofp, in_port):
        print "add_flow -> arp.arp: %s" % arp.arp

        src_ip = pkt.get_protocol(arp.arp).src_ip
        print "add_flow -> src_ip: %s" % src_ip

        # Don't push forwarding rules if an ARP request is received from a server.
        if src_ip == self.H1_ip or src_ip == self.H2_ip:
            return

        # Generate flow from client to server.
        match = ofp_parser.OFPMatch(in_port=in_port,
                                    ipv4_dst=self.VIRTUAL_IP,
                                    eth_type=ETH_TYPE_IP)

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        src_mac_address = eth.src
        print "add_flow -> src_mac_address: %s" % src_mac_address

        dest_ip_address = self.get_expected_dest_address(src_mac_address)
        print "add_flow -> expected_dest_ip_address: %s" % dest_ip_address

        actions = [
            ofp_parser.OFPActionSetField(ipv4_dst=dest_ip_address),
            ofp_parser.OFPActionOutput(self.ip_to_port[dest_ip_address])
        ]

        inst = [
            ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)
        ]

        mod = ofp_parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            buffer_id=ofp.OFP_NO_BUFFER,
            match=match,
            instructions=inst
        )

        datapath.send_msg(mod)

        # Generate reverse flow from server to host.
        match = ofp_parser.OFPMatch(in_port=self.ip_to_port[dest_ip_address],
                                    ipv4_src=dest_ip_address,
                                    ipv4_dst=src_ip,
                                    eth_type=ETH_TYPE_IP)

        actions = [
            ofp_parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP),
            ofp_parser.OFPActionOutput(in_port)
        ]

        inst = [
            ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)
        ]

        mod = ofp_parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            buffer_id=ofp.OFP_NO_BUFFER,
            match=match,
            instructions=inst)

        datapath.send_msg(mod)

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.lib.mac import haddr_to_int
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet.arp import ARP_REPLY, ARP_REQUEST
from ryu.lib.packet.ether_types import ETH_TYPE_IP, ETH_TYPE_ARP
from ryu.lib.packet import tcp
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ether_types
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3


class Server(object):
    def __init__(self, ip, mac, port):
        self.mac = mac
        self.port = port
        self.ip = ip


class LoadBalance(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    VIRTUAL_IP = "10.0.0.100"
    VIRTUAL_MAC = "1A:2B:3C:4D:5E:6F"

    SERVER1 = Server(mac="00:00:00:00:00:01", ip="10.0.0.1", port=1)
    SERVER2 = Server(mac="00:00:00:00:00:02", ip="10.0.0.2", port=2)

    def __init__(self, *args, **kwargs):
        super(LoadBalance, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        self.servers = [self.SERVER1, self.SERVER2]

    def handle_arp_packet(self, datapath, in_port, ofproto, parser, pkt):
        arp_contents = pkt.get_protocols(arp.arp)[0]
        if arp_contents.dst_ip == self.VIRTUAL_IP and arp_contents.opcode == 1:  # 1 = request

            self.logger.info("_____________________")
            self.logger.info("building ARP Response")
            self.logger.info("_____________________")
            self.logger.info("ARP request src_mac: %s", arp_contents.src_mac)
            self.logger.info("ARP request src_ip: %s", arp_contents.src_ip)

            arp_reply_data = self.build_arp_response(
                arp_contents.src_mac,
                arp_contents.src_ip
            )

            actions = [
                parser.OFPActionOutput(in_port)
            ]

            arp_resp = parser.OFPPacketOut(
                datapath=datapath,
                in_port=ofproto.OFPP_ANY,
                data=arp_reply_data,
                actions=actions,
                buffer_id=ofproto.OFP_NO_BUFFER
            )

            datapath.send_msg(arp_resp)

    def build_arp_response(self, dst_mac, dst_ip):
        src_mac = self.VIRTUAL_MAC
        src_ip = self.VIRTUAL_IP

        ether_reply = ethernet.ethernet(dst_mac, src_mac, ETH_TYPE_ARP)
        arp_reply = arp.arp(ARP_REQUEST, ETH_TYPE_IP, 6, 4, ARP_REPLY, src_mac, src_ip, dst_mac,
                            dst_ip)
        packet_reply = packet.Packet(protocols=[ether_reply, arp_reply])
        packet_reply.serialize()

        return packet_reply.data

    def get_expected_dest_address(self, src_mac):
        return self.servers[(haddr_to_int(src_mac) + 1) % len(self.servers)]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated")

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
        client_src_mac = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        if eth.ethertype == ETH_TYPE_ARP:
            self.handle_arp_packet(datapath, in_port, ofproto, parser, pkt)

        if eth.ethertype == ETH_TYPE_IP:
            ip_contents = pkt.get_protocols(ipv4.ipv4)[0]
            client_src_ip = ip_contents.src

            server = self.get_expected_dest_address(client_src_mac)

            server_ip = server.ip
            server_mac = server.mac
            port = server.port

            if client_src_ip in [server.ip for server in self.servers]:
                return

            if ip_contents.dst == self.VIRTUAL_IP and ip_contents.proto == 0x06:
                tcp_contents = pkt.get_protocols(tcp.tcp)[0]

                self.logger.info("client --> server:  req1.src_ip       = %s" % client_src_ip)
                self.logger.info("client --> server:  req1.src_mac      = %s" % client_src_mac)
                self.logger.info("client --> server:  req1.dst_ip       = %s" % ip_contents.dst)
                self.logger.info("client --> server:  req1.dst_mac      = %s" % dst_mac)
                self.logger.info("client --> server:  req1.in_port      = %s" % str(in_port))
                self.logger.info(
                    "client --> server:  req1.tcp.src_port = %s" % str(tcp_contents.src_port))
                self.logger.info(
                    "client --> server:  req1.tcp.dst_port = %s" % str(tcp_contents.dst_port))

                match1 = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=eth.ethertype,
                    eth_src=client_src_mac,
                    eth_dst=dst_mac,
                    ip_proto=ip_contents.proto,
                    ipv4_src=client_src_ip,
                    ipv4_dst=ip_contents.dst,
                    tcp_src=tcp_contents.src_port,
                    tcp_dst=tcp_contents.dst_port
                )

                actions1 = [
                    parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP),
                    parser.OFPActionSetField(eth_dst=server_mac),
                    parser.OFPActionSetField(ipv4_dst=server_ip),
                    parser.OFPActionOutput(port)
                ]

                ip_inst1 = [
                    parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions1)
                ]

                flow_mod1 = parser.OFPFlowMod(
                    datapath=datapath,
                    match=match1,
                    instructions=ip_inst1,
                    buffer_id=msg.buffer_id
                )

                self.logger.info("____________")
                self.logger.info("adding flow:")
                self.logger.info("____________")

                self.logger.info(
                    "client --> LB: %s --> %s", client_src_ip, ip_contents.dst)
                self.logger.info("LB --> server - %s --> %s", self.VIRTUAL_IP, server_ip)

                datapath.send_msg(flow_mod1)

                match2 = parser.OFPMatch(
                    in_port=port,
                    eth_type=eth.ethertype,
                    eth_src=server_mac,
                    eth_dst=self.VIRTUAL_MAC,
                    ip_proto=ip_contents.proto,
                    ipv4_src=server_ip,
                    ipv4_dst=self.VIRTUAL_IP,
                    tcp_src=tcp_contents.dst_port,
                    tcp_dst=tcp_contents.src_port
                )

                self.logger.info("server --> client:  req.src_ip        = %s" % server_ip)
                self.logger.info("server --> client:  req.src_mac       = %s" % server_mac)
                self.logger.info("server --> client:  req.dst_ip        = %s" % self.VIRTUAL_IP)
                self.logger.info("server --> client:  req.dst_mac       = %s" % self.VIRTUAL_MAC)
                self.logger.info("server --> client:  req.in_port       = %s" % port)
                self.logger.info(
                    "server --> client:  req.tcp.src_port  = %s" % tcp_contents.dst_port)
                self.logger.info(
                    "server --> client:  req.tcp.dst_port  = %s" % tcp_contents.src_port)

                actions2 = [
                    parser.OFPActionSetField(eth_src=self.VIRTUAL_MAC),
                    parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP),
                    parser.OFPActionSetField(eth_dst=client_src_mac),
                    parser.OFPActionSetField(ipv4_dst=client_src_ip),
                    parser.OFPActionOutput(in_port)
                ]

                ip_inst2 = [
                    parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions2)
                ]

                flow_mod2 = parser.OFPFlowMod(
                    datapath=datapath,
                    match=match2,
                    instructions=ip_inst2
                )

                self.logger.info("____________")
                self.logger.info("adding flow:")
                self.logger.info("____________")
                self.logger.info("server --> LB: %s --> %s", server_ip, self.VIRTUAL_IP)

                self.logger.info("LB --> client: %s --> %s", self.VIRTUAL_IP, str(client_src_ip))

                datapath.send_msg(flow_mod2)

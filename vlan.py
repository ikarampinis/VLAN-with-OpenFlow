# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import vlan
from ryu.lib.packet import ether_types
from ryu.ofproto import ether
"""
fill in the code here (optional)
"""
vlan100 = 100
vlan200 = 200
truncport = 1
switch1_accessLinks = {vlan100:{2,3},vlan200:{4}}
switch2_accessLinks = {vlan100:{4},vlan200:{2,3}}

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = msg.datapath_id
        self.logger.info("Datapath ID is %s", hex(dpid))

        if dpid == 0x1A:
            match = datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_dst_mask= 24, nw_tos = 8, nw_dst="192.168.2.0")
            actions =[datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:04:01"),datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:04:02"), datapath.ofproto_parser.OFPActionOutput(4)]
            self.add_flow(datapath, match, actions)
        elif dpid == 0x1B:
            match = datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_dst_mask= 24, nw_tos = 8, nw_dst="192.168.1.0")
            actions =[datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:04:02"),datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:04:01"), datapath.ofproto_parser.OFPActionOutput(4)]
            self.add_flow(datapath, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype
        ######
        self.mac_to_port.setdefault(dpid, {vlan100:{},vlan200:{}})
        ######
        self.logger.info("packet in %s %s %s %s in_port=%s", hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)

        if dpid == 0x1A:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                """
                fill in the code here
                """
                arp_pkt = pkt.get_protocol(arp.arp)
                if arp_pkt.opcode == 1 and arp_pkt.dst_ip == "192.168.1.1":
                    self.arpReply(datapath, eth.src, eth.dst, arp_pkt.src_ip, arp_pkt.dst_ip, msg.in_port)
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                """
                fill in the code here
                """

                ip_pkt = pkt.get_protocol(ipv4.ipv4)

                if "192.168.2." in ip_pkt.dst:
                        print("Router s1a -> packet from: ",ip_pkt.src," -- to: ", ip_pkt.dst)
                        newSrcMac = "00:00:00:00:03:01"
                        newDstMac = "00:00:00:00:03:02"
                        outport = 1

                        match = datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_dst_mask= 24, nw_dst = "192.168.2.0", nw_tos = 0)
                        actions =[datapath.ofproto_parser.OFPActionSetDlSrc(newSrcMac),datapath.ofproto_parser.OFPActionSetDlDst(newDstMac), datapath.ofproto_parser.OFPActionOutput(outport)]
                        self.add_flow(datapath, match, actions)
                        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id = ofproto.OFP_NO_BUFFER, in_port = ofproto.OFPP_CONTROLLER, actions=actions, data=msg.data)
                        datapath.send_msg(out)
                        return
                elif "192.168.1." in ip_pkt.dst:
                        print("Router s1a -> packet from: ",ip_pkt.src," -- to: ", ip_pkt.dst)
                        if ip_pkt.dst == "192.168.1.2":
                                newSrcMac = "00:00:00:00:01:01"
                                newDstMac = "00:00:00:00:01:02"
                                outport = 2
                        elif ip_pkt.dst == "192.168.1.3":
                                newSrcMac = "00:00:00:00:01:01"
                                newDstMac = "00:00:00:00:01:03"
                                outport = 2
                        else:
                                return

                        match = datapath.ofproto_parser.OFPMatch(in_port=1, nw_dst=ip_pkt.dst, dl_type=0x0800)
                        actions =[datapath.ofproto_parser.OFPActionSetDlSrc(newSrcMac),datapath.ofproto_parser.OFPActionSetDlDst(newDstMac), datapath.ofproto_parser.OFPActionOutput(outport)]
                        self.add_flow(datapath, match, actions)
                        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id = ofproto.OFP_NO_BUFFER, in_port = ofproto.OFPP_CONTROLLER,actions=actions, data=msg.data)
                        datapath.send_msg(out)
                        return
                else:
                        print("UNKOWN DESTINATION -> ", ip_pkt.dst)
                        newSrcMac = "00:00:00:00:01:01"
                        outport = msg.in_port

                        fail_ping = packet.Packet()
                        fail_ping.add_protocol(ethernet.ethernet(dst = src, src = newSrcMac, ethertype = ethertype))
                        fail_ping.add_protocol(ipv4.ipv4(proto=ip_pkt.proto, src="192.168.1.1", dst=ip_pkt.src))
                        ip_datagram = msg.data[14:]
                        fail_ping.add_protocol(icmp.icmp(type_=3, code=1,csum=0,data=icmp.dest_unreach(data = ip_datagram)))
                        fail_ping.serialize()

                        actions =[datapath.ofproto_parser.OFPActionOutput(outport)]
                        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id = ofproto.OFP_NO_BUFFER, in_port = ofproto.OFPP_CONTROLLER,actions=actions, data=fail_ping.data)
                        datapath.send_msg(out)
                        return
        if dpid == 0x1B:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                """
                fill in the code here
                """
                arp_pkt = pkt.get_protocol(arp.arp)
                if arp_pkt.opcode == 1 and arp_pkt.dst_ip == "192.168.2.1":
                    self.arpReply(datapath, eth.src, eth.dst, arp_pkt.src_ip, arp_pkt.dst_ip, msg.in_port)
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                """
                fill in the code here
                """

                ip_pkt = pkt.get_protocol(ipv4.ipv4)

                if "192.168.1." in ip_pkt.dst:
                        print("Router s1b -> packet from: ",ip_pkt.src," -- to: ", ip_pkt.dst)
                        newSrcMac = "00:00:00:00:03:02"
                        newDstMac = "00:00:00:00:03:01"
                        outport = 1

                        match = datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_dst_mask= 24, nw_dst = "192.168.1.0", nw_tos = 0)
                        actions =[datapath.ofproto_parser.OFPActionSetDlSrc(newSrcMac),datapath.ofproto_parser.OFPActionSetDlDst(newDstMac), datapath.ofproto_parser.OFPActionOutput(outport)]
                        self.add_flow(datapath, match, actions)
                        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id = ofproto.OFP_NO_BUFFER, in_port = ofproto.OFPP_CONTROLLER,actions=actions, data=msg.data)
                        datapath.send_msg(out)
                        return
                elif "192.168.2." in ip_pkt.dst:
                        print("Router s1b -> packet from: ",ip_pkt.src," -- to: ", ip_pkt.dst)
                        if ip_pkt.dst == "192.168.2.2":
                                newSrcMac = "00:00:00:00:02:01"
                                newDstMac = "00:00:00:00:02:02"
                                outport = 2
                        elif ip_pkt.dst == "192.168.2.3":
                                newSrcMac = "00:00:00:00:02:01"
                                newDstMac = "00:00:00:00:02:03"
                                outport = 2
                        else:
                                return

                        match = datapath.ofproto_parser.OFPMatch(in_port=1, nw_dst=ip_pkt.dst, dl_type=0x0800)
                        actions =[datapath.ofproto_parser.OFPActionSetDlSrc(newSrcMac),datapath.ofproto_parser.OFPActionSetDlDst(newDstMac), datapath.ofproto_parser.OFPActionOutput(outport)]
                        self.add_flow(datapath, match, actions)
                        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id = ofproto.OFP_NO_BUFFER, in_port = ofproto.OFPP_CONTROLLER,actions=actions, data=msg.data)
                        datapath.send_msg(out)
                        return
                else:
                        print("UNKOWN DESTINATION -> ", ip_pkt.dst)
                        newSrcMac = "00:00:00:00:02:01"
                        outport = msg.in_port

                        fail_ping = packet.Packet()
                        fail_ping.add_protocol(ethernet.ethernet(dst = src, src = newSrcMac, ethertype = ethertype))
                        fail_ping.add_protocol(ipv4.ipv4(proto=ip_pkt.proto, src="192.168.2.1", dst=ip_pkt.src))
                        ip_datagram = msg.data[14:]
                        fail_ping.add_protocol(icmp.icmp(type_=3, code=1,csum=0,data=icmp.dest_unreach(data = ip_datagram)))
                        fail_ping.serialize()

                        actions =[datapath.ofproto_parser.OFPActionOutput(outport)]
                        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id = ofproto.OFP_NO_BUFFER, in_port = ofproto.OFPP_CONTROLLER,actions=actions, data=fail_ping.data)
                        datapath.send_msg(out)
                        return
                return

        if dpid == 0x2 or dpid == 0x3:
            if dpid == 0x2:
                Access_Links = switch1_accessLinks
            if dpid == 0x3:
                Access_Links = switch2_accessLinks

            if msg.in_port == truncport:
                if eth.ethertype == ether_types.ETH_TYPE_8021Q:
                    vlan_header = pkt.get_protocol(vlan.vlan)
                    v_id = vlan_header.vid

                    if v_id == 100:
                    	vlanId = vlan100
                    elif v_id == 200:
                        vlanId = vlan200

                    self.mac_to_port[dpid][vlanId][src] = msg.in_port
                    if dst in self.mac_to_port[dpid][vlanId]:
                        out_port = self.mac_to_port[dpid][vlanId][dst]
                        match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_vlan=v_id, dl_dst=haddr_to_bin(dst))
                        actions = [datapath.ofproto_parser.OFPActionStripVlan(), datapath.ofproto_parser.OFPActionOutput(out_port)]
                        self.add_flow(datapath, match, actions)
                        self.sendPacketOut(msg, actions, datapath, ofproto)
                    else:
                        actions = [datapath.ofproto_parser.OFPActionStripVlan()]
                        for portNum in Access_Links[vlanId]:
                            actions.append(datapath.ofproto_parser.OFPActionOutput(portNum))
                        self.sendPacketOut(msg, actions, datapath, ofproto)

            else:
                if msg.in_port in Access_Links[vlan100]:
                    vlanId = vlan100
                elif msg.in_port in Access_Links[vlan200]:
                    vlanId = vlan200

                self.mac_to_port[dpid][vlanId][src] = msg.in_port
                if dst in self.mac_to_port[dpid][vlanId]:
                    out_port = self.mac_to_port[dpid][vlanId][dst]
                    match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                    if out_port == truncport:
                        actions = [datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=vlanId), datapath.ofproto_parser.OFPActionOutput(out_port)]
                    else:
                        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                    self.add_flow(datapath, match, actions)
                    self.sendPacketOut(msg, actions, datapath, ofproto)
                else:
                    actions = []
                    for portNum in Access_Links[vlanId]:
                        if portNum != msg.in_port:
                            actions.append(datapath.ofproto_parser.OFPActionOutput(portNum))
                    actions.append(datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=vlanId))
                    actions.append(datapath.ofproto_parser.OFPActionOutput(truncport))
                    self.sendPacketOut(msg, actions, datapath, ofproto)

            return
    """
    fill in the code here for the ARP reply functions.
    """
    def arpReply(self, datapath, src_mac, dst_mac, src_ip, dst_ip, in_port):
        ofproto = datapath.ofproto

        if dst_ip == "192.168.1.1":
                newSrcMac = "00:00:00:00:01:01"
                newSrcIp = "192.168.1.1"
        else:
                newSrcMac = "00:00:00:00:02:01"
                newSrcIp = "192.168.2.1"
        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(dst = src_mac, src = newSrcMac, ethertype = ether.ETH_TYPE_ARP))
        arp_reply.add_protocol(arp.arp(hwtype = 1, proto = 0x0800, hlen = 6, plen = 4, opcode = 2, src_mac = newSrcMac, src_ip = newSrcIp,
                dst_ip = src_ip))
        arp_reply.serialize()
        out_port = in_port
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id = ofproto.OFP_NO_BUFFER, in_port = ofproto.OFPP_CONTROLLER,actions=actions, data=arp_reply.data)
        datapath.send_msg(out)
        return

    def sendPacketOut(self, msg, actions, datapath, ofproto):
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,actions=actions, data=data)
        datapath.send_msg(out)
        return

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)

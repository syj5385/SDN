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

from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types, in_proto
from ryu.lib.packet import ipv6, icmpv6, icmp, ipv4, tcp
from ryu.lib.packet import arp


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'dpset':dpset.DPSet}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
	self.dpset = kwargs['dpset']

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

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

    def classify_packet(pkt):
        classified = 0
        
        # Classification of traffic
        
        return clssified
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)

	icmp_pkt = pkt.get_protocols(icmp.icmp)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
	icmpv6_pkt = pkt.get_protocols(icmpv6.icmpv6)
	ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
	tcp_pkt = pkt.get_protocols(tcp.tcp)


	if eth.ethertype == ether_types.ETH_TYPE_ARP:
	    self.logger.info("ARP packet")
#reply = self.handle_arp_request(msg, datapath, in_port, pkt, eth)
	    if in_port == 1:
	        out_port = 2
	    elif in_port == 2:
	        out_port = 1
 	    actions = [parser.OFPActionOutput(out_port)]

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
               data = msg.data

	    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, eth_src=eth.src, eth_dst=eth.dst )
            self.add_flow(datapath, 1, match, actions)
            out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
	    return

	elif len(icmpv6_pkt) > 0:
	    # ignore ipv6 packet
	    #self.logger.info("ignore ipv6 packet")
	    return

	elif len(icmp_pkt) > 0:
	   self.logger.info("ICMP packet" )

	   if datapath.id == 1 or datapath.id == 2:
	       self.logger.info("gateway")
	       if in_port == 1:
	           out_port = 4
	       elif in_port == 4:
	           out_port = 1
	   else :
	       if in_port == 1:
	  	   out_port = 2
	       elif in_port == 2:
	           out_port = 1
	
 	   actions = [parser.OFPActionOutput(out_port)]
	   match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ipv4_pkt.src, ipv4_dst=ipv4_pkt.dst, ip_proto=in_proto.IPPROTO_ICMP)
	   self.add_flow(datapath, 1, match, actions)

           data = None
           if msg.buffer_id == ofproto.OFP_NO_BUFFER:
               data = msg.data

           out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
           datapath.send_msg(out)
 	   self.logger.info("Switch %d: %d -> %d", datapath.id, in_port, out_port)
	   return
    
    class_of_traffic = classify_packet(pkt)
	if len(tcp_pkt) > 0:
	    t = pkt.get_protocol(tcp.tcp)
	    self.logger.info("[TCP Packet >> Class: %d] Src: %s:%d, DstIP: %s:%d", class_of_traffic,ipv4_pkt.src, t.src_port, ipv4_pkt.dst, t.dst_port)
	    if datapath.id == 1 or datapath.id == 2:
            if in_port == 1: # outbound traffic
                if class_of_traffic == 0:
                    out_port = 2 # default network
                else:
                    out_port = class_of_traffic + 1
            else: #inbound traffic
                out_port = 1

            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ipv4_pkt.src, ipv4_dst=ipv4_pkt.dst, ip_proto=in_proto.IPPROTO_TCP, tcp_src=t.src_port, tcp_dst=t.dst_port)
            self.add_flow(datapath, 1, match, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)
            return

	ipv6_pkt = pkt.get_protocols(ipv6.ipv6)
	if len(ipv6_pkt) > 0:
	    # ignore ipv6 packet
	    #self.logger.info("ignore ipv6 packet")
	    return
	if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
	    return

	self.logger.info("I dont know")
        dst = eth.dst
        src = eth.src

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

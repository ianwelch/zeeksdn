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
An OpenFlow 1.0 L2 learning switch implementation.
"""

#Commented by Ben Cravens


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

#implements a switch class
class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    #constructor method
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        #dictionary associating MAC addresses to interfaces
        #essentially a "in class" switch table
        self.mac_to_port = {}

    #adds a "flow" (an entry in a switch table associating a MAC address with an
    #output interface
    def add_flow(self, datapath, in_port, dst, src, actions):
        #get protocol (here this is openflow)
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port,
            dl_dst=haddr_to_bin(dst), dl_src=haddr_to_bin(src))

        #make flow modification (switch table modification) message
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        #send to the switch
        datapath.send_msg(mod)

    #This function is called when EventOFPPacketIn is the case (a packet has come in)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        #the message / packet data structure
        msg = ev.msg
        #the switch (here called a datapath)
        datapath = msg.datapath
        #the protocol
        ofproto = datapath.ofproto

        #packet contents
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        #make an empty entry in the switch table dictionary for this interface ID
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        #Task 1: block traffic between host 2 and host 3.
        print("destination MAC: {}".format(dst))
        print("source MAC: {}".format(src))

        # Associate the mac address with the interface in the table
        # to avoid broadcasting the packet next time.
        self.mac_to_port[dpid][src] = msg.in_port

        #if our destination is in the switch table
        if dst in self.mac_to_port[dpid]:
            #send our packet out of that interface
            out_port = self.mac_to_port[dpid][dst]
        else:
            #otherwise behave like a hub (broadcast)
            out_port = ofproto.OFPP_FLOOD

        #define port to send the packet to
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid broadcasting next time
        # in other words, modify the switch table on the actual switch
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, src, actions)

        data = None
        #don't send the packet if it is already stored in the switch's buffer
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        #prepare the packet to be forwarded to the switch
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        #forward packet to switch with forwarding instructions
        datapath.send_msg(out)

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

#!/usr/bin/env python3
"""
arp_monitor.py - Ryu app phát hiện ARP Spoofing
Chạy: ryu-manager arp_monitor.py ryu.app.ofctl_rest
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp
from datetime import datetime


# Bảng MAC-IP tin cậy (từ topology.py)
TRUSTED = {
    "10.0.0.1": "00:00:00:00:00:01",
    "10.0.0.11": "00:00:00:00:00:11",
    "10.0.0.12": "00:00:00:00:00:12",
    "10.0.0.13": "00:00:00:00:00:13",
    "10.0.0.14": "00:00:00:00:00:14",
    "10.0.0.15": "00:00:00:00:00:15",
    "10.0.0.21": "00:00:00:00:00:21",
    "10.0.0.22": "00:00:00:00:00:22",
    "10.0.0.23": "00:00:00:00:00:23",
    "10.0.0.24": "00:00:00:00:00:24",
    "10.0.0.25": "00:00:00:00:00:25",
    "10.0.0.26": "00:00:00:00:00:26",
    "10.0.0.27": "00:00:00:00:00:27",
    "10.0.0.28": "00:00:00:00:00:28",
    "10.0.0.29": "00:00:00:00:00:29",
    "10.0.0.30": "00:00:00:00:00:30",
}

alerts = []


class ARPMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ARPMonitor, self).__init__(*args, **kwargs)
        self.logger.info("ARP Monitor started - Trusted bindings loaded")

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table miss flow: gửi packets unknown đến controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                         ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch %s connected - Table miss flow installed", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        pkt = packet.Packet(ev.msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth and eth.ethertype == 0x0806:
            self.handle_arp(pkt)

    def handle_arp(self, pkt):
        arp_pkt = pkt.get_protocol(arp.arp)
        if not arp_pkt:
            return

        src_ip = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac

        trusted_mac = TRUSTED.get(src_ip)

        if trusted_mac and src_mac.lower() != trusted_mac.lower():
            alert = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "ARP_SPOOFING",
                "src_ip": src_ip,
                "src_mac": src_mac,
                "trusted_mac": trusted_mac,
            }
            alerts.append(alert)
            self.logger.warning(f"ARP Spoofing: {alert}")

    def get_alerts(self):
        return alerts

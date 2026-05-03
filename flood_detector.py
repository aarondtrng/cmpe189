from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4

import json
import urllib.request
import urllib.error
import time

FIREWALL_API = "http://127.0.0.1:8080/firewall/rules/all"
POLL_INTERVAL = 5        
PACKET_THRESHOLD = 1000      

class FloodDetector(app_manager.RyuApp):
    """
    Detects floods attacks by counting PacketIn events per source IP.
    Every POLL_INTERVAL seconds, any source IP that exceeded PACKET_THRESHOLD
    packets in that window is automatically blocked by rest_firewall REST API.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FloodDetector, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.blocked_ips = set()

        # packet counter: {src_ip: count} for current window
        self.packet_counts = {}
        self.window_start = time.time()

        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def state_change_handler(self, ev):
        """
        Fires when a switch connects or disconnects.
        Tracks connected switches to know which datapaths
        are active.
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info("Switch connected: dpid=%s", datapath.id)
        elif ev.state == CONFIG_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info("Switch disconnected: dpid=%s", datapath.id)

    def _monitor(self):
        """
        Sleeps for POLL_INTERVAL seconds, then checks if any source IP
        exceeded the packet threshold in that window. After checking,
        resets counter dict and window timestamp for the next interval.
        """
        while True:
            hub.sleep(POLL_INTERVAL)
            self._check_for_floods()
            self.packet_counts = {}
            self.window_start = time.time()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Fires whenever the switch sends a packet to controller.
        Parse the ipv4 layer to get the source IP and increment
        its counter.
        """
        msg = ev.msg
        pkt = packet.Packet(msg.data)

        # Only process IPv4 packets
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            return
        
        src_ip = ip_pkt.src
        if src_ip in self.blocked_ips:
            return
        
        # Increment counter for this source IP
        self.packet_counts[src_ip] = self.packet_counts.get(src_ip, 0) + 1

    def _check_for_floods(self, current_counts):
        """
        Called at the end of each POLL_INTERVAL window.
        Iterates through all source IPs seen in this window
        and checks if any exceeded PACKET_THRESHOLD.
        """
        for src_ip, count in self.packet_counts.items():
            if src_ip in self.blocked_ips:
                continue
            if count > PACKET_THRESHOLD:
                self.logger.warning(
                    "[WARNING] FLOOD DETECTED: src=%s sent %d packets in %ds",
                    src_ip, count, POLL_INTERVAL
                )
                self._install_deny_rule(src_ip)

    def _install_deny_rule(self, src_ip):
        """
        Calls rest_firewall REST API to install a DENY rule
        for the offending source IP.
        """
        if src_ip in self.blocked_ips:
            return
        
        body = {
            "nw_src": f"{src_ip}/32",
            "dl_type": "IPv4",
            "actions": "DENY",
            "priority": "9"
        }

        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            FIREWALL_API,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                result = resp.read().decode("utf-8")
                self.logger.info(
                    "Blocked flood source %s: %s", src_ip, result
                )
                self.blocked_ips.add(src_ip)
        except urllib.error.HTTPError as e:
            self.logger.error("Firewall API error: %s", e.read().decode())
        except Exception as e:
            self.logger.error("Failed to install deny rule: %s", e)

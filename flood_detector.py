from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4

import json
import urllib.request
import urllib.error

FIREWALL_API = "http://127.0.0.1:8080/firewall/all"
POLL_INTERVAL = 5        
PACKET_THRESHOLD = 100      

class FloodDetector(app_manager.RyuApp):
    """
    Polls OF flow stats every POLL_INTERVAL seconds.
    If any source IP exceeds PACKET_THRESHHOLD in that
    window, a DENY rule is installed by rest_firewall.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FloodDetector, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.last_packet_counts = {}
        self.blocked_ips = set()
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def state_change_handler(self, ev):
        """
        Fires when a switch connects or disconnects.
        Allows to track connected switches so we know
        who to request stats from.
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
        Runs forever in the background.
        Every POLL_INTERVAL seconds, asks each switch for flow stats.
        """
        while True:
            for dp in self.datapaths.values():
                self._request_flow_stats(dp)
            hub.sleep(POLL_INTERVAL)

    def _request_flow_stats(self, datapath):
        """
        Sends an OF FlowStatsRequest to the switch.
        The switch will reply with an EventOFPFlowStatsReply event.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(
            datapath, 
            table_id=ofproto.OFPTT_ALL
            )
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """
        Fires when the switch responds to the stats request.
        Loop through every flow entry and accumulate packet
        counts grouped by source IP.
        """
        body = ev.msg.body
        current_counts = {}

        for stat in body:
            src_ip = stat.match.get('ipv4_src')
            if src_ip is None:
                continue
            
            current_counts[src_ip] = (
                current_counts.get(src_ip, 0) + stat.packet_count
            )

        self._check_for_floods(current_counts)
        self.last_packet_counts = current_counts

    def _check_for_floods(self, current_counts):
        """
        Compares current packet counts to last poll.
        If the increase (delta) exceeds PACKET_THRESHOLD, block the IP.
        """
        for src_ip, count in current_counts.items():
            if src_ip in self.blocked_ips:
                continue

            last_count = self.last_packet_counts.get(src_ip, 0)
            delta = count - last_count  # packets sent in this interval

            if delta > PACKET_THRESHOLD:
                self.logger.warning(
                    "FLOOD DETECTED: src=%s sent %d packets in %ds",
                    src_ip, delta, POLL_INTERVAL
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

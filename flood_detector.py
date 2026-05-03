# Poll OpenFlow flow stats; if a source IPv4 sends too many packets per interval, DENY via rest_firewall.
# Counts only flows that include IPv4 source in the match (nw_src / ipv4_src) — e.g. rest_firewall or L3 flows.
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

import json
import socket
import struct
import urllib.error
import urllib.request

# Same path as manage_firewall / malicious_port_detector (rest_firewall POST rules).
FIREWALL_API = "http://127.0.0.1:8080/firewall/rules/all"
POLL_INTERVAL = .1
PACKET_THRESHOLD = 1
# Above rest_firewall default IPv4 permit (2); below typical PACKETIN (3500).
_DENY_PRIORITY = "4500"


def _normalize_ipv4_src(match):
    # Ryu flow-stats matches use nw_src and/or ipv4_src depending on version/path.
    raw = None
    if match is not None:
        raw = match.get("nw_src") or match.get("ipv4_src")
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw.split("/")[0].strip()
    if isinstance(raw, int):
        try:
            return socket.inet_ntoa(struct.pack("!I", raw & 0xFFFFFFFF))
        except (struct.error, OverflowError):
            return None
    return None


class FloodDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FloodDetector, self).__init__(*args, **kwargs)
        self.datapaths = {}
        # Per-switch snapshot of cumulative packet counts per source IP (last poll).
        self._last_src_counts = {}
        # Skip flood logic until we have one baseline sample per switch (avoid startup spike).
        self._baseline_done = set()
        self.blocked_ips = set()
        hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info("Switch connected: dpid=%s", datapath.id)
        elif ev.state == CONFIG_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self._last_src_counts.pop(datapath.id, None)
                self._baseline_done.discard(datapath.id)
                self.logger.info("Switch disconnected: dpid=%s", datapath.id)

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_flow_stats(dp)
            hub.sleep(POLL_INTERVAL)

    def _request_flow_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath, table_id=ofproto.OFPTT_ALL)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        current = {}

        for stat in ev.msg.body:
            src_ip = _normalize_ipv4_src(stat.match)
            if src_ip is None:
                continue
            current[src_ip] = current.get(src_ip, 0) + stat.packet_count

        if dpid not in self._baseline_done:
            self._last_src_counts[dpid] = current
            self._baseline_done.add(dpid)
            return

        last = self._last_src_counts.get(dpid, {})
        self._check_for_floods(current, last)
        self._last_src_counts[dpid] = current

    def _check_for_floods(self, current_counts, last_counts):
        for src_ip, count in current_counts.items():
            if src_ip in self.blocked_ips:
                continue

            last_count = last_counts.get(src_ip, 0)
            delta = count - last_count
            if delta < 0:
                # Flows reset or counter wrap; treat as zero growth for this window.
                delta = 0

            if delta > PACKET_THRESHOLD:
                self.logger.warning(
                    "FLOOD DETECTED: src=%s sent %d packets in ~%ds",
                    src_ip,
                    delta,
                    POLL_INTERVAL,
                )
                self._install_deny_rule(src_ip)

    def _install_deny_rule(self, src_ip):
        if src_ip in self.blocked_ips:
            return

        body = {
            "priority": _DENY_PRIORITY,
            "nw_src": "%s/32" % src_ip,
            "dl_type": "IPv4",
            "actions": "DENY",
        }

        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            FIREWALL_API,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                result = resp.read().decode("utf-8")
                self.logger.info("Blocked flood source %s: %s", src_ip, result)
                self.blocked_ips.add(src_ip)
        except urllib.error.HTTPError as e:
            self.logger.error("Firewall API error: %s", e.read().decode())
        except Exception as e:
            self.logger.error("Failed to install deny rule: %s", e)

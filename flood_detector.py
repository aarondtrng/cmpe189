# Flow + port stats -> rest_firewall DENY on spike; one in_port per poll; optional timed DELETE (AUTO_UNBLOCK_SECONDS).
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

import json
import re
import socket
import struct
import urllib.error
import urllib.request

FIREWALL_API = "http://127.0.0.1:8080/firewall/rules/all"
POLL_INTERVAL = 1
PACKET_THRESHOLD = 100
_DENY_PRIORITY = "4500"
# 0 = keep DENY; else DELETE that rule after N seconds.
AUTO_UNBLOCK_SECONDS = 10


def _normalize_ip(raw):
    if raw is None:
        return None
    if isinstance(raw, str):
        s = raw.split("/")[0].strip()
        return s if s else None
    if isinstance(raw, int):
        try:
            return socket.inet_ntoa(struct.pack("!I", raw & 0xFFFFFFFF))
        except (struct.error, OverflowError):
            return None
    return None


def _identity_from_match(match):
    if match is None:
        return None
    ip = _normalize_ip(match.get("nw_src") or match.get("ipv4_src"))
    if ip:
        return ("ip", ip)
    in_port = match.get("in_port")
    if in_port is not None and in_port != 0:
        return ("in_port", str(int(in_port)))
    dl_src = match.get("dl_src") or match.get("eth_src")
    if dl_src:
        mac = str(dl_src).replace("-", ":").lower()
        if mac != "00:00:00:00:00:00":
            return ("dl_src", mac)
    return None


def _blocked_key(kind, value):
    return "%s:%s" % (kind, value)


def _port_packet_total(stat):
    rx = int(getattr(stat, "rx_packets", 0) or 0)
    tx = int(getattr(stat, "tx_packets", 0) or 0)
    if rx == 0 and tx == 0 and hasattr(stat, "packet_count"):
        return int(stat.packet_count or 0)
    return rx + tx


def _extract_rule_id_from_post_response(text):
    m = re.search(r"rule_id=(\d+)", text)
    if m:
        return int(m.group(1))
    return None


class FloodDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FloodDetector, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.blocked_keys = set()
        self._last_flow_totals = {}
        self._flow_baseline_done = set()
        self._last_port_totals = {}
        self._port_baseline_done = set()
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
                self._last_flow_totals.pop(datapath.id, None)
                self._flow_baseline_done.discard(datapath.id)
                self._last_port_totals.pop(datapath.id, None)
                self._port_baseline_done.discard(datapath.id)
                self.logger.info("Switch disconnected: dpid=%s", datapath.id)

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_flow_stats(dp)
                self._request_port_stats(dp)
            hub.sleep(POLL_INTERVAL)

    def _request_flow_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath, table_id=ofproto.OFPTT_ALL)
        datapath.send_msg(req)

    def _request_port_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        current = {}

        for stat in ev.msg.body:
            ident = _identity_from_match(stat.match)
            if ident is None:
                continue
            k = _blocked_key(ident[0], ident[1])
            current[k] = current.get(k, 0) + stat.packet_count

        if dpid not in self._flow_baseline_done:
            self._last_flow_totals[dpid] = current
            self._flow_baseline_done.add(dpid)
            return

        last = self._last_flow_totals.get(dpid, {})
        self._check_for_floods(current, last)
        self._last_flow_totals[dpid] = current

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        ofproto = ev.msg.datapath.ofproto
        current = {}

        for stat in ev.msg.body:
            pno = stat.port_no
            if pno == 0 or pno >= ofproto.OFPP_MAX:
                continue
            total = _port_packet_total(stat)
            k = _blocked_key("in_port", str(int(pno)))
            current[k] = total

        if dpid not in self._port_baseline_done:
            self._last_port_totals[dpid] = current
            self._port_baseline_done.add(dpid)
            return

        last = self._last_port_totals.get(dpid, {})
        self._check_for_floods(current, last)
        self._last_port_totals[dpid] = current

    def _gather_flood_violations(self, current_totals, last_totals):
        # Only one in_port offender per poll (largest delta); ip/dl_src can each still trip.
        violations = []
        port_candidates = []

        for key, count in current_totals.items():
            if key in self.blocked_keys:
                continue
            last_count = last_totals.get(key, 0)
            delta = count - last_count
            if delta < 0:
                delta = 0
            if delta <= PACKET_THRESHOLD:
                continue
            if key.startswith("in_port:"):
                port_candidates.append((key, delta))
            else:
                violations.append((key, delta))

        if port_candidates:
            worst_key, worst_delta = max(port_candidates, key=lambda x: x[1])
            violations.append((worst_key, worst_delta))

        return violations

    def _check_for_floods(self, current_totals, last_totals):
        for key, delta in self._gather_flood_violations(current_totals, last_totals):
            self.logger.warning(
                "FLOOD DETECTED: key=%s delta=%d packets in ~%ds",
                key,
                delta,
                POLL_INTERVAL,
            )
            self._install_deny_rule(key)

    def _install_deny_rule(self, key):
        if key in self.blocked_keys:
            return
        kind, sep, value = key.partition(":")
        if sep != ":" or not value:
            self.logger.error("Bad flood key: %s", key)
            return

        if kind == "ip":
            body = {
                "priority": _DENY_PRIORITY,
                "nw_src": "%s/32" % value,
                "dl_type": "IPv4",
                "actions": "DENY",
            }
        elif kind == "in_port":
            body = {
                "priority": _DENY_PRIORITY,
                "dl_type": "IPv4",
                "in_port": value,
                "actions": "DENY",
            }
        elif kind == "dl_src":
            body = {
                "priority": _DENY_PRIORITY,
                "dl_type": "IPv4",
                "dl_src": value,
                "actions": "DENY",
            }
        else:
            self.logger.error("Unknown flood key kind: %s", kind)
            return

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
                self.logger.info("Blocked flood source %s: %s", key, result)
                self.blocked_keys.add(key)
                rid = _extract_rule_id_from_post_response(result)
                if AUTO_UNBLOCK_SECONDS and rid is not None:
                    hub.spawn(self._auto_unblock_rule, key, rid)
        except urllib.error.HTTPError as e:
            self.logger.error("Firewall API error: %s", e.read().decode())
        except Exception as e:
            self.logger.error("Failed to install deny rule: %s", e)

    def _delete_firewall_rule(self, rule_id):
        body = json.dumps({"rule_id": str(rule_id)}).encode("utf-8")
        req = urllib.request.Request(
            FIREWALL_API,
            data=body,
            headers={"Content-Type": "application/json"},
            method="DELETE",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def _auto_unblock_rule(self, blocked_key, rule_id):
        hub.sleep(AUTO_UNBLOCK_SECONDS)
        if blocked_key not in self.blocked_keys:
            return
        try:
            out = self._delete_firewall_rule(rule_id)
            self.blocked_keys.discard(blocked_key)
            self.logger.info(
                "Auto-unblocked %s (deleted rule_id=%s): %s",
                blocked_key,
                rule_id,
                out[:200],
            )
        except urllib.error.HTTPError as e:
            self.logger.error(
                "Auto-unblock HTTP error rule_id=%s: %s", rule_id, e.read().decode()
            )
        except Exception as e:
            self.logger.error("Auto-unblock failed rule_id=%s: %s", rule_id, e)

# Bad-port PACKETIN + PacketIn -> DENY by nw_src. Optional ALLOW_TCP/UDP_PORTS bypass PACKETIN and DENY.
# Default IPv4 permit: PUT .../module/enable in rest_firewall.
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import hub

import json
import urllib.request
import urllib.error
from urllib.parse import urlparse

FIREWALL_API = "http://127.0.0.1:8080/firewall/rules/all"
_FIREWALL_PARSED = urlparse(FIREWALL_API)
FIREWALL_BASE = f"{_FIREWALL_PARSED.scheme}://{_FIREWALL_PARSED.netloc}"

# Priorities above default IPv4 permit (2). ALLOW > PACKETIN so whitelisted dst ports never hit the controller.
_BAD_PORT_PACKETIN_PRIORITY = "3500"
_ALLOW_PORT_PRIORITY = "4000"
_DENY_PRIORITY = "4500"

BAD_TCP_PORTS = {
    31, 1170, 1234, 1243, 1981, 2001, 2023, 2989, 3024,
    3150, 3700, 4950, 6346, 6400, 6667, 6670, 12345,
    12346, 16660, 20034, 20432, 27374, 27665, 30100,
    31337, 33270, 33567, 33568, 40421, 60008, 65000
}

BAD_UDP_PORTS = {
    2140, 18753, 20433, 27444, 31335
}

# Explicit ALLOW on tp_dst (any source). Use to keep ports open even if listed in BAD_* or for normal services.
ALLOW_TCP_PORTS = {1,100,400,800,}
ALLOW_UDP_PORTS = {12, 200,300,700,}


class BadPortDetector(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(BadPortDetector, self).__init__(*args, **kwargs)
        self.blocked_signatures = set()  # Dedupe DENY POSTs per (src, proto, port).
        self._baseline_done = False
        hub.spawn(self._firewall_baseline_worker)  # Enable firewall + PACKETIN rows when REST is up.

    # Single HTTP call to the firewall REST API (GET/PUT/POST).
    def _firewall_request(self, method, url, body=None, timeout=5.0):
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")

    # Return all ACL rules from GET /firewall/rules/all as one flat list.
    def _get_rules_flat(self):
        url = f"{FIREWALL_BASE}/firewall/rules/all"
        _, text = self._firewall_request("GET", url)
        data = json.loads(text)
        out = []
        for sw in data or []:
            for acl in sw.get("access_control_list", []):
                out.extend(acl.get("rules", []))
        return out

    def _firewall_baseline_worker(self):
        # WSGI may lag app load; retry until baseline succeeds.
        hub.sleep(2.5)
        attempt = 0
        while not self._baseline_done:
            attempt += 1
            try:
                self._try_install_firewall_baseline()
                self._baseline_done = True
                self.logger.info(
                    "Firewall baseline OK (attempt %d): allow + bad-port PACKETIN rules",
                    attempt,
                )
                return
            except Exception as e:
                self.logger.warning(
                    "Baseline attempt %d failed (retry): %s", attempt, e
                )
                hub.sleep(0.5)

    # Enable firewall (also installs default IPv4 permit in rest_firewall); add PACKETIN per bad port if missing.
    def _try_install_firewall_baseline(self):
        enable_url = f"{FIREWALL_BASE}/firewall/module/enable/all"
        self._firewall_request("PUT", enable_url)
        rules = self._get_rules_flat()

        def has_packetin(proto, port):
            ps = str(port)
            for r in rules:
                if r.get("actions") != "PACKETIN":
                    continue
                if r.get("dl_type") != "IPv4" or r.get("nw_proto") != proto:
                    continue
                if str(r.get("tp_dst", "")) == ps:
                    return True
            return False

        def has_allow_port(proto, port):
            ps = str(port)
            for r in rules:
                if r.get("actions") != "ALLOW":
                    continue
                if r.get("dl_type") != "IPv4" or r.get("nw_proto") != proto:
                    continue
                if str(r.get("tp_dst", "")) == ps:
                    return True
            return False

        for port in sorted(ALLOW_TCP_PORTS):
            if has_allow_port("TCP", port):
                continue
            self._send_rule(
                {
                    "priority": _ALLOW_PORT_PRIORITY,
                    "dl_type": "IPv4",
                    "nw_proto": "TCP",
                    "tp_dst": str(port),
                    "actions": "ALLOW",
                }
            )

        for port in sorted(ALLOW_UDP_PORTS):
            if has_allow_port("UDP", port):
                continue
            self._send_rule(
                {
                    "priority": _ALLOW_PORT_PRIORITY,
                    "dl_type": "IPv4",
                    "nw_proto": "UDP",
                    "tp_dst": str(port),
                    "actions": "ALLOW",
                }
            )

        for port in BAD_TCP_PORTS:
            if port in ALLOW_TCP_PORTS:
                continue
            if has_packetin("TCP", port):
                continue
            self._send_rule(
                {
                    "priority": _BAD_PORT_PACKETIN_PRIORITY,
                    "dl_type": "IPv4",
                    "nw_proto": "TCP",
                    "tp_dst": str(port),
                    "actions": "PACKETIN",
                }
            )

        for port in BAD_UDP_PORTS:
            if port in ALLOW_UDP_PORTS:
                continue
            if has_packetin("UDP", port):
                continue
            self._send_rule(
                {
                    "priority": _BAD_PORT_PACKETIN_PRIORITY,
                    "dl_type": "IPv4",
                    "nw_proto": "UDP",
                    "tp_dst": str(port),
                    "actions": "PACKETIN",
                }
            )

    # POST one ACL rule JSON to /firewall/rules/all.
    def _send_rule(self, body):
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            FIREWALL_API,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()

    # Install a high-priority DENY for this source IP and destination port (once per signature).
    def install_deny_rule(self, src_ip, proto, dst_port):
        signature = (src_ip, proto, dst_port)
        if signature in self.blocked_signatures:
            return

        nw = "TCP" if proto == "TCP" else "UDP"

        body = {
            "priority": _DENY_PRIORITY,
            "nw_src": f"{src_ip}/32",
            "dl_type": "IPv4",
            "nw_proto": nw,
            "tp_dst": str(dst_port),
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
                self.logger.info(
                    "Installed deny for %s from %s to port %s: %s",
                    nw,
                    src_ip,
                    dst_port,
                    result,
                )
                self.blocked_signatures.add(signature)
        except urllib.error.HTTPError as e:
            self.logger.error("Firewall API HTTP error: %s", e.read().decode())
        except Exception as e:
            self.logger.error("Failed to install deny rule: %s", e)

    # On PACKETIN, if TCP/UDP targets a bad port, log and trigger install_deny_rule for the source.
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)

        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt is None:
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            return

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if tcp_pkt:
            if tcp_pkt.dst_port in ALLOW_TCP_PORTS:
                return
            if tcp_pkt.dst_port in BAD_TCP_PORTS:
                self.logger.warning(
                    "Bad TCP port detected: src=%s dst=%s port=%s",
                    ip_pkt.src,
                    ip_pkt.dst,
                    tcp_pkt.dst_port,
                )
                self.install_deny_rule(ip_pkt.src, "TCP", tcp_pkt.dst_port)

        elif udp_pkt:
            if udp_pkt.dst_port in ALLOW_UDP_PORTS:
                return
            if udp_pkt.dst_port in BAD_UDP_PORTS:
                self.logger.warning(
                    "Bad UDP port detected: src=%s dst=%s port=%s",
                    ip_pkt.src,
                    ip_pkt.dst,
                    udp_pkt.dst_port,
                )
                self.install_deny_rule(ip_pkt.src, "UDP", udp_pkt.dst_port)

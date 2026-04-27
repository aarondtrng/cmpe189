from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp

import json
import urllib.request
import urllib.error

FIREWALL_API = "http://127.0.0.1:8080/firewall/rules/all"

BAD_TCP_PORTS = {
    31, 1170, 1234, 1243, 1981, 2001, 2023, 2989, 3024,
    3150, 3700, 4950, 6346, 6400, 6667, 6670, 12345,
    12346, 16660, 20034, 20432, 27374, 27665, 30100,
    31337, 33270, 33567, 33568, 40421, 60008, 65000
}

BAD_UDP_PORTS = {
    2140, 18753, 20433, 27444, 31335
}


class BadPortDetector(app_manager.RyuApp):
    """
    Detects traffic to known suspicious TCP/UDP ports and installs
    DENY rules through rest_firewall.
    """

    def __init__(self, *args, **kwargs):
        super(BadPortDetector, self).__init__(*args, **kwargs)
        self.blocked_signatures = set()

    def install_deny_rule(self, src_ip, proto, dst_port):
        """
        Add a deny rule through Ryu rest_firewall.
        """
        signature = (src_ip, proto, dst_port)
        if signature in self.blocked_signatures:
            return

        body = {
            "nw_src": f"{src_ip}/32",
            "dl_type": "IPv4",
            "nw_proto": proto,
            "tp_dst": str(dst_port),
            "actions": "DENY"
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
                    "Installed deny rule for %s traffic from %s to port %s: %s",
                    proto, src_ip, dst_port, result
                )
                self.blocked_signatures.add(signature)
        except urllib.error.HTTPError as e:
            self.logger.error("Firewall API HTTP error: %s", e.read().decode())
        except Exception as e:
            self.logger.error("Failed to install deny rule: %s", e)

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
            if tcp_pkt.dst_port in BAD_TCP_PORTS:
                self.logger.warning(
                    "Bad TCP port detected: src=%s dst=%s port=%s",
                    ip_pkt.src, ip_pkt.dst, tcp_pkt.dst_port
                )
                self.install_deny_rule(ip_pkt.src, "TCP", tcp_pkt.dst_port)

        elif udp_pkt:
            if udp_pkt.dst_port in BAD_UDP_PORTS:
                self.logger.warning(
                    "Bad UDP port detected: src=%s dst=%s port=%s",
                    ip_pkt.src, ip_pkt.dst, udp_pkt.dst_port
                )
                self.install_deny_rule(ip_pkt.src, "UDP", udp_pkt.dst_port)
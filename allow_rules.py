from ryu.base import app_manager
from ryu.lib import hub

import json
import urllib.request
import urllib.error

FIREWALL_API = "http://127.0.0.1:8080/firewall/rules/all"

# Define your trusted allow rules here
ALLOW_RULES = [
    {"dl_type": "IPv4", "nw_proto": "ICMP", "actions": "ALLOW", "priority": "100"},
    {"dl_type": "IPv4", "nw_proto": "TCP", "actions": "ALLOW", "priority": "50"},
    {"dl_type": "IPv4", "nw_proto": "UDP", "actions": "ALLOW", "priority": "50"},
]

class AllowRules(app_manager.RyuApp):
    """
    Installs baseline allow rules via rest_firewall on startup.
    Runs after port_blocker has installed its DENY rules so
    allow rules can coexist cleanly with the bad port blocks.
    """

    def __init__(self, *args, **kwargs):
        super(AllowRules, self).__init__(*args, **kwargs)
        hub.spawn(self._install_allow_rules)

    def _install_allow_rules(self):
        hub.sleep(5)  # wait for port_blocker baseline to finish
        for rule in ALLOW_RULES:
            self._post_rule(rule)

    def _post_rule(self, body):
        try:
            data = json.dumps(body).encode("utf-8")
            req = urllib.request.Request(
                FIREWALL_API,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                self.logger.info("Allow rule installed: %s", 
                               resp.read().decode("utf-8"))
        except Exception as e:
            self.logger.error("Failed to install allow rule: %s", e)

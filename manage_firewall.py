#!/usr/bin/env python3
"""
HTTP client for Ryu's built-in rest_firewall REST API.

Field names match ryu.app.rest_firewall (same as rest_firewall.py in this repo):
  priority, in_port, dl_src, dl_dst, dl_type, nw_src, nw_dst,
  ipv6_src, ipv6_dst, nw_proto (TCP|UDP|ICMP|ICMPv6), tp_src, tp_dst,
  actions (ALLOW|DENY|PACKETIN)

Examples:
  python3 manage_firewall.py add --allow --dl-type IPv4 --nw-src 10.0.0.1/32 --priority 10
  python3 manage_firewall.py add --deny --dl-type IPv4 --dl-src 00:00:00:00:00:01 --priority 20
  python3 manage_firewall.py add --deny --dl-type IPv4 --nw-proto TCP --tp-dst 31337 --priority 30
  python3 manage_firewall.py list
  python3 manage_firewall.py delete --rule-id all
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

DEFAULT_BASE = "http://127.0.0.1:8080"
DEFAULT_RULES_PATH = "/firewall/rules/all"


def rules_url(base: str = DEFAULT_BASE, switch_id: str = "all") -> str:
    base = base.rstrip("/")
    return f"{base}/firewall/rules/{switch_id}"


def build_rule(
    *,
    action: str,
    priority: str | None = None,
    dl_type: str | None = None,
    nw_src: str | None = None,
    nw_dst: str | None = None,
    dl_src: str | None = None,
    dl_dst: str | None = None,
    ipv6_src: str | None = None,
    ipv6_dst: str | None = None,
    nw_proto: str | None = None,
    tp_src: str | int | None = None,
    tp_dst: str | int | None = None,
    in_port: str | int | None = None,
) -> dict:
    # Body keys match rest_firewall (dl_type, nw_src, nw_proto, tp_dst, actions, priority, ...).
    action = action.upper()
    if action not in ("ALLOW", "DENY", "PACKETIN"):
        raise ValueError("action must be ALLOW, DENY, or PACKETIN")

    body: dict = {"actions": action}

    if priority is not None:
        body["priority"] = str(priority)
    if dl_type is not None:
        body["dl_type"] = dl_type
    if nw_src is not None:
        body["nw_src"] = nw_src
    if nw_dst is not None:
        body["nw_dst"] = nw_dst
    if dl_src is not None:
        body["dl_src"] = dl_src
    if dl_dst is not None:
        body["dl_dst"] = dl_dst
    if ipv6_src is not None:
        body["ipv6_src"] = ipv6_src
    if ipv6_dst is not None:
        body["ipv6_dst"] = ipv6_dst
    if nw_proto is not None:
        body["nw_proto"] = nw_proto
    if tp_src is not None:
        body["tp_src"] = str(tp_src)
    if tp_dst is not None:
        body["tp_dst"] = str(tp_dst)
    if in_port is not None:
        body["in_port"] = str(in_port)

    return body


def http_request(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    timeout: float = 10.0,
) -> tuple[int, str]:
    # Returns (status, body); HTTP errors still return a body string.
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"} if data is not None else {},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        return e.code, err_body


def post_rule(body: dict, *, base: str = DEFAULT_BASE, switch_id: str = "all") -> tuple[int, str]:
    url = rules_url(base, switch_id)
    payload = json.dumps(body).encode("utf-8")
    return http_request(url, method="POST", data=payload)


def delete_rule(rule_id: str | int, *, base: str = DEFAULT_BASE, switch_id: str = "all") -> tuple[int, str]:
    url = rules_url(base, switch_id)
    body = json.dumps({"rule_id": str(rule_id)}).encode("utf-8")
    return http_request(url, method="DELETE", data=body)


def get_rules(*, base: str = DEFAULT_BASE, switch_id: str = "all") -> tuple[int, str]:
    return http_request(rules_url(base, switch_id), method="GET")


def _main() -> int:
    p = argparse.ArgumentParser(description="rest_firewall rule helper")
    p.add_argument("--base", default=DEFAULT_BASE, help="REST base URL (default: %(default)s)")
    p.add_argument("--switch", default="all", help="switch id path segment (default: %(default)s)")

    sub = p.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="GET /firewall/rules/{switch}")
    p_list.set_defaults(_fn="list")

    p_del = sub.add_parser("delete", help="DELETE a rule by id")
    p_del.add_argument("--rule-id", required=True, help='rule id or "all"')
    p_del.set_defaults(_fn="delete")

    p_add = sub.add_parser("add", help="POST a new rule")
    g = p_add.add_mutually_exclusive_group(required=True)
    g.add_argument("--allow", action="store_true")
    g.add_argument("--deny", action="store_true")
    g.add_argument("--packetin", action="store_true")

    p_add.add_argument("--priority", help="0-65533 as string")
    p_add.add_argument("--dl-type", help="ARP, IPv4, or IPv6")
    p_add.add_argument("--nw-src", dest="nw_src", help="e.g. 10.0.0.1/32")
    p_add.add_argument("--nw-dst", dest="nw_dst", help="e.g. 10.0.0.2/32")
    p_add.add_argument("--dl-src", dest="dl_src", help="MAC xx:xx:xx:xx:xx:xx")
    p_add.add_argument("--dl-dst", dest="dl_dst", help="MAC xx:xx:xx:xx:xx:xx")
    p_add.add_argument("--ipv6-src", dest="ipv6_src")
    p_add.add_argument("--ipv6-dst", dest="ipv6_dst")
    p_add.add_argument("--nw-proto", dest="nw_proto", help="TCP, UDP, ICMP, ICMPv6")
    p_add.add_argument("--tp-src", dest="tp_src")
    p_add.add_argument("--tp-dst", dest="tp_dst")
    p_add.add_argument("--in-port", dest="in_port")
    p_add.set_defaults(_fn="add")

    args = p.parse_args()

    if args._fn == "list":
        code, text = get_rules(base=args.base, switch_id=args.switch)
        print(text)
        return 0 if code == 200 else 1

    if args._fn == "delete":
        code, text = delete_rule(args.rule_id, base=args.base, switch_id=args.switch)
        print(text)
        return 0 if 200 <= code < 300 else 1

    if args._fn == "add":
        if args.allow:
            action = "ALLOW"
        elif args.deny:
            action = "DENY"
        else:
            action = "PACKETIN"

        body = build_rule(
            action=action,
            priority=args.priority,
            dl_type=args.dl_type,
            nw_src=args.nw_src,
            nw_dst=args.nw_dst,
            dl_src=args.dl_src,
            dl_dst=args.dl_dst,
            ipv6_src=args.ipv6_src,
            ipv6_dst=args.ipv6_dst,
            nw_proto=args.nw_proto,
            tp_src=args.tp_src,
            tp_dst=args.tp_dst,
            in_port=args.in_port,
        )
        code, text = post_rule(body, base=args.base, switch_id=args.switch)
        print(text)
        return 0 if 200 <= code < 300 else 1

    return 1


if __name__ == "__main__":
    sys.exit(_main())

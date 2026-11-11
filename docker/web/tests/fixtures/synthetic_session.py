"""SYNTHETIC Hermes session for the vulnerator-web tests.

Exact shape of ``GET /api/sessions/{id}/messages`` (hermes-agent 0.23): ``id``, ``role``,
``content``, ``tool_calls`` (JSON string), ``tool_call_id``, ``tool_name``, ``timestamp``,
``reasoning``. ALL targets are documentation ones (RFC 5737 ``192.0.2.0/24`` and
``example.com``): never real recon against a target (public-repo rule).
"""

from __future__ import annotations

import json

SID = "20261107_120000_synthetic"
T0 = 1_800_000_000.0
TARGET = "192.0.2.10"

SQLI_CMD = ("curl -s 'http://192.0.2.10/item?id=1%27%20OR%20%271%27=%271' "
            "-H 'Host: shop.example.com'")
SQLI_OUT = ("HTTP/1.1 200 OK\n<tr><td>1</td><td>widget</td></tr>\n"
            "<tr><td>2</td><td>gadget</td></tr>\n<tr><td>3</td><td>admin-only</td></tr>\n")


def _call(cid: str, name: str, args: dict) -> dict:
    return {"id": cid, "type": "function",
            "function": {"name": name, "arguments": json.dumps(args)}}


def session_meta(**over) -> dict:
    meta = {
        "id": SID, "source": "api_server", "model": "mistralai/mistral-large-4-0",
        "title": "Authorized pentest 192.0.2.10", "started_at": T0, "ended_at": None,
        "message_count": 14, "tool_call_count": 6, "input_tokens": 12000,
        "output_tokens": 2100, "estimated_cost_usd": 0.042, "last_active": T0 + 60,
        "parent_session_id": None, "preview": "Authorized pentest against 192.0.2.10",
    }
    meta.update(over)
    return meta


def messages() -> list[dict]:
    m = []

    def add(role, t, **kw):
        m.append({"id": len(m) + 1, "session_id": SID, "role": role, "timestamp": T0 + t, **kw})

    add("user", 0, content="Authorized pentest against 192.0.2.10 (scope: that host only).")
    add("assistant", 2, content="OODA — OBSERVE (step 1): port and service discovery on the target",
        reasoning="Start with a service scan to map the attack surface.",
        tool_calls=json.dumps([_call("call_nmap", "mcp_kali_kali_run",
                                     {"command": "nmap -sV -p 80,443 192.0.2.10",
                                      "targets": [TARGET], "engagement_id": "eng-test"})]))
    add("tool", 14.5, tool_call_id="call_nmap", tool_name="mcp_kali_kali_run",
        content=json.dumps({"status": "done", "returncode": 0,
                            "output": "80/tcp open http nginx 1.18\n443/tcp closed https\n"}))
    add("assistant", 16, content="**OODA — ORIENT (step 2):** nginx on 80, browse the shop",
        tool_calls=json.dumps([_call("call_nav", "mcp_playwright_browser_navigate",
                                     {"url": "http://shop.example.com/item?id=1"})]))
    add("tool", 18.2, tool_call_id="call_nav", tool_name="mcp_playwright_browser_navigate",
        content="Page URL: http://shop.example.com/item?id=1\nPage Title: Shop item")
    add("assistant", 20, content="OODA — DECIDE (step 3): test the id parameter for SQL injection",
        reasoning="The id parameter is reflected in a table; boolean-based SQLi is the cheapest test.")
    add("assistant", 21, content="OODA — ACT (step 4): boolean SQLi probe on id",
        tool_calls=json.dumps([_call("call_sqli", "mcp_kali_kali_run",
                                     {"command": SQLI_CMD, "targets": [TARGET]})]))
    add("tool", 23.75, tool_call_id="call_sqli", tool_name="mcp_kali_kali_run",
        content=json.dumps({"status": "done", "returncode": 0, "output": SQLI_OUT}))
    add("assistant", 25, content="OODA — ACT (step 5): record the confirmed SQL injection",
        tool_calls=json.dumps([_call("call_find", "mcp_kali_record_finding", {
            "engagement_id": "eng-test", "title": "Boolean SQL injection in /item?id",
            "state": "confirmed", "phase": "act", "target": "http://192.0.2.10/item",
            "technique_id": "T1190", "confidence": "high",
            "evidence": {"command": SQLI_CMD, "output": SQLI_OUT}})]))
    add("tool", 25.4, tool_call_id="call_find", tool_name="mcp_kali_record_finding",
        content=json.dumps({"status": "recorded", "finding": {"id": "f1", "title": "x"}}))
    add("assistant", 27, content="OODA — ACT (step 6): record admin panel as confirmed (no evidence)",
        tool_calls=json.dumps([_call("call_bad", "mcp_kali_record_finding", {
            "engagement_id": "eng-test", "title": "Admin panel exposed", "state": "confirmed"})]))
    add("tool", 27.2, tool_call_id="call_bad", tool_name="mcp_kali_record_finding",
        content=json.dumps({"status": "error",
                            "error": "invalid 'confirmed' finding: requires reproducible 'evidence'"}))
    add("assistant", 29, content="OODA — ACT (step 7): out-of-scope probe",
        tool_calls=json.dumps([_call("call_oos", "mcp_kali_kali_run",
                                     {"command": "curl -s http://198.51.100.7/"})]))
    add("tool", 29.1, tool_call_id="call_oos", tool_name="mcp_kali_kali_run",
        content=json.dumps({"status": "failed", "scope_violation": True,
                            "error": "SCOPE_VIOLATION: 198.51.100.7 out of scope"}))
    return m


def caido_entries() -> list[dict]:
    """Nodes from ``caido_client.search_history`` (HISTORY_QUERY shape), synthetic."""
    return [
        {"id": "12", "method": "GET", "host": "shop.example.com", "port": 80,
         "path": "/item", "isTls": False, "length": 120, "createdAt": int((T0 + 18) * 1000),
         "response": {"id": "r12", "statusCode": 200, "roundtripTime": 41, "length": 2048,
                      "createdAt": int((T0 + 18.1) * 1000)}},
        {"id": "13", "method": "POST", "host": "shop.example.com", "port": 443,
         "path": "/login", "isTls": True, "length": 90, "createdAt": int((T0 + 19) * 1000),
         "response": None},
    ]

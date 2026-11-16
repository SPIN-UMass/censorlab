"""scenario.py — Python loader for `scenario.conf` (see scenario.sh for the grammar).

The file is a flat KEY=value list.  Both loaders implement the *same* regular
grammar so that bash and Python can never disagree about a scenario's contents:

    blank / #comment
    KEY=bareword            bareword ∈ [A-Za-z0-9_./:-]*
    KEY="quoted"            quoted   ∈ [^"$`\\]*
    KEY ∈ [A-Z][A-Z0-9_]*
"""

import os
import re

_BLANK = re.compile(r"^\s*(#.*)?$")
_QUOTED = re.compile(r'^([A-Z][A-Z0-9_]*)="([^"$`\\]*)"\s*$')
_BARE = re.compile(r"^([A-Z][A-Z0-9_]*)=([A-Za-z0-9_./:-]*)\s*$")

REQUIRED = ("ID", "NAME", "MACRO", "CLIENT_IP", "PCAP", "LABELS", "POSITIVE_ACTIONS")

# Canonical tool order and scenario.conf key prefixes (mirrors scenario.sh)
TOOLS = ("PyCL", "CensorLang", "Zeek", "Scapy", "Suricata", "Snort", "OpenGFW")
TOOL_PREFIX = {
    "PyCL": "PYCL",
    "CensorLang": "CL",
    "Zeek": "ZEEK",
    "Scapy": "SCAPY",
    "Suricata": "SURICATA",
    "Snort": "SNORT",
    "OpenGFW": "OPENGFW",
}


class ScenarioError(ValueError):
    pass


def load_scenario(scenario_dir):
    """Parse <scenario_dir>/scenario.conf into a dict.

    Extra keys: "DIR" (absolute scenario dir) and "_prefix" (TOOL_PREFIX).
    """
    path = os.path.join(scenario_dir, "scenario.conf")
    if not os.path.exists(path):
        raise ScenarioError(f"missing {path}")
    out = {"DIR": os.path.abspath(scenario_dir), "_prefix": TOOL_PREFIX}
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if _BLANK.match(line):
                continue
            m = _QUOTED.match(line) or _BARE.match(line)
            if not m:
                raise ScenarioError(f"{path}:{lineno}: unrecognized line: {line!r}")
            out[m.group(1)] = m.group(2)
    for key in REQUIRED:
        if not out.get(key):
            raise ScenarioError(f"{path}: missing required key {key}")
    return out


def tool_enabled(sc, tool):
    """True if the scenario declares an implementation for `tool`."""
    p = TOOL_PREFIX[tool]
    if tool in ("PyCL", "CensorLang"):
        return bool(sc.get(f"{p}_CONFIG"))
    if tool in ("Zeek", "Scapy"):
        return bool(sc.get(f"{p}_SCRIPT"))
    return bool(sc.get(f"{p}_RULES"))


def tool_note(sc, tool):
    return sc.get(f"NOTE_{TOOL_PREFIX[tool]}", "")

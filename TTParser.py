#!/usr/bin/env python3
"""
Generates a single Markdown table from Caldera operation and event logs.
"""

import json
import sys
import base64
from typing import Optional, List, Dict, Any

def load_json(path: str):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def safe_decode_command(cmd: Optional[str]) -> str:
    """Decode base64 commands if possible; else return original"""
    if not cmd:
        return ""
    if isinstance(cmd, (dict, list)):
        return json.dumps(cmd, ensure_ascii=False)
    if not isinstance(cmd, str):
        return str(cmd)
    try:
        decoded_bytes = base64.b64decode(cmd, validate=True)
        decoded_text = decoded_bytes.decode('utf-8')
        if decoded_text.strip():
            return decoded_text
        return cmd
    except (base64.binascii.Error, UnicodeDecodeError, ValueError):
        return cmd

def extract_header(op: Dict[str, Any]) -> Dict[str, str]:
    return {
        "name": op.get("name") or op.get("operation_name") or "Unnamed Operation",
        "start": op.get("start") or op.get("operation_start") or "",
        "finish": op.get("finish") or op.get("operation_end") or ""
    }

def normalize_event(e: Dict[str, Any]) -> Dict[str, str]:
    attack = e.get("attack_metadata") or e.get("attack") or {}
    ability = e.get("ability_metadata") or e.get("ability") or {}

    technique_name = (
        attack.get("technique_name")
        or attack.get("technique")
        or ability.get("ability_name")
        or ability.get("ability_id")
        or e.get("ability_name")
        or "UNKNOWN"
    )

    tactic = attack.get("tactic") or ""

    cmd_candidates = [
        e.get("command"),
        (e.get("output") or {}).get("stdout"),
        e.get("raw_command"),
        e.get("ability", {}).get("command")
    ]
    cmd = next((c for c in cmd_candidates if c), None)
    decoded_cmd = safe_decode_command(cmd)

    return {
        "technique": technique_name,
        "tactic": tactic,
        "command": decoded_cmd
    }

def generate_md_table(events: List[Dict[str, str]]) -> str:
    lines = []
    lines.append("## Event Logs — TTP Summary")
    lines.append("")
    lines.append("| Technique | Tactic | Command | Windows source log | Detection | gap identified |")
    lines.append("|---|---|---|---|---|---|")

    for e in events:
        tech = e["technique"]
        tactic = e["tactic"]
        cmd = " ".join(line.strip() for line in e["command"].splitlines())
        # escape pipes
        def esc(s: str) -> str:
            return s.replace("|", "\\|")
        lines.append(f"| {esc(tech)} | {esc(tactic)} | {esc(cmd)} |  |  |  |")

    lines.append("")
    return "\n".join(lines)

def main():
    if len(sys.argv) < 3:
        print("Usage: python TTParser.py <operation_json> <event_logs_json> [output_md]")
        sys.exit(1)

    op_file = sys.argv[1]
    events_file = sys.argv[2]
    out_file = sys.argv[3] if len(sys.argv) > 3 else "report.md"

    op_json = load_json(op_file)
    events_json = load_json(events_file)

    normalized_events = [normalize_event(e) for e in events_json]
    md_table = generate_md_table(normalized_events)

    if out_file == "-":
        print(md_table)
    else:
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(md_table)
        print(f"Wrote markdown table to {out_file}")

if __name__ == "__main__":
    main()

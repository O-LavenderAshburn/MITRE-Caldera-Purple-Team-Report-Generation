# MITRE-Caldera-Purple-Team-Report-Generation
Basic report generation for MITRE Caldera json outputs

Usage: python TTParser.py <operation_json> <event_logs_json> [output_md]


## Event Logs — TTP Summary

| Technique | Tactic | Command | Windows source log | Detection | gap identified |
|---|---|---|---|---|---|
| System Information Discovery | discovery | cmd.exe /c systeminfo |  |  |  |


Adding to the table is simple as adding to the generate_md_table function 

```Python
def generate_md_table(events: List[Dict[str, str]]) -> str:
    lines = []
    lines.append("## Event Logs — TTP Summary")
    lines.append("")
    lines.append("| Technique | Tactic | Command | Windows source log | Detection | Gap identified |")
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
```

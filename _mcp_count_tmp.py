from pathlib import Path
import re
import json

text = Path("src/orchesis/scanner.py").read_text(encoding="utf-8")
start = text.index("class McpConfigScanner:")
end = text.index("class PolicyScanner:")
block = text[start:end]
apps = len(re.findall(r"findings\.append\(\s*ScanFinding\(", block))
cats = sorted(set(re.findall(r'category="([^"]+)"', block)))
print("McpConfigScanner findings.append(ScanFinding(...)) sites:", apps)
print("Distinct category strings:", len(cats))
for c in cats:
    print(" ", c)

# REMEDIATION_GUIDE size
rg = text[text.index("REMEDIATION_GUIDE = {") : text.index("}", text.index("REMEDIATION_GUIDE = {")) + 1]
# crude - instead exec first 50 lines
exec_part = Path("src/orchesis/scanner.py").read_text(encoding="utf-8")
# count keys in REMEDIATION_GUIDE via regex
keys = re.findall(r'^\s{4}"([^"]+)":\s"', exec_part.split("REMEDIATION_GUIDE = {")[1].split("\n}\n")[0], re.M)
print("REMEDIATION_GUIDE keys (partial parse):", len(keys))

mapping = Path("src/orchesis/scanner_data/owasp_mcp_mapping.json")
if mapping.exists():
    data = json.loads(mapping.read_text(encoding="utf-8"))
    all_checks = []
    for item in data.get("owasp_mcp", []):
        all_checks.extend(item.get("our_checks") or [])
    uniq = sorted(set(all_checks))
    print("owasp_mcp_mapping.json unique our_checks:", len(uniq), uniq)

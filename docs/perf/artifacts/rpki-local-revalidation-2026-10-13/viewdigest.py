import hashlib, json, sys
text = sys.stdin.read()
try:
    docs = [json.loads(text)]
except ValueError:
    docs = [json.loads(l) for l in text.splitlines() if l.strip()]
VOL = ("age", "time", "epoch", "uptime", "stamp")
def clean(x):
    if isinstance(x, dict):
        return {k: clean(v) for k, v in x.items() if not any(s in k.lower() for s in VOL)}
    if isinstance(x, list):
        return [clean(v) for v in x]
    return x
routes = []
for d in docs:
    if isinstance(d, dict) and d.get("type") == "route":
        routes.append(d["route"])
    elif isinstance(d, dict) and isinstance(d.get("routes"), list):
        routes += d["routes"]
    elif isinstance(d, list):
        routes += d
rows = sorted(json.dumps(clean(r), sort_keys=True) for r in routes)
print(hashlib.sha256("\n".join(rows).encode()).hexdigest(), len(rows))

import os, sys, threading, time, urllib.request
murl, rurl, pid, stop, pout, rout, interval = sys.argv[1:8]
interval = float(interval)
def ticks():
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return int(f[11]) + int(f[12])
def ready():
    with open(rout, "w", buffering=1) as o:
        o.write("epoch\tstatus\tlatency_ms\n")
        while not os.path.exists(stop):
            t = time.time(); status = "error"
            try:
                with urllib.request.urlopen(rurl, timeout=2) as r:
                    r.read(); status = str(r.status)
            except urllib.error.HTTPError as e:
                status = str(e.code)
            except Exception:
                pass
            o.write(f"{t:.3f}\t{status}\t{(time.time() - t) * 1000:.1f}\n")
            time.sleep(max(0, interval - (time.time() - t)))
threading.Thread(target=ready, daemon=True).start()
with open(pout, "w", buffering=1) as o:
    o.write("epoch\tticks\tupdates_received\tscrape_ms\n")
    while not os.path.exists(stop):
        t = time.time(); total = -1
        try:
            with urllib.request.urlopen(murl, timeout=5) as r:
                total = 0
                for line in r.read().decode().splitlines():
                    if line.startswith("bgp_messages_received_total{") and 'type="update"' in line:
                        total += int(float(line.rsplit(" ", 1)[1]))
        except Exception:
            total = -1
        try:
            tk = ticks()
        except OSError:
            break
        o.write(f"{t:.3f}\t{tk}\t{total}\t{(time.time() - t) * 1000:.1f}\n")
        time.sleep(max(0, interval - (time.time() - t)))

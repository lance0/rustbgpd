import os, sys, threading, time, urllib.request
import signal
murl, rurl, pid, stop, pout, rout, interval, cg, peak_out, peak_req, hold_out = sys.argv[1:12]
interval = float(interval)
term = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: term.set())
peak_fd = os.open(f"{cg}/memory.peak", os.O_RDWR)
os.write(peak_fd, b"reset")
def read_peak(path):
    os.lseek(peak_fd, 0, 0)
    value = os.read(peak_fd, 64).decode().strip()
    open(path + ".tmp", "w").write(value + "\n")
    os.rename(path + ".tmp", path)
def ticks():
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return int(f[11]) + int(f[12])
def ready():
    with open(rout, "w", buffering=1) as o:
        o.write("epoch\tstatus\tlatency_ms\n")
        while not os.path.exists(stop) and not term.is_set():
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
    o.write("epoch\tticks\tupdates_received\tscrape_ms\tcg_current\n")
    while not os.path.exists(stop) and not term.is_set():
        t = time.time(); total = -1
        if not os.path.exists(peak_out) and os.path.exists(peak_req):
            read_peak(peak_out)
        try:
            with urllib.request.urlopen(murl, timeout=5) as r:
                total = 0
                for line in r.read().decode().splitlines():
                    if line.startswith("bgp_messages_received_total{") and 'type="update"' in line:
                        total += int(float(line.rsplit(" ", 1)[1]))
        except Exception:
            total = -1
        try:
            tk = ticks(); cur = int(open(f"{cg}/memory.current").read())
        except OSError:
            break
        o.write(f"{t:.3f}\t{tk}\t{total}\t{(time.time() - t) * 1000:.1f}\t{cur}\n")
        term.wait(max(0, interval - (time.time() - t)))
read_peak(hold_out)

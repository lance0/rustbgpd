"""Post-hoc .text comparison of two daemon builds of one source tree.

usage: text-diff.py MAIN.dis BGTH.dis RODATA_LO RODATA_HI

Inputs are `objdump -d --no-show-raw-insn -j .text` listings. Lines must match
exactly, except that a RIP-relative operand may differ when both builds'
targets lie inside .rodata (the build path reorders merged string constants).
"""
import re
import sys

ro_lo, ro_hi = int(sys.argv[3], 16), int(sys.argv[4], 16)
rip = re.compile(r"-?0x[0-9a-f]+\(%rip\)(.*?)\s+# ([0-9a-f]+)( <[^>]*>)?$")
total = same = rodata = 0
other = []
with open(sys.argv[1]) as a, open(sys.argv[2]) as b:
    for la, lb in zip(a, b, strict=True):
        total += 1
        if la == lb:
            same += 1
            continue
        la, lb = la.rstrip("\n"), lb.rstrip("\n")
        ma, mb = rip.search(la), rip.search(lb)
        if ma and mb and rip.sub("R", la) == rip.sub("R", lb):
            ta, tb = int(ma.group(2), 16), int(mb.group(2), 16)
            if ro_lo <= ta < ro_hi and ro_lo <= tb < ro_hi:
                rodata += 1
                continue
        other.append((la, lb))
print(f"instructions={total} identical={same} rip_operand_into_rodata_only={rodata} other={len(other)}")
for pair in other[:10]:
    print(pair)
sys.exit(1 if other else 0)

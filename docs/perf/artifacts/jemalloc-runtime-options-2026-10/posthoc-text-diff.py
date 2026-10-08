"""Post-hoc .text comparison of two daemon builds of one source tree.

usage: posthoc-text-diff.py MAIN.dis BGTH.dis RODATA_LO RODATA_HI

Inputs are `objdump -d --no-show-raw-insn -j .text` listings. Instruction
lines (`<address>:<tab><mnemonic> ...`) must match exactly, except that a
RIP-relative operand may differ when both builds' targets lie inside .rodata
(the build path reorders merged string constants). Every other listing line
(blank lines and labels) is counted separately and must match exactly.
"""

import re
import sys

ro_lo, ro_hi = int(sys.argv[3], 16), int(sys.argv[4], 16)
insn = re.compile(r"^\s*[0-9a-f]+:\t")
rip = re.compile(r"-?0x[0-9a-f]+\(%rip\)(.*?)\s+# ([0-9a-f]+)( <[^>]*>)?$")
instructions = same = rodata = other_lines = other_mismatch = 0
other = []
with open(sys.argv[1]) as a, open(sys.argv[2]) as b:
    for la, lb in zip(a, b, strict=True):
        la, lb = la.rstrip("\n"), lb.rstrip("\n")
        is_insn = bool(insn.match(la))
        if is_insn != bool(insn.match(lb)):
            other.append((la, lb))
            continue
        if not is_insn:
            other_lines += 1
            if la != lb:
                other_mismatch += 1
                other.append((la, lb))
            continue
        instructions += 1
        if la == lb:
            same += 1
            continue
        ma, mb = rip.search(la), rip.search(lb)
        if ma and mb and rip.sub("R", la) == rip.sub("R", lb):
            ta, tb = int(ma.group(2), 16), int(mb.group(2), 16)
            if ro_lo <= ta < ro_hi and ro_lo <= tb < ro_hi:
                rodata += 1
                continue
        other.append((la, lb))
print(
    f"instructions={instructions} identical={same} rip_operand_into_rodata_only={rodata} "
    f"non_instruction_lines={other_lines} non_instruction_mismatches={other_mismatch} "
    f"unexplained={len(other)}"
)
for pair in other[:10]:
    print(pair)
sys.exit(1 if other else 0)

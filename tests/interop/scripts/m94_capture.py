#!/usr/bin/env python3
"""Issue one test-controlled ExaBGP withdrawal through its process API."""

import os
import time


WITHDRAW_TRIGGER = "/tmp/m94-withdraw"


def main() -> None:
    while not os.path.exists(WITHDRAW_TRIGGER):
        time.sleep(0.2)
    print("withdraw route 203.0.113.95/32 next-hop 10.94.0.2", flush=True)
    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()

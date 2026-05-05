#!/usr/bin/env python3
"""Fetch seeds from bitcoin.fish.foo and filter to good IPv4/IPv6 addresses."""

import sys
import urllib.request

URL = "https://bitcoin.fish.foo/seeds.txt"
#URL = "https://mainnet.achownodes.xyz/seeds.txt"

def parse_line(line):
    """Parse a line, return (addr, is_good_flag) or None."""
    line = line.strip()
    if not line or line.startswith('#'):
        print("comment", line)
        return None
    fields = line.split()
    if len(fields) < 2:
        print("too short", line)
        return None
    addr = fields[0]
    good_flag = fields[1]
    # Skip non-good nodes
    if good_flag != '1':
        return None
    # Skip .onion and .i2p
    if '.onion' in addr or '.i2p' in addr:
        print("onion or i2p", line)
        return None
    # Skip IPv6
    if addr.startswith('['):
        print("ipv6", line)
        return None
    # Must have a port
    if ':' not in addr:
        print("no port", line)
        return None
    # Validate IPv4:port
    host, _, port = addr.rpartition(':')
    parts = host.split('.')
    if len(parts) != 4:
        return None
    try:
        if all(0 <= int(p) <= 255 for p in parts) and 0 < int(port) <= 65535:
            return addr
    except ValueError:
        pass
    return None

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "addrs.txt"
    print(f"Fetching {URL} ...")
    resp = urllib.request.urlopen(URL)
    lines = resp.read().decode().splitlines()
    good = [a for l in lines if (a := parse_line(l)) is not None]
    print(f"Got {len(lines)} lines, {len(good)} good addresses")
    with open(out, 'w') as f:
        for addr in good:
            f.write(addr + '\n')
    print(f"Written to {out}")

if __name__ == '__main__':
    main()

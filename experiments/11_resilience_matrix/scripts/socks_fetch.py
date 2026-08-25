#!/usr/bin/env python3
"""socks_fetch.py — HTTP GET through a SOCKS5 proxy, with optional RFC 1929 auth.

Pluggable transports (obfs4/lyrebird, Snowflake) receive their per-bridge
arguments through the SOCKS5 username/password fields, so curl cannot be used
(it cannot send a NUL password).  Prints "ok <bytes> <seconds>" or "fail <why>".

Usage: socks_fetch.py PROXY_HOST PROXY_PORT TARGET_HOST TARGET_PORT PATH [PT_ARGS]
  PT_ARGS  e.g. "cert=...;iat-mode=0" (encoded per pt-spec §3.5: username = first
           255 bytes, password = remainder or a single NUL byte)
"""

import socket
import struct
import sys
import time


def socks5_connect(proxy, target, pt_args=None, timeout=60.0):
    s = socket.create_connection(proxy, timeout=timeout)
    if pt_args:
        user = pt_args.encode()[:255]
        pw = pt_args.encode()[255:] or b"\x00"
        s.sendall(b"\x05\x02\x00\x02")
    else:
        s.sendall(b"\x05\x01\x00")
    ver, method = s.recv(2)
    if method == 0x02:
        s.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw)
        _, status = s.recv(2)
        if status != 0:
            raise OSError("socks auth failed")
    elif method != 0x00:
        raise OSError(f"socks method {method} unsupported")
    host, port = target
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack("!H", port))
    resp = s.recv(10)
    if len(resp) < 2 or resp[1] != 0:
        raise OSError(f"socks connect failed: {resp!r}")
    return s


def main():
    proxy = (sys.argv[1], int(sys.argv[2]))
    target = (sys.argv[3], int(sys.argv[4]))
    path = sys.argv[5]
    pt_args = sys.argv[6] if len(sys.argv) > 6 else None
    t0 = time.perf_counter()
    try:
        s = socks5_connect(proxy, target, pt_args)
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {target[0]}\r\nConnection: close\r\n\r\n".encode())
        # Read headers, then exactly Content-Length body bytes: pluggable
        # transports do not necessarily propagate the origin's FIN promptly.
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        head, _, body = buf.partition(b"\r\n\r\n")
        length = None
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":", 1)[1].strip())
        n = len(body)
        while length is not None and n < length:
            chunk = s.recv(65536)
            if not chunk:
                break
            n += len(chunk)
        s.close()
        print(f"ok {n} {time.perf_counter() - t0:.3f}")
    except Exception as e:  # noqa: BLE001
        print(f"fail {type(e).__name__}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

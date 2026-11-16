# To test this
# (WORKS)
# curl https://google.com
# (FAILS)
# sslocal shadowsocks.json
# curl --proxy socks5://localhost:1080 https://google.com
def process(packet):
    tcp = packet.tcp
    # Only data-bearing segments are classified (the popcount of an empty
    # payload is NaN, which would otherwise fall through to "drop")
    if tcp and packet.payload_len > 0:
        # Ex1: average popcount outside (3.4, 4.6)
        ppc = packet.payload_avg_popcount
        if ppc <= 3.4 or ppc >= 4.6:
            return
        num_printable = 0
        ctg = 0
        for i, b in enumerate(packet.payload):
            p = b in range(0x20, 0x7F)
            num_printable += p
            # Ex2: first six bytes are printable
            if i == 5 and num_printable == 6:
                return
            if p:
                ctg += 1
                # Ex4: more than 20 contiguous printable bytes
                if ctg > 20:
                    return
            else:
                ctg = 0
        # Ex3: more than half of the bytes are printable
        if num_printable > packet.payload_len // 2:
            return
        ports = [tcp.src, tcp.dst]
        if 80 in ports or 443 in ports:
            return
        return "drop"

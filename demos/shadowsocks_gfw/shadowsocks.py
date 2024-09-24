def process(packet):
    tcp = packet.tcp
    if tcp:
        ppc = packet.payload_avg_popcount
        if ppc <= 3.4 or ppc >= 4.6:
            return
        num_nonp = 0
        for i, b in enumerate(packet.payload):
            p = b in range(0x20, 0x7F)
            num_nonp += p
            ctg = 0
            if i == 6 and num_nonp == 6:
                return
            if p:
                ctg += 1
            else:
                if ctg > 20:
                    return
                else:
                    ctg = 0
        if num_nonp > packet.payload_len // 2:
            return
        ports = [tcp.src, tcp.dst]
        if 80 in ports or 443 in ports:
            return
        return "drop"

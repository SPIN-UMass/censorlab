from rust import Model, Packet

lens = []
dirs = []
packet_num = 0
should_drop = False


def process(packet: Packet):
    global packet_num, lens, dirs, model
    lens.append(float(packet.payload_len))
    dirs.append(float(packet.direction))
    packet_num += 1
    if packet_num == 10:
        model_output = model.evaluate("shadowsocks", lens + dirs)
        lens = []
        dirs = []
        if model_output[0] > 0.5:
            should_drop
    if should_drop:
        return "drop"

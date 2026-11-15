from rust import Model, Packet

lens = []
dirs = []
packet_num = 0
should_drop = False


def process(packet: Packet):
    global packet_num, lens, dirs, model, should_drop
    lens.append(float(packet.payload_len))
    dirs.append(float(packet.direction))
    packet_num += 1
    if packet_num == 10:
        # The model was trained on interleaved (len, dir) pairs, see utils.combine_data
        features = [v for pair in zip(lens, dirs) for v in pair]
        model_output = model.evaluate("shadowsocks", features)
        lens = []
        dirs = []
        if model_output[0] > 0.5:
            should_drop = True
    if should_drop:
        return "drop"

from rust import Model, Packet

data = []
packet_num = 0


def process(packet: Packet):
    global packet_num, data, model
    data.append(packet.payload_entropy)
    data.append(float(packet.direction))
    data.append(float(packet.payload_len))
    packet_num += 1
    if packet_num == 30:
        model_output = model.evaluate("foobar", data)
        if model_output[1] < 0.5:
            return "reset"
    return None

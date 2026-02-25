# ML Protocol Classification Censor (PyCL)
# Uses an ONNX model to classify encrypted protocols.
# Collects features over a window of 10 packets, then evaluates.
# Based on Wang et al. traffic classification approach.
#
# The model receives a feature vector of [lengths..., directions...] and
# returns a probability score.  If score > 0.5, traffic is classified as
# a blocked protocol (e.g. Shadowsocks, obfs4) and dropped.

from rust import Model

WINDOW_SIZE = 10
lens = []
dirs = []
packet_num = 0
should_drop = False

def process(packet):
    global packet_num, lens, dirs, should_drop
    if should_drop:
        return "drop"
    lens.append(float(packet.payload_len))
    dirs.append(float(packet.direction))
    packet_num += 1
    if packet_num >= WINDOW_SIZE:
        result = model.evaluate("classifier", lens + dirs)
        lens.clear()
        dirs.clear()
        packet_num = 0
        if result[0] > 0.5:
            should_drop = True
            return "drop"

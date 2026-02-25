# Model Extraction Experiment Censor (PyCL)
# Uses a linear regression model to classify connections based on
# the first 2 packet lengths (HTTPS vs obfs4).
#
# The model "extractor" is an ONNX model that takes [len1, len2] as input
# and outputs a probability. If p > 0.5, the connection is flagged as
# obfs4 and dropped.
#
# NOTE: State variables are re-initialized per connection by RustPython.

from rust import Model

lens = []
packet_num = 0
should_drop = False

def process(packet):
    global packet_num, lens, should_drop
    if should_drop:
        return "drop"
    if packet.payload_len > 0:
        lens.append(float(packet.payload_len))
        packet_num += 1
    if packet_num >= 2:
        result = model.evaluate("extractor", lens[:2])
        if result[0] > 0.5:
            should_drop = True
            return "drop"

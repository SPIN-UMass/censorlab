# CensorLang ML Protocol Classification
# Simplified: evaluates the model on per-packet features.
# Uses payload length and entropy as input features.
# NOTE: CensorLang runs per-packet; for multi-packet windowing,
# use PyCL mode which supports stateful accumulation.

# Skip empty payload packets
if field:tcp.payload.len == 0: RETURN allow

# Set up model inputs: [payload_len, entropy]
COPY field:tcp.payload.len -> model:classifier:in:0
COPY field:transport.payload.entropy -> model:classifier:in:1

# Run inference
MODEL classifier

# Check classification result
COPY model:classifier:out:0 -> reg:f.0
if reg:f.0 > 0.5: RETURN terminate

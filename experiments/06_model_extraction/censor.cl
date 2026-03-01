# CensorLang Model Extraction Censor
# Uses a linear regression model (ONNX) to classify connections
# based on the first 2 packet lengths (HTTPS vs obfs4).
# If p > 0.5, connection is classified as obfs4 and dropped.
#
# reg:i.0 = first packet length
# reg:i.1 = second packet length
# reg:i.2 = count of data packets seen
# reg:b.0 = flagged for drop
# reg:f.0 = model output probability

# If already flagged, drop immediately
if reg:b.0 == True: RETURN terminate

# Skip empty payload packets
if field:tcp.payload.len == 0: RETURN allow

# Count packets with payload
ADD reg:i.2, 1 -> reg:i.2

# Store first packet length
if reg:i.2 == 1: COPY field:tcp.payload.len -> reg:i.0

# On second data packet: store length, run model, check result
if reg:i.2 == 2: COPY field:tcp.payload.len -> reg:i.1
if reg:i.2 == 2: COPY reg:i.0 -> model:extractor:in:0
if reg:i.2 == 2: COPY reg:i.1 -> model:extractor:in:1
if reg:i.2 == 2: MODEL extractor
if reg:i.2 == 2: COPY model:extractor:out:0 -> reg:f.0
if reg:f.0 > 0.5: COPY True -> reg:b.0
if reg:b.0 == True: RETURN terminate

# CensorLang ML Protocol Classification
# Classifies encrypted proxy traffic using an ONNX model.
# Accumulates the first 10 packets' lengths and directions,
# then runs the model. Model inputs: [len_0..len_9, dir_0..dir_9].

# Skip empty payload packets
if field:tcp.payload.len == 0: RETURN allow

# Packet 1: fill model input slots 0 (length) and 10 (direction)
if field:env.num_packets == 1: COPY field:tcp.payload.len -> model:classifier:in:0
if field:env.num_packets == 1: COPY field:direction -> model:classifier:in:10

# Packet 2
if field:env.num_packets == 2: COPY field:tcp.payload.len -> model:classifier:in:1
if field:env.num_packets == 2: COPY field:direction -> model:classifier:in:11

# Packet 3
if field:env.num_packets == 3: COPY field:tcp.payload.len -> model:classifier:in:2
if field:env.num_packets == 3: COPY field:direction -> model:classifier:in:12

# Packet 4
if field:env.num_packets == 4: COPY field:tcp.payload.len -> model:classifier:in:3
if field:env.num_packets == 4: COPY field:direction -> model:classifier:in:13

# Packet 5
if field:env.num_packets == 5: COPY field:tcp.payload.len -> model:classifier:in:4
if field:env.num_packets == 5: COPY field:direction -> model:classifier:in:14

# Packet 6
if field:env.num_packets == 6: COPY field:tcp.payload.len -> model:classifier:in:5
if field:env.num_packets == 6: COPY field:direction -> model:classifier:in:15

# Packet 7
if field:env.num_packets == 7: COPY field:tcp.payload.len -> model:classifier:in:6
if field:env.num_packets == 7: COPY field:direction -> model:classifier:in:16

# Packet 8
if field:env.num_packets == 8: COPY field:tcp.payload.len -> model:classifier:in:7
if field:env.num_packets == 8: COPY field:direction -> model:classifier:in:17

# Packet 9
if field:env.num_packets == 9: COPY field:tcp.payload.len -> model:classifier:in:8
if field:env.num_packets == 9: COPY field:direction -> model:classifier:in:18

# Packet 10: fill last slot, run model, check result
if field:env.num_packets == 10: COPY field:tcp.payload.len -> model:classifier:in:9
if field:env.num_packets == 10: COPY field:direction -> model:classifier:in:19
if field:env.num_packets == 10: MODEL classifier
if field:env.num_packets == 10: COPY model:classifier:out:0 -> reg:f.0
if reg:f.0 > 0.5: RETURN terminate

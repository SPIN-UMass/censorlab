# CensorLang ML Protocol Classification
# NOTE: CensorLang does not support ML model inference.
# This file is a placeholder -- ML classification requires PyCL mode.
# A basic entropy-based heuristic is provided as a non-ML fallback.

if field:tcp.payload.len == 0: RETURN allow_all
if field:transport.payload.entropy > 3.0: RETURN terminate

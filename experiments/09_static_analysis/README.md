# 09 — CensorLang static cost bounds

Reviewers A and E asked for the static analysis that §4.3 promises: what a
strategy *costs a censor* per connection and per packet, derived from the program
text rather than measured.  CensorLang makes this decidable — programs are
loop-free and operate on fixed, typed register banks — and `censorlab analyze`
computes, for any `.cl` program:

| quantity | meaning |
|----------|---------|
| per-connection bytes (allocated) | what the engine holds per connection: three full register banks of `num_registers` each (8 B float + 8 B int + 1 B bool per index; 272 B at the default 16), the model input/output buffers the program fills, and the engine's fixed per-connection state (`size_of::<ProgramEnv>()`) |
| per-connection bytes (touched) | the same, but counting only the connection registers the program can read or write — the footprint of an engine that sized banks to the program |
| per-host bytes | host (`hreg`) registers, shared by all connections of a host; touched and allocated (full banks) |

The analysis runs on the program as the engine loads it: checked against the
config it ships with (`censor_lang.toml` next to the program, if present) and
optimised.  `lines` is the optimised line count, `source_lines` the count as
written.
| ops/packet | worst-case constant-time operations for one packet: conditions + reads + writes + copies + arithmetic + logic + returns (each line runs at most once; the first executed `RETURN` ends evaluation) |
| regex/packet | regex evaluations, each linear in payload length |
| model calls | ONNX inferences per packet |

Per-packet cost is therefore the dot product of these counts with a
per-operation cost vector for the censor's hardware; per-connection memory is
exact.

```bash
nix develop .#experiments
bash experiments/09_static_analysis/scripts/run.sh     # results/static_analysis.{csv,json}
censorlab analyze experiments/04_shadowsocks/censor.cl  # one program, human-readable
censorlab analyze --json demos/…/censor.cl
```

Programs covered are listed in `programs.conf`.

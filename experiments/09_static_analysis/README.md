# 09 — CensorLang static cost bounds

Reviewers A and E asked for the static analysis that §4.3 promises: what a
strategy *costs a censor* per connection and per packet, derived from the program
text rather than measured.  CensorLang makes this decidable — programs are
loop-free and operate on fixed, typed register banks — and `censorlab analyze`
computes, for any `.cl` program:

| quantity | meaning |
|----------|---------|
| per-connection bytes | connection registers the program can touch (8 B float/int, 1 B bool) + the engine's fixed per-connection counters (20 B) |
| per-host bytes | host (`hreg`) registers, shared by all connections of a host |
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

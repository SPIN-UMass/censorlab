# Experiments TODO

## Severe

### Exp 05: ML Classification — train/test split
The ONNX model is trained on 100% of the test PCAP data and then evaluated on
that same data. There is no train/test split, so PyCL's accuracy is artificially
inflated. Add a proper train/test split to `train_model.py`.

## CensorLang missing features

### CensorLang: packet injection
CensorLang cannot craft and inject response packets. PyCL can return raw bytes
(e.g., forged DNS responses) for injection, but CensorLang has no equivalent.

**Affected experiments:**
- Exp 02 (DNS injection): PyCL injects forged DNS responses, CensorLang can
  only drop queries (causes timeout instead of poisoning)

## Timing methodology

### Zeek timing includes process startup
Zeek is measured with wall-clock `date +%s%N` around the entire `zeek` process,
including startup, script compilation, PCAP loading, and shutdown. CensorLab and
Scapy measure only the processing loop. This makes Zeek appear ~50x slower than
it would with equivalent measurement.

**Possible fix:** Use Zeek's internal timing via `zeek_init`/`zeek_done` event
timestamps, or measure all tools the same way (all wall-clock or all internal).

## Test data

### Synthetic PCAPs lack adversarial cases
The generated PCAPs are designed such that all tools produce identical
classification results, even when implementations differ (e.g., CensorLang's
simplified rules in exp 04). No edge cases test where simplified implementations
would diverge from the full logic. Consider adding adversarial test cases where
missing rules would cause different outcomes.

## Exp 07: Benchmark improvements

- Increase iterations from 3-5 to 10+ for statistical reliability
- Add warmup runs (discard first 1-2 iterations)
- Move timer in `pcap.rs` to start after `File::open()` to exclude file I/O
- Switch from `SystemTime` to `std::time::Instant` for monotonic measurement
- Randomize censor execution order across iterations to avoid cache effects
- Consider adding external timer (e.g., `hyperfine`) as cross-check

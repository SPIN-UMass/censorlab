#!/usr/bin/env python3
"""Train the linear "extractor" model for the model extraction experiment (Exp. 6).

The paper describes this model as a "linear regression model" predicting
HTTPS vs. obfs4 from the lengths of the first 2 non-empty packets.  Because
the censor needs a probability to threshold at 0.5, the model is a
*logistic* regression (a linear model with a sigmoid link):

    P(obfs4 | l1, l2) = sigmoid(w1 * l1 + w2 * l2 + b)

Training data is experiment 05's synthetic training capture
(``05_ml_classification/pcap/train.pcap`` + ``train_labels.csv``): its
"blocked" flows mimic obfs4/Shadowsocks (uniform random lengths), its
"normal" flows mimic HTTPS.  Features per flow are the payload lengths of
the first two packets with a non-empty TCP payload, in either direction -
exactly what ``censor.py`` collects (it ignores direction).

The ONNX graph is built by hand (MatMul -> Add -> Sigmoid) with the tensor
names CensorLab requires (see src/model/mod.rs):

  - input  ``float_input``    f32[1, 2]  = [l1, l2]
  - output ``probabilities``  f32[1, 2]  = [P(obfs4), P(HTTPS)]

``model.evaluate("extractor", [l1, l2])`` returns the flattened output, so
``result[0]`` is P(obfs4) and ``censor.py`` drops when it exceeds 0.5.

The features are standardized for fitting; the scaling is folded back into
the raw-length weights stored in the graph and in
``results/model_params.json``.

Usage (inside the censorlab-experiments image or `nix develop .#experiments`):
    python3 experiments/06_model_extraction/train_model.py
"""

import argparse
import csv
import json
import os
import sys

import numpy as np
from scapy.all import PcapReader, TCP
from sklearn.linear_model import LogisticRegression

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXP05_PCAP_DIR = os.path.join(SCRIPT_DIR, "..", "05_ml_classification", "pcap")
NUM_FEATURES = 2  # must match censor.py
OBFS4_LABEL = "blocked"  # exp 05's label for the obfs4/Shadowsocks-like class


def extract_flows(pcap_path, labels_path):
    """Return (X, y): X[i] = first two non-empty payload lengths of flow i,
    y[i] = 1 for obfs4, 0 for HTTPS."""
    with PcapReader(pcap_path) as reader:
        packets = list(reader)
    with open(labels_path, newline="") as f:
        labels = list(csv.DictReader(f))

    X, y = [], []
    for row in labels:
        first = int(row["first_packet_index"])
        count = int(row["num_packets"])
        lengths = []
        for pkt in packets[first:first + count]:
            if not pkt.haslayer(TCP):
                continue
            n = len(bytes(pkt[TCP].payload))
            if n > 0:
                lengths.append(float(n))
            if len(lengths) == NUM_FEATURES:
                break
        if len(lengths) < NUM_FEATURES:
            sys.exit(f"flow {row['flow_index']} has fewer than {NUM_FEATURES} non-empty packets")
        if row["class"] not in (OBFS4_LABEL, "normal"):
            sys.exit(f"unexpected class {row['class']!r} in {labels_path}")
        X.append(lengths)
        y.append(1 if row["class"] == OBFS4_LABEL else 0)
    return np.array(X, dtype=np.float64), np.array(y, dtype=np.int64)


def build_onnx(weights, bias):
    """Hand-built ONNX graph: probabilities = [sigmoid(xW+b), 1 - sigmoid(xW+b)]."""
    import onnx
    from onnx import TensorProto, helper

    W = helper.make_tensor("W", TensorProto.FLOAT, [NUM_FEATURES, 1],
                           [float(w) for w in weights])
    B = helper.make_tensor("B", TensorProto.FLOAT, [1], [float(bias)])
    one = helper.make_tensor("one", TensorProto.FLOAT, [1], [1.0])
    nodes = [
        helper.make_node("MatMul", ["float_input", "W"], ["logit_nobias"]),
        helper.make_node("Add", ["logit_nobias", "B"], ["logit"]),
        helper.make_node("Sigmoid", ["logit"], ["p_obfs4"]),
        helper.make_node("Sub", ["one", "p_obfs4"], ["p_https"]),
        helper.make_node("Concat", ["p_obfs4", "p_https"], ["probabilities"], axis=1),
    ]
    graph = helper.make_graph(
        nodes,
        "extractor",
        [helper.make_tensor_value_info("float_input", TensorProto.FLOAT, [1, NUM_FEATURES])],
        [helper.make_tensor_value_info("probabilities", TensorProto.FLOAT, [1, 2])],
        initializer=[W, B, one],
    )
    model = helper.make_model(
        graph,
        producer_name="censorlab-exp06-train_model",
        opset_imports=[helper.make_opsetid("", 13)],
    )
    model.ir_version = 8
    onnx.checker.check_model(model, full_check=True)
    return model


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pcap", default=os.path.join(EXP05_PCAP_DIR, "train.pcap"))
    parser.add_argument("--labels", default=os.path.join(EXP05_PCAP_DIR, "train_labels.csv"))
    parser.add_argument("--output", default=os.path.join(SCRIPT_DIR, "model.onnx"))
    parser.add_argument("--params", default=os.path.join(SCRIPT_DIR, "results", "model_params.json"))
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    X, y = extract_flows(args.pcap, args.labels)
    print(f"{len(X)} flows: {int(y.sum())} obfs4, {int((y == 0).sum())} HTTPS")

    mean, std = X.mean(axis=0), X.std(axis=0)
    clf = LogisticRegression(random_state=args.seed)
    clf.fit((X - mean) / std, y)
    # Fold the standardization into raw-length weights
    w = clf.coef_[0] / std
    b = float(clf.intercept_[0] - np.sum(clf.coef_[0] * mean / std))
    acc = float(((X @ w + b > 0).astype(int) == y).mean())
    print(f"weights (raw lengths): w1={w[0]:.6g} w2={w[1]:.6g} b={b:.6g}")
    print(f"training accuracy: {acc:.4f}")

    model = build_onnx(w, b)
    import onnx
    onnx.save(model, args.output)
    print(f"ONNX model saved to {args.output}")

    # Cross-check the exported graph against the sklearn model
    import onnxruntime as ort
    sess = ort.InferenceSession(args.output)
    onnx_p = np.array([
        sess.run(["probabilities"], {"float_input": x.reshape(1, -1).astype(np.float32)})[0][0]
        for x in X
    ])
    skl_p = clf.predict_proba((X - mean) / std)[:, 1]
    max_err = float(np.abs(onnx_p[:, 0] - skl_p).max())
    print(f"max |P_onnx(obfs4) - P_sklearn(obfs4)| over training set: {max_err:.2e}")
    if max_err > 1e-4 or not np.allclose(onnx_p.sum(axis=1), 1.0, atol=1e-6):
        sys.exit("exported ONNX model disagrees with the trained classifier")

    os.makedirs(os.path.dirname(args.params), exist_ok=True)
    with open(args.params, "w") as f:
        json.dump({
            "description": "P(obfs4) = sigmoid(w1*len1 + w2*len2 + b); "
                           "censor.py drops when P(obfs4) > 0.5, i.e. w1*len1 + w2*len2 + b > 0",
            "model": "LogisticRegression (sklearn, standardized features, folded into raw weights)",
            "features": ["len_first_nonempty_payload", "len_second_nonempty_payload"],
            "w1": float(w[0]),
            "w2": float(w[1]),
            "b": b,
            "training_flows": int(len(X)),
            "training_obfs4": int(y.sum()),
            "training_https": int((y == 0).sum()),
            "training_accuracy": acc,
            "seed": args.seed,
            "training_pcap": os.path.relpath(args.pcap, SCRIPT_DIR),
        }, f, indent=2)
        f.write("\n")
    print(f"parameters written to {args.params}")


if __name__ == "__main__":
    main()

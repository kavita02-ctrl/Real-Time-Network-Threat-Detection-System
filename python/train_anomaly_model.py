#!/usr/bin/env python3
"""Train a lightweight network-flow anomaly model and export it to ONNX."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Iterable

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset


FEATURES = [
    "packets",
    "bytes",
    "duration_ms",
    "src_degree",
    "dst_degree",
    "proto_tcp",
    "proto_udp",
    "mean_packet_len",
    "inter_arrival_ms",
    "syn_count",
    "fin_count",
    "rst_count",
]


class Autoencoder(nn.Module):
    def __init__(self, input_dim: int) -> None:
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 24),
            nn.ReLU(),
            nn.Linear(24, 8),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 24),
            nn.ReLU(),
            nn.Linear(24, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


class ScoredAutoencoder(nn.Module):
    def __init__(self, model: Autoencoder) -> None:
        super().__init__()
        self.model = model

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        reconstructed = self.model(x)
        return torch.mean(torch.square(x - reconstructed), dim=1)


def synthetic_dataset(rows: int, seed: int) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)

    benign = np.column_stack(
        [
            rng.poisson(12, rows),
            rng.normal(7500, 1600, rows),
            rng.gamma(2.0, 45.0, rows),
            rng.poisson(4, rows),
            rng.poisson(5, rows),
            rng.binomial(1, 0.72, rows),
            rng.binomial(1, 0.24, rows),
            rng.normal(620, 90, rows),
            rng.exponential(12, rows),
            rng.poisson(1, rows),
            rng.poisson(1, rows),
            rng.poisson(0.05, rows),
        ]
    )

    anomaly_rows = max(rows // 8, 1)
    anomalies = np.column_stack(
        [
            rng.poisson(90, anomaly_rows),
            rng.normal(120000, 25000, anomaly_rows),
            rng.gamma(1.2, 650.0, anomaly_rows),
            rng.poisson(80, anomaly_rows),
            rng.poisson(70, anomaly_rows),
            rng.binomial(1, 0.9, anomaly_rows),
            rng.binomial(1, 0.08, anomaly_rows),
            rng.normal(1300, 280, anomaly_rows),
            rng.exponential(1.8, anomaly_rows),
            rng.poisson(55, anomaly_rows),
            rng.poisson(0.2, anomaly_rows),
            rng.poisson(18, anomaly_rows),
        ]
    )

    x = np.vstack([benign, anomalies]).astype(np.float32)
    y = np.concatenate(
        [np.zeros(len(benign), dtype=np.int64), np.ones(len(anomalies), dtype=np.int64)]
    )
    x = np.maximum(x, 0)
    return x, y


def load_csv(path: Path) -> tuple[np.ndarray, np.ndarray | None]:
    with path.open("r", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = [feature for feature in FEATURES if feature not in reader.fieldnames]
        if missing:
            raise ValueError(f"CSV is missing feature columns: {', '.join(missing)}")

        rows: list[list[float]] = []
        labels: list[int] = []
        has_label = "label" in (reader.fieldnames or [])

        for row in reader:
            rows.append([float(row[name]) for name in FEATURES])
            if has_label:
                labels.append(int(float(row["label"])))

    x = np.asarray(rows, dtype=np.float32)
    y = np.asarray(labels, dtype=np.int64) if labels else None
    return x, y


def standardize(x: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    mean = x.mean(axis=0)
    std = x.std(axis=0)
    std = np.where(std < 1e-6, 1.0, std)
    return ((x - mean) / std).astype(np.float32), mean.astype(float), std.astype(float)


def train(model: Autoencoder, x_train: np.ndarray, epochs: int, batch_size: int) -> None:
    dataset = TensorDataset(torch.from_numpy(x_train))
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    loss_fn = nn.MSELoss()

    model.train()
    for epoch in range(1, epochs + 1):
        total = 0.0
        for (batch,) in loader:
            optimizer.zero_grad(set_to_none=True)
            reconstructed = model(batch)
            loss = loss_fn(reconstructed, batch)
            loss.backward()
            optimizer.step()
            total += float(loss.item()) * len(batch)
        print(f"epoch={epoch:03d} loss={total / len(dataset):.6f}")


def score(model: Autoencoder, x: np.ndarray) -> np.ndarray:
    model.eval()
    with torch.no_grad():
        tensor = torch.from_numpy(x)
        reconstructed = model(tensor)
        return torch.mean(torch.square(tensor - reconstructed), dim=1).numpy()


def export_onnx(model: Autoencoder, path: Path, input_dim: int) -> None:
    scored = ScoredAutoencoder(model).eval()
    dummy = torch.zeros(1, input_dim, dtype=torch.float32)
    torch.onnx.export(
        scored,
        dummy,
        path,
        input_names=["features"],
        output_names=["anomaly_score"],
        dynamic_axes={"features": {0: "batch"}, "anomaly_score": {0: "batch"}},
        opset_version=17,
    )


def validate_onnx(path: Path, sample: np.ndarray) -> None:
    try:
        import onnxruntime as ort
    except ImportError:
        print("onnxruntime not installed; skipping ONNX validation")
        return

    session = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
    result = session.run(None, {"features": sample[:8].astype(np.float32)})[0]
    print(f"onnx_validation_scores={np.round(result, 6).tolist()}")


def write_metadata(
    path: Path,
    mean: Iterable[float],
    std: Iterable[float],
    threshold: float,
    contamination: float,
) -> None:
    payload = {
        "feature_order": FEATURES,
        "mean": list(map(float, mean)),
        "std": list(map(float, std)),
        "threshold": float(threshold),
        "score_semantics": "mean squared reconstruction error after standardization",
        "contamination": float(contamination),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, help="Optional CSV with feature columns")
    parser.add_argument("--model-out", type=Path, default=Path("models/network_anomaly.onnx"))
    parser.add_argument(
        "--metadata-out", type=Path, default=Path("models/feature_config.json")
    )
    parser.add_argument("--epochs", type=int, default=15)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--synthetic-rows", type=int, default=5000)
    parser.add_argument("--contamination", type=float, default=0.02)
    parser.add_argument("--seed", type=int, default=7)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    if args.data:
        x, y = load_csv(args.data)
        if y is not None and np.any(y == 0):
            train_x = x[y == 0]
        else:
            train_x = x
    else:
        x, y = synthetic_dataset(args.synthetic_rows, args.seed)
        train_x = x[y == 0]

    standardized, mean, std = standardize(train_x)
    model = Autoencoder(input_dim=len(FEATURES))
    train(model, standardized, args.epochs, args.batch_size)

    train_scores = score(model, standardized)
    percentile = 100.0 * (1.0 - args.contamination)
    threshold = float(np.percentile(train_scores, percentile))

    args.model_out.parent.mkdir(parents=True, exist_ok=True)
    args.metadata_out.parent.mkdir(parents=True, exist_ok=True)
    export_onnx(model, args.model_out, len(FEATURES))
    write_metadata(args.metadata_out, mean, std, threshold, args.contamination)
    validate_onnx(args.model_out, standardized)

    print(f"saved_model={args.model_out}")
    print(f"saved_metadata={args.metadata_out}")
    print(f"threshold={threshold:.6f}")


if __name__ == "__main__":
    main()

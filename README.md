# Real-Time Network Threat Detection System

A starter implementation for a modern network threat detector that trains a
lightweight anomaly model in Python, exports it to ONNX, and runs real-time
inference from a multithreaded C++ packet pipeline.

The repository is intentionally split into two phases:

- **Offline training:** Python builds a compact autoencoder anomaly detector
  over network-flow features and exports an ONNX model plus feature metadata.
- **Online inference:** C++ captures or replays packets, maintains sharded flow
  state, normalizes features exactly like training, and runs ONNX Runtime
  inference across worker threads.

## Repository Layout

```text
python/                  Training and ONNX export code
cpp/                     C++17 inference engine
docs/                    Architecture notes
models/                  Generated ONNX model and feature metadata
data/                    Optional CSV datasets or packet captures
```

## Quick Start: Train And Export

Create a Python environment, then install the training dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r python/requirements.txt
```

Train on synthetic flow data:

```bash
python python/train_anomaly_model.py --epochs 20
```

Or train from a CSV with the expected feature columns:

```bash
python python/train_anomaly_model.py --data data/flows.csv --epochs 30
```

Outputs:

- `models/network_anomaly.onnx`
- `models/feature_config.json`

## Quick Start: Build C++ Inference

Install ONNX Runtime C++ and libpcap development headers. Then build:

```bash
cmake -S cpp -B build \
  -DONNXRUNTIME_ROOT=/path/to/onnxruntime-linux-x64
cmake --build build -j
```

Replay a packet capture:

```bash
./build/threat_detector \
  --model models/network_anomaly.onnx \
  --config models/feature_config.json \
  --pcap data/sample.pcap \
  --workers 4
```

Capture from an interface:

```bash
sudo ./build/threat_detector \
  --model models/network_anomaly.onnx \
  --config models/feature_config.json \
  --interface eth0 \
  --workers 8
```

If libpcap is unavailable, the binary can still run a synthetic packet stream:

```bash
./build/threat_detector \
  --model models/network_anomaly.onnx \
  --config models/feature_config.json \
  --synthetic 100000
```

## Engineering Notes

- The model is an autoencoder by default because it is small, fast, and exports
  cleanly to ONNX. It can be replaced with a GNN once the graph tensor contract
  is finalized.
- C++ feature extraction uses sharded flow state to reduce lock contention.
- Worker threads own separate ONNX Runtime sessions so inference does not
  serialize behind one session-level lock.
- The queue is bounded. If workers fall behind, packets are dropped in a
  controlled and measurable way rather than growing memory without bound.

See [docs/architecture.md](docs/architecture.md) for the full data flow and
extension points.

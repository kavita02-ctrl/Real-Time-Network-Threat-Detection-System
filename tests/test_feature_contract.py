import ast
from pathlib import Path
import unittest

import numpy as np

try:
    from python.train_anomaly_model import FEATURES, standardize, synthetic_dataset
except ModuleNotFoundError as exc:
    if exc.name != "torch":
        raise
    FEATURES = None
    standardize = None
    synthetic_dataset = None


def load_feature_order_from_source():
    source = Path("python/train_anomaly_model.py").read_text()
    module = ast.parse(source)
    for node in module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "FEATURES":
                    return ast.literal_eval(node.value)
    raise AssertionError("FEATURES assignment not found")


class FeatureContractTest(unittest.TestCase):
    def test_feature_order_is_stable(self):
        feature_order = FEATURES if FEATURES is not None else load_feature_order_from_source()
        self.assertEqual(
            feature_order,
            [
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
            ],
        )

    def test_standardization_round_trip(self):
        if synthetic_dataset is None:
            self.skipTest("torch is not installed; install python/requirements.txt")
        x, y = synthetic_dataset(64, seed=11)
        train_x = x[y == 0]
        z, mean, std = standardize(train_x)
        restored = z * std + mean
        np.testing.assert_allclose(restored, train_x, rtol=1e-5, atol=1e-4)


if __name__ == "__main__":
    unittest.main()

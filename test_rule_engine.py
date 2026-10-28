"""Small offline checks for the alert-only detection rules."""

import unittest

from detection.rule_engine import detect


class RuleEngineTests(unittest.TestCase):
    def test_normal_process_and_common_https_port_is_not_alerted(self):
        snapshot = {
            "timestamp": "test",
            "hostname": "TEST-PC",
            "processes": [{"pid": 10, "name": "browser.exe", "cpu_percent": 4}],
            "connections": [{"pid": 10, "remote_address": "198.51.100.4:443"}],
        }
        self.assertEqual(detect(snapshot), [])

    def test_miner_name_and_pool_port_are_combined(self):
        snapshot = {
            "timestamp": "test",
            "hostname": "TEST-PC",
            "processes": [{"pid": 4321, "name": "xmrig", "cpu_percent": 10}],
            "connections": [{"pid": 4321, "remote_address": "203.0.113.8:3333"}],
        }
        alerts = detect(snapshot)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["score"], 90)
        self.assertEqual(alerts[0]["severity"], "high")
        self.assertEqual(
            {item["rule_id"] for item in alerts[0]["indicators"]},
            {"MINER_PROCESS_NAME", "MINING_POOL_PORT"},
        )

    def test_sustained_cpu_only_alerts_on_fifth_sample_and_resets(self):
        snapshot = {
            "timestamp": "test",
            "hostname": "TEST-PC",
            "processes": [{"pid": 77, "name": "worker.exe", "cpu_percent": 90}],
            "connections": [],
        }
        streaks = {}
        for _ in range(4):
            self.assertEqual(detect(snapshot, cpu_streaks=streaks), [])

        alerts = detect(snapshot, cpu_streaks=streaks)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["score"], 25)
        self.assertEqual(alerts[0]["severity"], "medium")
        self.assertEqual(alerts[0]["indicators"][0]["rule_id"], "SUSTAINED_HIGH_CPU")

        snapshot["processes"][0]["cpu_percent"] = 10
        self.assertEqual(detect(snapshot, cpu_streaks=streaks), [])
        snapshot["processes"][0]["cpu_percent"] = 90
        for _ in range(4):
            self.assertEqual(detect(snapshot, cpu_streaks=streaks), [])
        self.assertEqual(len(detect(snapshot, cpu_streaks=streaks)), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

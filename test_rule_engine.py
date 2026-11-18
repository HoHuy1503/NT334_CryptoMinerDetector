"""Offline tests for rule-based and behavioral miner indicators."""

import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import main
from detection.rule_engine import detect


class RuleEngineTests(unittest.TestCase):
    def test_normal_process_and_common_https_port_is_not_alerted(self):
        snapshot = {
            "timestamp": "test", "hostname": "TEST-PC",
            "processes": [{"pid": 10, "name": "browser.exe", "cpu_percent": 4}],
            "connections": [{"pid": 10, "remote_address": "198.51.100.4:443"}],
        }
        self.assertEqual(detect(snapshot), [])

    def test_miner_name_with_exe_suffix_and_pool_port_are_combined(self):
        snapshot = {
            "timestamp": "test", "hostname": "TEST-PC",
            "processes": [{"pid": 4321, "name": "XMrig.EXE", "cpu_percent": 10}],
            "connections": [{"pid": 4321, "remote_address": "203.0.113.8:3333", "status": "ESTABLISHED"}],
        }
        alerts = detect(snapshot)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["score"], 90)
        self.assertEqual(alerts[0]["severity"], "high")
        self.assertEqual(
            {item["rule_id"] for item in alerts[0]["indicators"]},
            {"MINER_PROCESS_NAME", "MINING_POOL_PORT"},
        )

    def test_closed_pool_port_connection_is_ignored(self):
        snapshot = {
            "timestamp": "test", "hostname": "TEST-PC",
            "processes": [{"pid": 22, "name": "worker.exe", "cpu_percent": 1}],
            "connections": [{"pid": 22, "remote_address": "203.0.113.8:3333", "status": "TIME_WAIT"}],
        }
        self.assertEqual(detect(snapshot), [])

    def test_stratum_command_line_indicator_alerts_even_with_unknown_name(self):
        snapshot = {
            "timestamp": "test", "hostname": "TEST-PC",
            "processes": [{"pid": 30, "name": "servicehost.exe", "cpu_percent": 5,
                           "command_line_indicators": ["STRATUM_POOL_URI"]}],
            "connections": [],
        }
        alerts = detect(snapshot)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["score"], 40)
        self.assertIn("MINING_STRATUM_COMMAND_LINE", {i["rule_id"] for i in alerts[0]["indicators"]})

    def test_sustained_cpu_only_alerts_on_fifth_sample_and_resets(self):
        snapshot = {
            "timestamp": "test", "hostname": "TEST-PC",
            "processes": [{"pid": 77, "name": "worker.exe", "cpu_percent": 90}],
            "connections": [],
        }
        streaks = {}
        for _ in range(4):
            self.assertEqual(detect(snapshot, cpu_streaks=streaks), [])
        alerts = detect(snapshot, cpu_streaks=streaks)
        self.assertEqual(alerts[0]["score"], 25)
        self.assertEqual(alerts[0]["severity"], "medium")
        snapshot["processes"][0]["cpu_percent"] = 10
        self.assertEqual(detect(snapshot, cpu_streaks=streaks), [])
        snapshot["processes"][0]["cpu_percent"] = 90
        for _ in range(4):
            self.assertEqual(detect(snapshot, cpu_streaks=streaks), [])
        self.assertEqual(len(detect(snapshot, cpu_streaks=streaks)), 1)

    def test_cpu_while_system_idle_alerts_on_tenth_sample_and_resets(self):
        snapshot = {
            "timestamp": "test", "hostname": "TEST-PC", "system_cpu_percent": 10,
            "processes": [{"pid": 78, "name": "servicehost.exe", "cpu_percent": 25}],
            "connections": [],
        }
        streaks = {}
        for _ in range(9):
            self.assertEqual(detect(snapshot, idle_cpu_streaks=streaks), [])
        alerts = detect(snapshot, idle_cpu_streaks=streaks)
        self.assertEqual(alerts[0]["score"], 20)
        self.assertIn("SUSTAINED_PROCESS_CPU_WHILE_SYSTEM_IDLE",
                      {i["rule_id"] for i in alerts[0]["indicators"]})
        snapshot["system_cpu_percent"] = 40
        self.assertEqual(detect(snapshot, idle_cpu_streaks=streaks), [])
        snapshot["system_cpu_percent"] = 10
        for _ in range(9):
            self.assertEqual(detect(snapshot, idle_cpu_streaks=streaks), [])
        self.assertEqual(len(detect(snapshot, idle_cpu_streaks=streaks)), 1)

    def test_sustained_gpu_activity_alerts_on_tenth_sample_and_resets(self):
        snapshot = {
            "timestamp": "test", "hostname": "TEST-PC",
            "processes": [{"pid": 79, "name": "servicehost.exe", "cpu_percent": 2,
                           "gpu_engine_percent": 65, "gpu_engine_type": "compute_0"}],
            "connections": [],
        }
        streaks = {}
        for _ in range(9):
            self.assertEqual(detect(snapshot, gpu_streaks=streaks), [])
        alerts = detect(snapshot, gpu_streaks=streaks)
        self.assertEqual(alerts[0]["score"], 20)
        self.assertIn("SUSTAINED_GPU_ENGINE_ACTIVITY",
                      {i["rule_id"] for i in alerts[0]["indicators"]})
        snapshot["processes"][0]["gpu_engine_percent"] = 5
        self.assertEqual(detect(snapshot, gpu_streaks=streaks), [])
        snapshot["processes"][0]["gpu_engine_percent"] = 65
        for _ in range(9):
            self.assertEqual(detect(snapshot, gpu_streaks=streaks), [])
        self.assertEqual(len(detect(snapshot, gpu_streaks=streaks)), 1)


class GpuCollectorTests(unittest.TestCase):
    def test_groups_gpu_engine_counters_by_pid_without_invoking_powershell(self):
        samples = [
            {"InstanceName": "pid_100_luid_x_phys_0_eng_0_engtype_Compute_0", "CookedValue": 35},
            {"InstanceName": "pid_100_luid_x_phys_0_eng_1_engtype_Compute_0", "CookedValue": 40},
            {"InstanceName": "pid_200_luid_x_phys_0_eng_0_engtype_3D", "CookedValue": 55},
        ]
        fake_result = SimpleNamespace(returncode=0, stdout=json.dumps(samples))
        with patch("main.os.name", "nt"), patch("main.subprocess.run", return_value=fake_result) as run:
            usage = main.collect_gpu_usage_by_pid()
        run.assert_called_once()
        self.assertEqual(usage[100], {"percent": 75.0, "engine_type": "compute_0"})
        self.assertEqual(usage[200], {"percent": 55.0, "engine_type": "3d"})

    def test_gpu_collector_fails_closed_when_counter_command_fails(self):
        fake_result = SimpleNamespace(returncode=1, stdout="", stderr="unavailable")
        with patch("main.os.name", "nt"), patch("main.subprocess.run", return_value=fake_result):
            self.assertEqual(main.collect_gpu_usage_by_pid(), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
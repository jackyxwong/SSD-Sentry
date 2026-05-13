import copy
import logging
import os
import tempfile
import time
import unittest
from collections import deque
from unittest import mock

import ssd_sentry_monitor as ssd_monitor


class DummyHandler(logging.Handler):
    def emit(self, record):
        return None


class SSDSentryMonitorTests(unittest.TestCase):
    def make_protector(self):
        protector = object.__new__(ssd_monitor.SSDProtector)
        protector.config = copy.deepcopy(ssd_monitor.DEFAULT_CONFIG)
        protector.state = {}
        protector.history = deque(maxlen=1024)
        protector.last_alert = "UNKNOWN"
        protector.proc_last_stats = {}
        protector.proc_daily_totals = {}
        protector.kill_history = {}
        protector.pid_day_key = None
        protector.proc_lib = object()
        protector.once = False
        protector.dry_run = False
        protector.config_path = "config.json"
        protector.logger = logging.getLogger("ssd-sentry-test")
        protector.logger.handlers = []
        protector.reload_requested = False
        return protector

    def test_collect_sample_uses_process_rate_fallback(self):
        protector = self.make_protector()
        with mock.patch("ssd_sentry_monitor.get_total_bytes_written", return_value=1024):
            with mock.patch("ssd_sentry_monitor.get_swap_used_gb", return_value=0.0):
                with mock.patch("ssd_sentry_monitor.compute_cumulative_gb", return_value=0.0):
                    with mock.patch("ssd_sentry_monitor.time.time", return_value=100.0):
                        with mock.patch.object(
                            protector,
                            "collect_process_metrics",
                            return_value=[{
                                "pid": 123,
                                "name": "python",
                                "rate_mb_s": 200.0,
                                "memory_bytes": 1024,
                                "daily_written_bytes": 0
                            }]
                        ):
                            sample = protector.collect_sample()

        self.assertEqual(sample["physical_rate_mb_s"], 0.0)
        self.assertEqual(sample["process_rate_mb_s"], 200.0)
        self.assertEqual(sample["effective_rate_mb_s"], 200.0)
        self.assertEqual(sample["daily_written_gb"], 0.0)
        self.assertEqual(protector.state["rate_high_since"], 100.0)

    def test_prime_once_sample_waits_for_probe_when_state_missing(self):
        protector = self.make_protector()
        with mock.patch.object(protector, "collect_sample", return_value={"timestamp": 1.0}) as collect:
            with mock.patch("ssd_sentry_monitor.time.sleep") as sleep:
                result = protector.prime_once_sample()

        self.assertTrue(result)
        collect.assert_called_once()
        sleep.assert_called_once_with(protector.config["once_probe_seconds"])

    def test_collect_sample_resets_stale_state_gap(self):
        protector = self.make_protector()
        protector.state = {
            "last_total_written_bytes": 100,
            "last_sample_time": 0.0,
        }
        protector.history.append((1.0, 999999))
        with mock.patch("ssd_sentry_monitor.get_total_bytes_written", return_value=5000):
            with mock.patch("ssd_sentry_monitor.get_swap_used_gb", return_value=0.0):
                with mock.patch("ssd_sentry_monitor.compute_cumulative_gb", return_value=0.0):
                    with mock.patch("ssd_sentry_monitor.time.time", return_value=120.0):
                        with mock.patch.object(protector, "collect_process_metrics", return_value=[]):
                            sample = protector.collect_sample()

        self.assertTrue(sample["is_stale_baseline"])
        self.assertEqual(sample["delta_bytes"], 0)
        self.assertEqual(sample["physical_rate_mb_s"], 0.0)
        self.assertEqual(len(protector.history), 1)

    def test_collect_sample_resets_daily_counter_on_new_day(self):
        protector = self.make_protector()
        protector.state = {
            "daily_day_key": "2026-05-10",
            "daily_start_total_bytes": 100,
        }
        localtime_value = time.struct_time((2026, 5, 11, 0, 0, 5, 0, 131, -1))
        with mock.patch("ssd_sentry_monitor.get_total_bytes_written", return_value=5000):
            with mock.patch("ssd_sentry_monitor.get_swap_used_gb", return_value=0.0):
                with mock.patch("ssd_sentry_monitor.compute_cumulative_gb", return_value=0.0):
                    with mock.patch("ssd_sentry_monitor.time.time", return_value=120.0):
                        with mock.patch("ssd_sentry_monitor.time.localtime", return_value=localtime_value):
                            with mock.patch.object(protector, "collect_process_metrics", return_value=[]):
                                sample = protector.collect_sample()

        self.assertEqual(sample["daily_written_gb"], 0.0)
        self.assertEqual(protector.state["daily_day_key"], "2026-05-11")
        self.assertEqual(protector.state["daily_start_total_bytes"], 5000)

    def test_handle_red_kills_highest_writer_first(self):
        protector = self.make_protector()
        sample = {
            "timestamp": 100.0,
            "actionable_red": True,
            "rate_red_live": True,
            "swap_red_live": False,
            "daily_red_live": False,
            "process_metrics": [
                {"pid": 1, "name": "launchd", "rate_mb_s": 999.0, "memory_bytes": 1, "daily_written_bytes": 0},
                {"pid": 22, "name": "safe-app", "rate_mb_s": 80.0, "memory_bytes": 10, "daily_written_bytes": 0},
                {"pid": 33, "name": "writer-app", "rate_mb_s": 200.0, "memory_bytes": 5, "daily_written_bytes": 0},
            ]
        }
        with mock.patch("ssd_sentry_monitor.kill_process", return_value=True) as kill:
            protector.handle_red(sample)

        kill.assert_called_once_with(33, protector.config, protector.logger)
        self.assertTrue(protector.state["red_initial_writer_killed"])
        self.assertEqual(
            protector.state["observation_until"],
            100.0 + protector.config["observation_seconds"]
        )

    def test_handle_red_uses_memory_cleanup_after_first_kill(self):
        protector = self.make_protector()
        protector.state["red_initial_writer_killed"] = True
        sample = {
            "timestamp": 100.0,
            "actionable_red": True,
            "rate_red_live": True,
            "swap_red_live": False,
            "daily_red_live": False,
            "process_metrics": [
                {"pid": 1, "name": "launchd", "rate_mb_s": 5.0, "memory_bytes": 99, "daily_written_bytes": 0},
                {"pid": 22, "name": "small-writer", "rate_mb_s": 120.0, "memory_bytes": 2, "daily_written_bytes": 0},
                {"pid": 33, "name": "big-ram-app", "rate_mb_s": 3.0, "memory_bytes": 500, "daily_written_bytes": 0},
            ]
        }
        with mock.patch("ssd_sentry_monitor.kill_process", return_value=True) as kill:
            protector.handle_red(sample)

        kill.assert_called_once_with(33, protector.config, protector.logger)

    def test_update_live_snapshot_includes_current_metrics(self):
        protector = self.make_protector()
        protector.snapshot_lock = mock.MagicMock()
        protector.snapshot_lock.__enter__ = mock.MagicMock(return_value=None)
        protector.snapshot_lock.__exit__ = mock.MagicMock(return_value=None)
        protector.live_snapshot = {}
        protector.state["observation_until"] = 130.0
        sample = {
            "timestamp": 123.0,
            "effective_rate_mb_s": 180.0,
            "physical_rate_mb_s": 150.0,
            "process_rate_mb_s": 175.0,
            "cumulative_60_gb": 12.0,
            "cumulative_120_gb": 25.0,
            "daily_written_gb": 44.0,
            "swap_gb": 1.5,
            "sample_window_seconds": 2.0,
            "total_written_bytes": 500 * 1024 * 1024 * 1024,
            "actionable_red": True,
            "daily_yellow_hit": False,
            "daily_red_hit": False,
            "daily_red_live": False,
            "rate_red_live": True,
            "swap_red_live": False,
            "dangerous_writer_hit": False,
            "process_metrics": [
                {
                    "pid": 33,
                    "name": "writer-a",
                    "rate_mb_s": 200.0,
                    "memory_bytes": 3 * 1024**3,
                    "daily_written_bytes": 50 * 1024**3,
                    "daily_group_written_bytes": 70 * 1024**3
                }
            ]
        }

        protector.update_live_snapshot(sample, "RED")

        snapshot = protector.live_snapshot
        self.assertTrue(snapshot["available"])
        self.assertEqual(snapshot["alert"], "RED")
        self.assertEqual(snapshot["mode"], "observation")
        self.assertEqual(snapshot["process_metrics"][0]["name"], "writer-a")
        self.assertIn("rate-red 180.00>=150.00MB/s", snapshot["triggers"])

    def test_handle_red_logs_decision_context(self):
        protector = self.make_protector()
        sample = {
            "timestamp": 100.0,
            "actionable_red": True,
            "rate_red_live": True,
            "swap_red_live": False,
            "daily_red_live": False,
            "effective_rate_mb_s": 220.0,
            "cumulative_60_gb": 5.0,
            "cumulative_120_gb": 12.0,
            "swap_gb": 1.0,
            "daily_written_gb": 20.0,
            "daily_red_hit": False,
            "daily_yellow_hit": False,
            "dangerous_writer_hit": False,
            "process_metrics": [
                {"pid": 1, "name": "launchd", "rate_mb_s": 999.0, "memory_bytes": 1, "daily_written_bytes": 0},
                {"pid": 22, "name": "writer-b", "rate_mb_s": 80.0, "memory_bytes": 10, "daily_written_bytes": 0},
                {"pid": 33, "name": "writer-a", "rate_mb_s": 200.0, "memory_bytes": 5, "daily_written_bytes": 0},
            ]
        }
        with self.assertLogs("ssd-sentry-test", level="INFO") as captured:
            with mock.patch("ssd_sentry_monitor.kill_process", return_value=True):
                protector.handle_red(sample)

        output = "\n".join(captured.output)
        self.assertIn("decision action=kill strategy=highest-writer", output)
        self.assertIn("decision-candidate bucket=writer rank=1 pid=33", output)
        self.assertIn("decision-selected action=kill strategy=highest-writer pid=33", output)

    def test_handle_red_uses_daily_writer_for_daily_only_red(self):
        protector = self.make_protector()
        sample = {
            "timestamp": 100.0,
            "actionable_red": True,
            "rate_red_live": False,
            "swap_red_live": False,
            "daily_red_live": True,
            "daily_written_gb": 300.0,
            "process_metrics": [
                {"pid": 22, "name": "current-small-writer", "rate_mb_s": 30.0, "memory_bytes": 10, "daily_written_bytes": 5 * 1024**3},
                {"pid": 33, "name": "daily-culprit", "rate_mb_s": 12.0, "memory_bytes": 5, "daily_written_bytes": 180 * 1024**3},
            ]
        }
        with mock.patch("ssd_sentry_monitor.kill_process", return_value=True) as kill:
            protector.handle_red(sample)

        kill.assert_called_once_with(33, protector.config, protector.logger)

    def test_handle_red_skips_daily_only_red_without_dominant_writer(self):
        protector = self.make_protector()
        sample = {
            "timestamp": 100.0,
            "actionable_red": True,
            "rate_red_live": False,
            "swap_red_live": False,
            "daily_red_live": True,
            "daily_written_gb": 320.0,
            "process_metrics": [
                {"pid": 22, "name": "writer-a", "rate_mb_s": 15.0, "memory_bytes": 10, "daily_written_bytes": 20 * 1024**3},
                {"pid": 33, "name": "writer-b", "rate_mb_s": 14.0, "memory_bytes": 5, "daily_written_bytes": 15 * 1024**3},
            ]
        }
        with mock.patch("ssd_sentry_monitor.kill_process") as kill:
            protector.handle_red(sample)

        kill.assert_not_called()

    def test_summarize_triggers_reports_key_conditions(self):
        sample = {
            "rate_red_live": True,
            "effective_rate_mb_s": 180.0,
            "cumulative_60_gb": 22.0,
            "cumulative_120_gb": 41.0,
            "swap_red_live": False,
            "swap_gb": 6.0,
            "daily_red_live": True,
            "daily_red_hit": True,
            "daily_yellow_hit": True,
            "daily_written_gb": 350.0,
            "dangerous_writer_hit": True,
        }

        triggers = ssd_monitor.summarize_triggers(sample, ssd_monitor.DEFAULT_CONFIG)

        self.assertIn("rate-red 180.00>=150.00MB/s", triggers)
        self.assertIn("c120-red 41.00>=40.00GB", triggers)
        self.assertIn("swap-yellow 6.00>=5.00GB", triggers)
        self.assertIn("day-red-live 350.00>=300.00GB and rate>=10.00MB/s", triggers)
        self.assertIn("dangerous-writer-escalation", triggers)

    def test_handle_red_skips_kill_when_only_cumulative_red_remains(self):
        protector = self.make_protector()
        protector.state["red_initial_writer_killed"] = True
        sample = {
            "timestamp": 100.0,
            "actionable_red": False,
            "rate_red_live": False,
            "swap_red_live": False,
            "daily_red_live": False,
            "process_metrics": [
                {"pid": 33, "name": "writer-app", "rate_mb_s": 0.0, "memory_bytes": 500, "daily_written_bytes": 0},
            ]
        }
        with mock.patch("ssd_sentry_monitor.kill_process") as kill:
            protector.handle_red(sample)

        kill.assert_not_called()

    def test_remote_control_and_self_are_not_kill_candidates(self):
        metrics = [
            {"pid": os.getpid(), "name": "python3", "rate_mb_s": 900.0, "memory_bytes": 1, "daily_written_bytes": 0},
            {"pid": 2, "name": "TeamViewer", "rate_mb_s": 800.0, "memory_bytes": 2, "daily_written_bytes": 0},
            {"pid": 3, "name": "writer-app", "rate_mb_s": 100.0, "memory_bytes": 3, "daily_written_bytes": 0},
        ]

        selected = ssd_monitor.select_highest_writer_process(metrics, ssd_monitor.DEFAULT_CONFIG)
        self.assertEqual(selected["pid"], 3)

    def test_setup_logging_falls_back_when_primary_log_file_is_denied(self):
        fallback_handler = DummyHandler()
        with mock.patch(
            "ssd_sentry_monitor.RotatingFileHandler",
            side_effect=[PermissionError("denied"), fallback_handler]
        ) as rotating:
            logger = ssd_monitor.setup_logging(
                {"log_file": "/var/log/ssd-sentry/ssd_sentry_monitor.log"}
            )

        self.assertIs(logger.handlers[0], fallback_handler)
        self.assertEqual(
            rotating.call_args_list[1].args[0],
            "/tmp/ssd-sentry/ssd_sentry_monitor.log"
        )

    def test_save_state_writes_atomically(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "state.json")
            ssd_monitor.save_state(path, {"hello": "world"})

            self.assertTrue(os.path.exists(path))
            self.assertEqual(ssd_monitor.load_state(path), {"hello": "world"})
            leftovers = [name for name in os.listdir(temp_dir) if name != "state.json"]
            self.assertEqual(leftovers, [])

    def test_interval_helpers_use_new_defaults_and_check_interval_fallback(self):
        self.assertEqual(
            ssd_monitor.get_sample_interval_seconds({}),
            ssd_monitor.DEFAULT_SAMPLE_INTERVAL_SECONDS
        )
        self.assertEqual(
            ssd_monitor.get_summary_log_interval_seconds({"check_interval_seconds": 9}),
            9.0
        )
        self.assertEqual(
            ssd_monitor.get_summary_log_interval_seconds({
                "check_interval_seconds": 9,
                "summary_log_interval_seconds": 4
            }),
            4.0
        )

    def test_build_runtime_info_exposes_status_socket_and_intervals(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "config.json")
            with open(config_path, "w", encoding="utf-8") as handle:
                handle.write('{"sample_interval_seconds": 3, "summary_log_interval_seconds": 11}')

            info = ssd_monitor.build_runtime_info(config_path, os.path.join(temp_dir, "state.json"))

        self.assertEqual(info["status_socket_path"], ssd_monitor.STATUS_SOCKET_PATH)
        self.assertEqual(info["sample_interval_seconds"], 3.0)
        self.assertEqual(info["summary_log_interval_seconds"], 11.0)

    def test_apply_pending_reload_refreshes_config(self):
        protector = self.make_protector()
        protector.reload_requested = True
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "config.json")
            with open(config_path, "w", encoding="utf-8") as handle:
                handle.write('{"check_interval_seconds": 3}')
            protector.config_path = config_path

            with mock.patch("ssd_sentry_monitor.setup_logging", return_value=protector.logger):
                protector.apply_pending_reload()

        self.assertFalse(protector.reload_requested)
        self.assertEqual(protector.config["check_interval_seconds"], 3)


if __name__ == "__main__":
    unittest.main()

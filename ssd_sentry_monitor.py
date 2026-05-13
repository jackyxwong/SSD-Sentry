#!/usr/bin/env python3
import argparse
import ctypes
import ctypes.util
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections import deque

__version__ = "1.0.0"
STATUS_SOCKET_PATH = os.environ.get(
    "SSDP_STATUS_SOCKET_PATH",
    "/var/run/ssd-sentry/status.sock"
)
DEFAULT_SAMPLE_INTERVAL_SECONDS = 2
DEFAULT_SUMMARY_LOG_INTERVAL_SECONDS = 10
STATUS_SOCKET_MODE = 0o666
STATUS_SOCKET_DIR_MODE = 0o755
LIVE_SNAPSHOT_PROCESS_LIMIT = 6
DAEMON_STDIO_MAX_BYTES = 10 * 1024 * 1024
DAEMON_STDIO_BACKUP_COUNT = 5

DEFAULT_CONFIG = {
    "check_interval_seconds": 10,
    "sample_interval_seconds": 2,
    "summary_log_interval_seconds": 10,
    "once_probe_seconds": 2,
    "stale_state_reset_seconds": 60,
    "observation_seconds": 7,
    "daily": {
        "yellow_gb": 200,
        "red_gb": 300,
        "action_min_rate_mb_s": 10,
        "action_min_process_gb": 100,
        "action_min_share": 0.25
    },
    "respawn_escalation": {
        "kill_count": 3,
        "window_seconds": 300,
        "restart_after_seconds": 120
    },
    "notifications": {
        "enabled": False,
        "webhook_url": "",
        "timeout_seconds": 5,
        "notify_on": [
            "kill",
            "restart",
            "respawn-escalation",
            "alert-transition"
        ]
    },
    "yellow": {
        "disk_write_mb_s": 150,
        "duration_seconds": 30,
        "cumulative_gb": 20,
        "swap_gb": 5
    },
    "red": {
        "disk_write_mb_s": 150,
        "duration_seconds": 60,
        "cumulative_gb": 40,
        "swap_gb": 10
    },
    "dangerous_kill_on_yellow": True,
    "dangerous_min_rate_mb_s": 150,
    "dangerous_min_duration_seconds": 30,
    "use_process_write_rate_fallback": True,
    "post_kill_restart_seconds": 300,
    "restart_cooldown_seconds": 3600,
    "enable_authrestart": True,
    "enable_safe_kill": True,
    "kill_timeout_seconds": 10,
    "log_file": "/var/log/ssd-sentry/ssd_sentry_monitor.log",
    "state_file": "/var/db/ssd-sentry/state.json",
    "safe_processes": [
        "xcodebuild",
        "clang",
        "clang++",
        "gcc",
        "g++",
        "make",
        "cmake",
        "rsync",
        "tar",
        "zip",
        "unzip",
        "git",
        "svn"
    ],
    "dangerous_processes": [
        "ffmpeg",
        "convert",
        "node",
        "python",
        "mongod"
    ],
    "excluded_system_processes": [
        "kernel_task",
        "launchd",
        "loginwindow",
        "WindowServer",
        "syslogd",
        "UserEventAgent",
        "trustd",
        "securityd",
        "mds",
        "mdworker",
        "mdworker_shared",
        "spotlight",
        "fseventsd",
        "notifyd",
        "opendirectoryd",
        "cfprefsd",
        "teamviewer*",
        "anydesk*",
        "rustdesk*",
        "remoting*"
    ]
}

RUSAGE_INFO_V2 = 2


class RusageInfoV2(ctypes.Structure):
    _fields_ = [
        ("ri_uuid", ctypes.c_uint8 * 16),
        ("ri_user_time", ctypes.c_uint64),
        ("ri_system_time", ctypes.c_uint64),
        ("ri_pkg_idle_wkups", ctypes.c_uint64),
        ("ri_interrupt_wkups", ctypes.c_uint64),
        ("ri_pageins", ctypes.c_uint64),
        ("ri_wired_size", ctypes.c_uint64),
        ("ri_resident_size", ctypes.c_uint64),
        ("ri_phys_footprint", ctypes.c_uint64),
        ("ri_proc_start_abstime", ctypes.c_uint64),
        ("ri_proc_exit_abstime", ctypes.c_uint64),
        ("ri_child_user_time", ctypes.c_uint64),
        ("ri_child_system_time", ctypes.c_uint64),
        ("ri_child_pkg_idle_wkups", ctypes.c_uint64),
        ("ri_child_interrupt_wkups", ctypes.c_uint64),
        ("ri_child_pageins", ctypes.c_uint64),
        ("ri_child_elapsed_abstime", ctypes.c_uint64),
        ("ri_diskio_bytesread", ctypes.c_uint64),
        ("ri_diskio_byteswritten", ctypes.c_uint64)
    ]


class SSDProtector:
    def __init__(self, config_path, state_path, once=False, dry_run=False):
        self.config = load_config(config_path)
        self.config_path = config_path
        self.state_path = state_path
        self.once = once
        self.dry_run = dry_run
        self.logger = setup_logging(self.config, once or dry_run)
        self.state = load_state(state_path)
        self.history = deque(maxlen=1024)
        self.last_alert = self.state.get("last_alert", "UNKNOWN")
        self.proc_last_stats = self.state.get("proc_last_stats", {})
        self.proc_daily_totals = self.state.get("proc_daily_totals", {})
        self.kill_history = self.state.get("kill_history", {})
        self.pid_day_key = None
        self.proc_lib = load_libproc(self.logger)
        self.reload_requested = False
        self.last_summary_log_at = 0.0
        self.last_summary_log_alert = None
        self.snapshot_lock = threading.Lock()
        self.live_snapshot = build_boot_live_snapshot(self.config)
        self.status_socket = None
        self.status_socket_thread = None
        self.install_signal_handlers()
        if not self.once and not self.dry_run:
            self.start_status_socket_server()
        if self.config.get("safe_processes"):
            self.logger.info(
                "safe_processes is informational only; RED enforcement uses excluded_system_processes"
            )

    def run(self):
        if self.once:
            if not self.prime_once_sample():
                return

        while True:
            self.apply_pending_reload()
            sample = self.collect_sample()
            if sample is None:
                self.update_live_snapshot_unavailable("sample unavailable")
                time.sleep(get_sample_interval_seconds(self.config))
                continue

            alert = self.evaluate_alert(sample)
            self.sync_red_state(alert, sample)
            self.notify_alert_transition(alert, sample)

            if self.should_log_summary(sample["timestamp"], alert):
                self.log_sample_summary(sample, alert)
                if alert in ("YELLOW", "RED"):
                    self.log_top_processes(sample.get("process_metrics"))

            if alert == "RED":
                self.handle_red(sample)

            self.handle_restart_if_needed(alert, sample)

            self.state["last_alert"] = alert
            self.update_live_snapshot(sample, alert)
            save_state(self.state_path, self.state)
            self.last_alert = alert

            if self.once:
                break

            time.sleep(get_sample_interval_seconds(self.config))

    def install_signal_handlers(self):
        if not hasattr(signal, "SIGHUP"):
            return
        try:
            signal.signal(signal.SIGHUP, self.handle_sighup)
        except (ValueError, OSError):
            pass

    def handle_sighup(self, signum, frame):
        self.reload_requested = True

    def apply_pending_reload(self):
        if not self.reload_requested:
            return
        self.reload_requested = False
        self.config = load_config(self.config_path)
        self.logger = setup_logging(self.config, self.once or self.dry_run)
        self.logger.warning("configuration reloaded from %s", self.config_path)

    def start_status_socket_server(self):
        socket_dir = os.path.dirname(STATUS_SOCKET_PATH)
        try:
            if socket_dir:
                os.makedirs(socket_dir, exist_ok=True)
                os.chmod(socket_dir, STATUS_SOCKET_DIR_MODE)
            if os.path.exists(STATUS_SOCKET_PATH):
                os.unlink(STATUS_SOCKET_PATH)
            status_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            status_socket.settimeout(1.0)
            status_socket.bind(STATUS_SOCKET_PATH)
            os.chmod(STATUS_SOCKET_PATH, STATUS_SOCKET_MODE)
            status_socket.listen(8)
        except OSError as exc:
            self.logger.error("status socket setup failed path=%s: %s", STATUS_SOCKET_PATH, exc)
            return

        self.status_socket = status_socket
        self.status_socket_thread = threading.Thread(
            target=self.serve_status_socket,
            name="ssd-sentry-status",
            daemon=True
        )
        self.status_socket_thread.start()
        self.logger.info("status socket listening path=%s", STATUS_SOCKET_PATH)

    def serve_status_socket(self):
        while True:
            if self.status_socket is None:
                return
            try:
                conn, _ = self.status_socket.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                self.logger.error("status socket accept failed: %s", exc)
                return
            with conn:
                try:
                    conn.sendall(self.get_live_snapshot_json().encode("utf-8"))
                except OSError:
                    continue

    def get_live_snapshot_json(self):
        with self.snapshot_lock:
            return json.dumps(self.live_snapshot, sort_keys=True)

    def update_live_snapshot_unavailable(self, message):
        with self.snapshot_lock:
            snapshot = build_boot_live_snapshot(self.config)
            snapshot["message"] = message
            snapshot["updated_at"] = time.time()
            self.live_snapshot = snapshot

    def update_live_snapshot(self, sample, alert):
        triggers = summarize_triggers(sample, self.config)
        top_processes = []
        for item in (sample.get("process_metrics") or [])[:LIVE_SNAPSHOT_PROCESS_LIMIT]:
            top_processes.append(build_process_metric_payload(item))
        with self.snapshot_lock:
            self.live_snapshot = {
                "available": True,
                "alert": alert,
                "hostname": socket.gethostname(),
                "message": "",
                "mode": current_mode_name(self.state, sample["timestamp"]),
                "observation_until": self.state.get("observation_until"),
                "pid": os.getpid(),
                "process_metrics": top_processes,
                "rate_red_live": sample.get("rate_red_live", False),
                "sample_interval_seconds": get_sample_interval_seconds(self.config),
                "sample_time": sample["timestamp"],
                "summary_log_interval_seconds": get_summary_log_interval_seconds(self.config),
                "swap_red_live": sample.get("swap_red_live", False),
                "timestamp": time.time(),
                "total_written_gb": sample["total_written_bytes"] / (1024 * 1024 * 1024),
                "triggers": triggers,
                "version": __version__,
                "actionable_red": sample.get("actionable_red", False),
                "cumulative_120_gb": sample.get("cumulative_120_gb", 0.0),
                "cumulative_60_gb": sample.get("cumulative_60_gb", 0.0),
                "daily_red_hit": sample.get("daily_red_hit", False),
                "daily_red_live": sample.get("daily_red_live", False),
                "daily_written_gb": sample.get("daily_written_gb", 0.0),
                "daily_yellow_hit": sample.get("daily_yellow_hit", False),
                "effective_rate_mb_s": sample.get("effective_rate_mb_s", 0.0),
                "physical_rate_mb_s": sample.get("physical_rate_mb_s", 0.0),
                "process_rate_mb_s": sample.get("process_rate_mb_s", 0.0),
                "red_since": self.state.get("red_since"),
                "sample_window_seconds": sample.get("sample_window_seconds", 0.0),
                "swap_gb": sample.get("swap_gb", 0.0)
            }

    def should_log_summary(self, now, alert):
        interval = get_summary_log_interval_seconds(self.config)
        if self.last_summary_log_at <= 0:
            self.last_summary_log_at = now
            self.last_summary_log_alert = alert
            return True
        if alert != self.last_summary_log_alert:
            self.last_summary_log_at = now
            self.last_summary_log_alert = alert
            return True
        if (now - self.last_summary_log_at) >= interval:
            self.last_summary_log_at = now
            self.last_summary_log_alert = alert
            return True
        return False

    def log_sample_summary(self, sample, alert):
        self.logger.info(
            (
                "sample rate=%.2fMB/s physical=%.2fMB/s process=%.2fMB/s "
                "delta=%.2fMB window=%.2fs total=%.2fGB day=%.2fGB "
                "cumulative60=%.2fGB cumulative120=%.2fGB swap=%.2fGB alert=%s"
            ),
            sample["effective_rate_mb_s"],
            sample["physical_rate_mb_s"],
            sample["process_rate_mb_s"],
            sample["delta_bytes"] / (1024 * 1024),
            sample["sample_window_seconds"],
            sample["total_written_bytes"] / (1024 * 1024 * 1024),
            sample["daily_written_gb"],
            sample["cumulative_60_gb"],
            sample["cumulative_120_gb"],
            sample["swap_gb"],
            alert
        )
        self.logger.info(
            "sample-triggers %s",
            "; ".join(summarize_triggers(sample, self.config))
        )

    def prime_once_sample(self):
        last_bytes = self.state.get("last_total_written_bytes")
        last_time = self.state.get("last_sample_time")
        if last_bytes is not None and last_time is not None:
            return True

        probe_seconds = max(1, int(self.config.get("once_probe_seconds", 2)))
        self.logger.info(
            "priming initial sample for once mode; waiting %ss before measuring rate",
            probe_seconds
        )
        if self.collect_sample() is None:
            return False
        time.sleep(probe_seconds)
        return True

    def sync_red_state(self, alert, sample):
        if alert == "RED" and sample.get("actionable_red", False):
            if self.state.get("red_since") is None:
                self.state["red_since"] = sample["timestamp"]
            return

        self.state.pop("red_since", None)
        self.state.pop("observation_until", None)
        self.state.pop("red_initial_writer_killed", None)
        self.state.pop("respawn_escalated_since", None)

    def notify_alert_transition(self, alert, sample):
        previous = self.last_alert
        if previous == alert:
            return
        if previous == "UNKNOWN" and not self.once:
            previous = "STARTUP"
        message = "alert transition %s -> %s" % (previous, alert)
        self.send_notification(
            "alert-transition",
            message,
            {
                "from": previous,
                "to": alert,
                "sample": build_sample_payload(sample)
            }
        )

    def sync_daily_state(self, now, total_bytes):
        day_key = time.strftime("%Y-%m-%d", time.localtime(now))
        if self.pid_day_key != day_key:
            self.pid_day_key = day_key
            self.proc_daily_totals.clear()
            self.proc_last_stats.clear()
            self.kill_history.clear()

        if self.state.get("daily_day_key") != day_key:
            self.state["daily_day_key"] = day_key
            self.state["daily_start_total_bytes"] = total_bytes
            self.state["daily_written_bytes"] = 0
            self.state["proc_daily_totals"] = self.proc_daily_totals
            self.state["proc_last_stats"] = self.proc_last_stats
            self.state["kill_history"] = self.kill_history
            self.logger.info("daily counters reset for %s", day_key)
            return 0

        start_total = self.state.get("daily_start_total_bytes")
        if start_total is None or total_bytes < start_total:
            self.state["daily_start_total_bytes"] = total_bytes
            self.state["daily_written_bytes"] = 0
            return 0

        daily_written_bytes = max(0, total_bytes - start_total)
        self.state["daily_written_bytes"] = daily_written_bytes
        return daily_written_bytes

    def persist_process_state(self):
        self.state["proc_last_stats"] = self.proc_last_stats
        self.state["proc_daily_totals"] = self.proc_daily_totals
        self.state["kill_history"] = self.kill_history

    def send_notification(self, event_type, message, details=None):
        if self.dry_run:
            return
        send_notification(self.config, self.logger, event_type, message, details)

    def record_kill_history(self, process_name, now):
        key = normalize_process_name(process_name)
        respawn_config = self.config.get("respawn_escalation", {})
        window_seconds = float(respawn_config.get("window_seconds", 300))
        threshold = int(respawn_config.get("kill_count", 3))
        history = self.kill_history.get(key, [])
        history = [ts for ts in history if (now - ts) <= window_seconds]
        history.append(now)
        self.kill_history[key] = history
        self.persist_process_state()
        if len(history) < threshold:
            return False

        first_kill_time = history[0]
        previous = self.state.get("respawn_escalated_since")
        if previous is None or first_kill_time < previous:
            self.state["respawn_escalated_since"] = first_kill_time
        self.logger.critical(
            "respawn escalation triggered for %s: %d kills in %.0fs",
            process_name,
            len(history),
            window_seconds
        )
        self.send_notification(
            "respawn-escalation",
            "respawn escalation triggered for %s" % process_name,
            {
                "process_name": process_name,
                "kill_count": len(history),
                "window_seconds": window_seconds,
                "first_kill_time": first_kill_time,
                "latest_kill_time": now
            }
        )
        return True

    def collect_sample(self):
        now = time.time()
        total_bytes = get_total_bytes_written(self.logger)
        if total_bytes is None:
            return None
        daily_written_bytes = self.sync_daily_state(now, total_bytes)
        daily_written_gb = daily_written_bytes / (1024 * 1024 * 1024)

        last_bytes = self.state.get("last_total_written_bytes")
        last_time = self.state.get("last_sample_time")
        delta_time = None
        is_stale_baseline = False
        if last_time is not None:
            delta_time = now - last_time
            stale_after = max(
                float(self.config.get("stale_state_reset_seconds", 60)),
                get_sample_interval_seconds(self.config) * 3.0
            )
            if delta_time > stale_after:
                is_stale_baseline = True
                self.logger.info(
                    "stale sample state detected; resetting baseline after %.2fs gap",
                    delta_time
                )
                last_bytes = None
                last_time = None
                self.history.clear()

        if last_bytes is None or last_time is None:
            delta_bytes = 0
            rate_mb_s = 0.0
        else:
            delta_bytes = max(0, total_bytes - last_bytes)
            delta_time = max(0.001, now - last_time)
            rate_mb_s = (delta_bytes / delta_time) / (1024 * 1024)
        sample_window_seconds = 0.0 if last_time is None else max(0.001, now - last_time)

        self.state["last_total_written_bytes"] = total_bytes
        self.state["last_sample_time"] = now

        self.history.append((now, delta_bytes))
        cumulative_60_gb = compute_cumulative_gb(self.history, 60)
        cumulative_120_gb = compute_cumulative_gb(self.history, 120)

        swap_gb = get_swap_used_gb(self.logger)
        if swap_gb is None:
            swap_gb = 0.0

        process_metrics = self.collect_process_metrics()
        process_rate_mb_s = sum(item["rate_mb_s"] for item in process_metrics)
        effective_rate_mb_s = rate_mb_s
        if self.config.get("use_process_write_rate_fallback", True):
            effective_rate_mb_s = max(rate_mb_s, process_rate_mb_s)
        daily_config = self.config.get("daily", {})
        daily_yellow_gb = float(daily_config.get("yellow_gb", 200))
        daily_red_gb = float(daily_config.get("red_gb", 300))
        daily_action_min_rate_mb_s = float(daily_config.get("action_min_rate_mb_s", 10))
        daily_yellow_hit = daily_written_gb >= daily_yellow_gb
        daily_red_hit = daily_written_gb >= daily_red_gb
        rate_red_live = effective_rate_mb_s >= self.config["red"]["disk_write_mb_s"]
        swap_red_live = swap_gb >= self.config["red"]["swap_gb"]
        daily_red_live = daily_red_hit and effective_rate_mb_s >= daily_action_min_rate_mb_s
        actionable_red = rate_red_live or swap_red_live or daily_red_live

        rate_high_since = self.state.get("rate_high_since")
        if effective_rate_mb_s >= self.config["yellow"]["disk_write_mb_s"]:
            if rate_high_since is None:
                rate_high_since = now
        else:
            rate_high_since = None
        self.state["rate_high_since"] = rate_high_since

        return {
            "timestamp": now,
            "rate_mb_s": effective_rate_mb_s,
            "physical_rate_mb_s": rate_mb_s,
            "process_rate_mb_s": process_rate_mb_s,
            "effective_rate_mb_s": effective_rate_mb_s,
            "delta_bytes": delta_bytes,
            "sample_window_seconds": sample_window_seconds,
            "cumulative_60_gb": cumulative_60_gb,
            "cumulative_120_gb": cumulative_120_gb,
            "daily_written_gb": daily_written_gb,
            "swap_gb": swap_gb,
            "rate_high_since": rate_high_since,
            "total_written_bytes": total_bytes,
            "last_total_written_bytes": last_bytes,
            "process_metrics": process_metrics,
            "is_stale_baseline": is_stale_baseline,
            "actionable_red": actionable_red,
            "daily_yellow_hit": daily_yellow_hit,
            "daily_red_hit": daily_red_hit,
            "daily_red_live": daily_red_live,
            "rate_red_live": rate_red_live,
            "swap_red_live": swap_red_live
        }

    def evaluate_alert(self, sample):
        now = sample["timestamp"]
        yellow = self.config["yellow"]
        red = self.config["red"]
        daily_yellow_hit = sample.get("daily_yellow_hit", False)
        daily_red_hit = sample.get("daily_red_hit", False)
        rate_mb_s = sample["effective_rate_mb_s"]
        rate_high_since = sample["rate_high_since"]
        rate_high_duration = 0
        if rate_high_since is not None:
            rate_high_duration = now - rate_high_since

        yellow_hit = (
            (rate_mb_s >= yellow["disk_write_mb_s"] and rate_high_duration >= yellow["duration_seconds"]) or
            (sample["cumulative_60_gb"] >= yellow["cumulative_gb"]) or
            (sample["swap_gb"] >= yellow["swap_gb"]) or
            daily_yellow_hit
        )

        red_hit = (
            (rate_mb_s >= red["disk_write_mb_s"] and rate_high_duration >= red["duration_seconds"]) or
            (sample["cumulative_120_gb"] >= red["cumulative_gb"]) or
            (sample["swap_gb"] >= red["swap_gb"]) or
            daily_red_hit
        )

        dangerous_writer_hit = False
        if yellow_hit and self.config.get("dangerous_kill_on_yellow", False):
            dangerous_writer_hit = self.has_dangerous_writer(sample)
            if dangerous_writer_hit:
                red_hit = True

        sample["yellow_hit"] = yellow_hit
        sample["red_hit"] = red_hit
        sample["dangerous_writer_hit"] = dangerous_writer_hit

        if red_hit:
            return "RED"
        if yellow_hit:
            return "YELLOW"
        return "NORMAL"

    def has_dangerous_writer(self, sample):
        rates = sample.get("process_metrics")
        if rates is None:
            rates = self.collect_process_metrics()
        min_rate = self.config.get("dangerous_min_rate_mb_s", self.config["red"]["disk_write_mb_s"])
        min_duration = self.config.get("dangerous_min_duration_seconds", self.config["yellow"]["duration_seconds"])
        rate_high_since = sample["rate_high_since"]
        rate_high_duration = 0
        if rate_high_since is not None:
            rate_high_duration = sample["timestamp"] - rate_high_since
        if rate_high_duration < min_duration:
            return False
        for item in rates:
            if item["rate_mb_s"] < min_rate:
                continue
            if is_dangerous_process(item["name"], self.config):
                return True
        return False

    def collect_process_metrics(self):
        if self.proc_lib is None:
            return []
        now = time.time()
        day_key = time.strftime("%Y-%m-%d", time.localtime(now))
        if self.pid_day_key != day_key:
            self.pid_day_key = day_key
            self.proc_daily_totals.clear()
            self.proc_last_stats.clear()
            self.kill_history.clear()
        processes = list_processes(self.logger)
        active_proc_keys = set()
        metrics = []

        for pid, name in processes:
            if pid == os.getpid():
                continue

            pid_stats = get_pid_stats(self.proc_lib, pid)
            if pid_stats is None:
                continue
            bytes_written, memory_bytes, start_abstime = pid_stats
            proc_key = make_process_key(pid, start_abstime)
            active_proc_keys.add(proc_key)
            norm_name = normalize_process_name(name)
            last_stats = self.proc_last_stats.get(proc_key, {})
            last_bytes = last_stats.get("last_bytes")
            last_time = last_stats.get("last_time")
            proc_daily_bytes = int(last_stats.get("daily_written_bytes", 0))

            rate_mb_s = 0.0
            if last_bytes is None or last_time is None:
                self.proc_last_stats[proc_key] = {
                    "pid": pid,
                    "name": name,
                    "start_abstime": int(start_abstime),
                    "last_bytes": int(bytes_written),
                    "last_time": now,
                    "daily_written_bytes": proc_daily_bytes
                }
                metrics.append({
                    "pid": pid,
                    "name": name,
                    "rate_mb_s": rate_mb_s,
                    "memory_bytes": memory_bytes,
                    "daily_written_bytes": proc_daily_bytes,
                    "daily_group_written_bytes": int(self.proc_daily_totals.get(norm_name, 0))
                })
                continue

            delta_bytes = max(0, bytes_written - last_bytes)
            if delta_bytes > 0:
                delta_time = max(0.001, now - last_time)
                rate_mb_s = (delta_bytes / delta_time) / (1024 * 1024)
                proc_daily_bytes += delta_bytes
                self.proc_daily_totals[norm_name] = int(self.proc_daily_totals.get(norm_name, 0)) + delta_bytes

            self.proc_last_stats[proc_key] = {
                "pid": pid,
                "name": name,
                "start_abstime": int(start_abstime),
                "last_bytes": int(bytes_written),
                "last_time": now,
                "daily_written_bytes": int(proc_daily_bytes)
            }

            metrics.append({
                "pid": pid,
                "name": name,
                "rate_mb_s": rate_mb_s,
                "memory_bytes": memory_bytes,
                "daily_written_bytes": int(proc_daily_bytes),
                "daily_group_written_bytes": int(self.proc_daily_totals.get(norm_name, 0))
            })

        for proc_key in list(self.proc_last_stats.keys()):
            if proc_key not in active_proc_keys:
                self.proc_last_stats.pop(proc_key, None)

        self.persist_process_state()

        metrics.sort(key=lambda item: item["rate_mb_s"], reverse=True)
        return metrics

    def log_top_processes(self, rates=None, top_n=5):
        if rates is None:
            rates = self.collect_process_metrics()
        if not rates:
            self.logger.info("process sampling unavailable")
            return
        for item in rates[:top_n]:
            self.logger.info(
                "process pid=%s name=%s rate=%.2fMB/s memory=%.2fGB day=%.2fGB groupday=%.2fGB",
                item["pid"],
                item["name"],
                item["rate_mb_s"],
                item["memory_bytes"] / (1024 * 1024 * 1024),
                item["daily_written_bytes"] / (1024 * 1024 * 1024),
                item["daily_group_written_bytes"] / (1024 * 1024 * 1024)
            )

    def log_kill_decision(self, sample, metrics, strategy, selected):
        reason_map = {
            "daily-culprit": (
                "daily-only red with ongoing writes; chose dominant daily culprit"
            ),
            "highest-memory-swap": (
                "swap-only red before first writer kill; chose highest memory candidate"
            ),
            "highest-memory-fallback": (
                "no positive-rate writer candidate; fell back to highest memory candidate"
            ),
            "highest-memory": (
                "initial writer already handled; continuing RAM-ranked cleanup while red persists"
            ),
            "highest-writer": (
                "first actionable red sample; chose highest current write-rate candidate"
            ),
        }
        self.logger.info(
            "decision action=kill strategy=%s triggers=%s reason=%s",
            strategy,
            "; ".join(summarize_triggers(sample, self.config)),
            reason_map.get(strategy, "selected eligible process"),
        )
        for idx, item in enumerate(rank_highest_writer_candidates(metrics, self.config)[:3], start=1):
            self.logger.info(
                "decision-candidate bucket=writer rank=%d %s",
                idx,
                describe_process_candidate(item)
            )
        for idx, item in enumerate(rank_highest_memory_candidates(metrics, self.config)[:3], start=1):
            self.logger.info(
                "decision-candidate bucket=memory rank=%d %s",
                idx,
                describe_process_candidate(item)
            )
        if strategy == "daily-culprit":
            for idx, item in enumerate(rank_daily_culprit_candidates(metrics, sample, self.config)[:3], start=1):
                self.logger.info(
                    "decision-candidate bucket=daily rank=%d %s share=%.2f%% culprit=%.2fGB",
                    idx,
                    describe_process_candidate(item),
                    float(item.get("daily_share", 0.0)) * 100.0,
                    float(item.get("daily_culprit_bytes", 0.0)) / (1024 * 1024 * 1024)
                )
        self.logger.info(
            "decision-selected action=kill strategy=%s %s",
            strategy,
            describe_process_candidate(selected)
        )

    def log_restart_decision(self, sample, red_since, required_seconds):
        metrics = sample.get("process_metrics") or []
        red_for_seconds = max(0.0, sample["timestamp"] - red_since)
        self.logger.critical(
            "decision action=restart triggers=%s red_for=%.1fs threshold=%.1fs sample_rate=%.2fMB/s swap=%.2fGB day=%.2fGB",
            "; ".join(summarize_triggers(sample, self.config)),
            red_for_seconds,
            required_seconds,
            sample.get("effective_rate_mb_s", 0.0),
            sample.get("swap_gb", 0.0),
            sample.get("daily_written_gb", 0.0)
        )
        for idx, item in enumerate(rank_highest_writer_candidates(metrics, self.config)[:3], start=1):
            self.logger.critical(
                "decision-candidate bucket=writer rank=%d %s",
                idx,
                describe_process_candidate(item)
            )
        for idx, item in enumerate(rank_highest_memory_candidates(metrics, self.config)[:3], start=1):
            self.logger.critical(
                "decision-candidate bucket=memory rank=%d %s",
                idx,
                describe_process_candidate(item)
            )

    def handle_red(self, sample):
        if not sample.get("actionable_red", False):
            self.logger.warning("red alert persists from cumulative or swap window; skipping kill")
            return

        now = sample["timestamp"]
        observation_until = self.state.get("observation_until")
        if observation_until and now < observation_until:
            self.logger.warning(
                "observation mode active for %.1fs; skipping kill",
                observation_until - now
            )
            return

        metrics = sample.get("process_metrics")
        if metrics is None:
            metrics = self.collect_process_metrics()

        swap_only_red = sample.get("swap_red_live", False) and not sample.get("rate_red_live", False) and not sample.get("daily_red_live", False)
        daily_only_red = sample.get("daily_red_live", False) and not sample.get("rate_red_live", False) and not sample.get("swap_red_live", False)
        strategy = "highest-writer"
        if daily_only_red:
            strategy = "daily-culprit"
            selected = select_daily_culprit_process(metrics, sample, self.config)
            if selected is None:
                self.logger.warning(
                    "daily red active but no dominant current writer found; skipping kill"
                )
                return
        elif swap_only_red and not self.state.get("red_initial_writer_killed", False):
            strategy = "highest-memory-swap"
            selected = select_highest_memory_process(metrics, self.config)
        elif not self.state.get("red_initial_writer_killed", False):
            selected = select_highest_writer_process(metrics, self.config)
            if selected is None:
                strategy = "highest-memory-fallback"
                selected = select_highest_memory_process(metrics, self.config)
        else:
            strategy = "highest-memory"
            selected = select_highest_memory_process(metrics, self.config)

        if selected is None:
            self.logger.warning("no eligible processes found for %s kill", strategy)
            return

        self.log_kill_decision(sample, metrics, strategy, selected)

        pid = selected["pid"]
        name = selected["name"]
        rate = selected["rate_mb_s"]
        memory_gb = selected["memory_bytes"] / (1024 * 1024 * 1024)

        if self.dry_run:
            self.logger.warning(
                "dry-run kill strategy=%s pid=%s name=%s rate=%.2fMB/s memory=%.2fGB",
                strategy,
                pid,
                name,
                rate,
                memory_gb
            )
            killed = True
        else:
            killed = kill_process(pid, self.config, self.logger)
            if killed:
                self.logger.warning(
                    "killed strategy=%s pid=%s name=%s rate=%.2fMB/s memory=%.2fGB",
                    strategy,
                    pid,
                    name,
                    rate,
                    memory_gb
                )
            else:
                self.logger.warning(
                    "failed kill strategy=%s pid=%s name=%s rate=%.2fMB/s memory=%.2fGB",
                    strategy,
                    pid,
                    name,
                    rate,
                    memory_gb
                )

        if killed:
            self.state["red_initial_writer_killed"] = True
            self.state["last_kill_time"] = now
            self.state["observation_until"] = now + self.config.get("observation_seconds", 7)
            self.record_kill_history(name, now)
            self.send_notification(
                "kill",
                "killed %s via %s" % (name, strategy),
                {
                    "strategy": strategy,
                    "pid": pid,
                    "name": name,
                    "rate_mb_s": rate,
                    "memory_gb": memory_gb
                }
            )

    def handle_restart_if_needed(self, alert, sample):
        if alert != "RED" or not sample.get("actionable_red", False):
            return

        red_since = self.state.get("red_since")
        if red_since is None:
            return

        now = sample["timestamp"]
        required_seconds = float(self.config["post_kill_restart_seconds"])
        escalation_since = self.state.get("respawn_escalated_since")
        if escalation_since is not None:
            respawn_config = self.config.get("respawn_escalation", {})
            required_seconds = min(
                required_seconds,
                float(respawn_config.get("restart_after_seconds", required_seconds))
            )
            red_since = min(red_since, escalation_since)

        if (now - red_since) < required_seconds:
            return

        last_restart = self.state.get("last_restart_time")
        if last_restart and (now - last_restart) < self.config["restart_cooldown_seconds"]:
            self.logger.warning("restart skipped: cooldown active")
            return

        if not self.config.get("enable_authrestart", True):
            self.logger.error("restart suppressed by config")
            return

        if self.dry_run:
            self.log_restart_decision(sample, red_since, required_seconds)
            self.logger.error("dry-run restart would call fdesetup authrestart")
            return

        self.log_restart_decision(sample, red_since, required_seconds)
        self.logger.critical("restart triggered: calling fdesetup authrestart")
        self.send_notification(
            "restart",
            "restart triggered via authrestart",
            {
                "red_since": red_since,
                "required_seconds": required_seconds,
                "sample": build_sample_payload(sample)
            }
        )
        try:
            subprocess.run(["/usr/bin/fdesetup", "authrestart"], check=False)
        finally:
            self.state["last_restart_time"] = now


def parse_args():
    parser = argparse.ArgumentParser(description="SSD Sentry monitor daemon")
    parser.add_argument("--config", default="/usr/local/ssd-sentry/config.json")
    parser.add_argument("--state", default="/var/db/ssd-sentry/state.json")
    parser.add_argument("--once", action="store_true", help="run one sample and exit")
    parser.add_argument("--dry-run", action="store_true", help="log actions without killing or restart")
    parser.add_argument("--version", action="store_true", help="print version and exit")
    parser.add_argument("--runtime-info", action="store_true", help="print JSON runtime info and exit")
    return parser.parse_args()


def deep_update(dst, src):
    for key, value in src.items():
        if isinstance(value, dict) and isinstance(dst.get(key), dict):
            deep_update(dst[key], value)
        else:
            dst[key] = value


def load_config(path):
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        deep_update(config, data)
    return config


def load_state(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except Exception:
            return {}
    return {}


def save_state(path, state):
    state_dir = os.path.dirname(path)
    target_dir = state_dir or "."
    os.makedirs(target_dir, exist_ok=True)

    fd, temp_path = tempfile.mkstemp(
        prefix=".state.",
        suffix=".json.tmp",
        dir=target_dir
    )
    try:
        try:
            os.fchmod(fd, 0o644)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        try:
            dir_fd = os.open(target_dir, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def get_sample_interval_seconds(config):
    return max(1.0, float(config.get("sample_interval_seconds", DEFAULT_SAMPLE_INTERVAL_SECONDS)))


def get_summary_log_interval_seconds(config):
    fallback = config.get("check_interval_seconds", DEFAULT_SUMMARY_LOG_INTERVAL_SECONDS)
    return max(1.0, float(config.get("summary_log_interval_seconds", fallback)))


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def build_runtime_info(config_path, state_path):
    runtime_config = load_config(config_path)
    script_path = os.path.realpath(__file__)
    config_exists = os.path.exists(config_path)
    state_exists = os.path.exists(state_path)
    return {
        "version": __version__,
        "script_path": script_path,
        "script_sha256": sha256_file(script_path),
        "status_socket_path": STATUS_SOCKET_PATH,
        "config_path": config_path,
        "config_exists": config_exists,
        "config_sha256": sha256_file(config_path) if config_exists else None,
        "sample_interval_seconds": get_sample_interval_seconds(runtime_config),
        "summary_log_interval_seconds": get_summary_log_interval_seconds(runtime_config),
        "state_path": state_path,
        "state_exists": state_exists,
        "hostname": socket.gethostname()
    }


def build_sample_payload(sample):
    return {
        "timestamp": sample.get("timestamp"),
        "effective_rate_mb_s": sample.get("effective_rate_mb_s"),
        "physical_rate_mb_s": sample.get("physical_rate_mb_s"),
        "process_rate_mb_s": sample.get("process_rate_mb_s"),
        "cumulative_60_gb": sample.get("cumulative_60_gb"),
        "cumulative_120_gb": sample.get("cumulative_120_gb"),
        "daily_written_gb": sample.get("daily_written_gb"),
        "swap_gb": sample.get("swap_gb"),
        "actionable_red": sample.get("actionable_red")
    }


def build_boot_live_snapshot(config):
    return {
        "available": False,
        "alert": "UNKNOWN",
        "hostname": socket.gethostname(),
        "message": "warming up",
        "mode": "starting",
        "observation_until": None,
        "pid": os.getpid(),
        "process_metrics": [],
        "rate_red_live": False,
        "red_since": None,
        "sample_interval_seconds": get_sample_interval_seconds(config),
        "sample_time": None,
        "summary_log_interval_seconds": get_summary_log_interval_seconds(config),
        "swap_red_live": False,
        "timestamp": time.time(),
        "total_written_gb": 0.0,
        "triggers": [],
        "version": __version__,
        "actionable_red": False,
        "cumulative_120_gb": 0.0,
        "cumulative_60_gb": 0.0,
        "daily_red_hit": False,
        "daily_red_live": False,
        "daily_written_gb": 0.0,
        "daily_yellow_hit": False,
        "effective_rate_mb_s": 0.0,
        "physical_rate_mb_s": 0.0,
        "process_rate_mb_s": 0.0,
        "sample_window_seconds": 0.0,
        "swap_gb": 0.0
    }


def current_mode_name(state, now):
    observation_until = state.get("observation_until")
    red_since = state.get("red_since")
    if observation_until and float(observation_until) > now:
        return "observation"
    if red_since:
        return "actionable-red"
    return "steady"


def build_process_metric_payload(item):
    return {
        "daily_group_written_gb": float(item.get("daily_group_written_bytes", 0.0)) / (1024 * 1024 * 1024),
        "daily_written_gb": float(item.get("daily_written_bytes", 0.0)) / (1024 * 1024 * 1024),
        "memory_gb": float(item.get("memory_bytes", 0.0)) / (1024 * 1024 * 1024),
        "name": item.get("name"),
        "pid": item.get("pid"),
        "rate_mb_s": float(item.get("rate_mb_s", 0.0))
    }


def send_notification(config, logger, event_type, message, details=None):
    notifications = config.get("notifications", {})
    if not notifications.get("enabled", False):
        return

    notify_on = notifications.get("notify_on", [])
    if notify_on and event_type not in notify_on:
        return

    webhook_url = notifications.get("webhook_url", "").strip()
    if not webhook_url:
        logger.warning("notifications enabled but webhook_url is empty")
        return

    payload = {
        "event": event_type,
        "message": message,
        "hostname": socket.gethostname(),
        "timestamp": time.time(),
        "details": details or {}
    }
    request = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(
            request,
            timeout=float(notifications.get("timeout_seconds", 5))
        ) as response:
            response.read()
        logger.info("notification sent event=%s", event_type)
    except urllib.error.URLError as exc:
        logger.error("notification failed event=%s: %s", event_type, exc)
    except Exception as exc:
        logger.error("notification exception event=%s: %s", event_type, exc)


def setup_logging(config, log_to_console=False):
    log_path = config["log_file"]
    log_dir = os.path.dirname(log_path)
    try:
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
    except PermissionError:
        log_dir = "/tmp/ssd-sentry"
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "ssd_sentry_monitor.log")

    logger = logging.getLogger("ssd-sentry")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for existing in list(logger.handlers):
        logger.removeHandler(existing)
        try:
            existing.close()
        except Exception:
            pass

    try:
        handler = RotatingFileHandler(log_path, maxBytes=50 * 1024 * 1024, backupCount=5)
    except (PermissionError, OSError):
        log_dir = "/tmp/ssd-sentry"
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "ssd_sentry_monitor.log")
        handler = RotatingFileHandler(log_path, maxBytes=50 * 1024 * 1024, backupCount=5)
    formatter = logging.Formatter("[%(asctime)s] %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    if log_to_console:
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(formatter)
        logger.addHandler(console)

    return logger


def get_daemon_stdio_paths(config):
    main_log_path = config.get("log_file", DEFAULT_CONFIG["log_file"])
    log_dir = os.path.dirname(main_log_path) or "/tmp/ssd-sentry"
    return (
        log_dir,
        os.path.join(log_dir, "ssd_sentry_daemon.log"),
        os.path.join(log_dir, "ssd_sentry_daemon.err.log"),
    )


class RotatingLogStream:
    def __init__(self, logger, level):
        self.logger = logger
        self.level = level
        self.buffer = ""
        self.encoding = "utf-8"

    def write(self, data):
        if not data:
            return 0
        if not isinstance(data, str):
            data = data.decode("utf-8", errors="replace")
        self.buffer += data.replace("\r\n", "\n")
        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            if line:
                self.logger.log(self.level, line)
        return len(data)

    def flush(self):
        if self.buffer:
            self.logger.log(self.level, self.buffer.rstrip("\n"))
            self.buffer = ""

    def isatty(self):
        return False


def build_rotating_stream_logger(name, path):
    log_dir = os.path.dirname(path)
    try:
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
    except PermissionError:
        log_dir = "/tmp/ssd-sentry"
        os.makedirs(log_dir, exist_ok=True)
        path = os.path.join(log_dir, os.path.basename(path))

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for existing in list(logger.handlers):
        logger.removeHandler(existing)
        try:
            existing.close()
        except Exception:
            pass

    try:
        handler = RotatingFileHandler(
            path,
            maxBytes=DAEMON_STDIO_MAX_BYTES,
            backupCount=DAEMON_STDIO_BACKUP_COUNT,
        )
    except (PermissionError, OSError):
        log_dir = "/tmp/ssd-sentry"
        os.makedirs(log_dir, exist_ok=True)
        path = os.path.join(log_dir, os.path.basename(path))
        handler = RotatingFileHandler(
            path,
            maxBytes=DAEMON_STDIO_MAX_BYTES,
            backupCount=DAEMON_STDIO_BACKUP_COUNT,
        )
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(message)s"))
    logger.addHandler(handler)
    return logger


def setup_daemon_stdio(config):
    log_dir, stdout_path, stderr_path = get_daemon_stdio_paths(config)
    try:
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
    except PermissionError:
        log_dir = "/tmp/ssd-sentry"
        os.makedirs(log_dir, exist_ok=True)
        stdout_path = os.path.join(log_dir, os.path.basename(stdout_path))
        stderr_path = os.path.join(log_dir, os.path.basename(stderr_path))

    stdout_logger = build_rotating_stream_logger("ssd-sentry.stdout", stdout_path)
    stderr_logger = build_rotating_stream_logger("ssd-sentry.stderr", stderr_path)
    sys.stdout = RotatingLogStream(stdout_logger, logging.INFO)
    sys.stderr = RotatingLogStream(stderr_logger, logging.ERROR)


def get_total_bytes_written(logger):
    try:
        proc = subprocess.run(
            ["/usr/sbin/ioreg", "-r", "-d", "1", "-c", "IOBlockStorageDriver", "-k", "Statistics"],
            capture_output=True,
            text=True,
            check=False
        )
        if proc.returncode != 0:
            logger.error("ioreg failed: %s", proc.stderr.strip())
            return None
        values = re.findall(r'"Bytes \(Write\)"=([0-9]+)', proc.stdout)
        return sum(int(value) for value in values)
    except Exception as exc:
        logger.error("ioreg exception: %s", exc)
        return None


def get_swap_used_gb(logger):
    try:
        proc = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "vm.swapusage"],
            capture_output=True,
            text=True,
            check=False
        )
        if proc.returncode != 0:
            logger.error("sysctl failed: %s", proc.stderr.strip())
            return None
        text = proc.stdout.strip()
        match = re.search(r"used = ([0-9.]+)([MG])", text)
        if not match:
            return None
        value = float(match.group(1))
        unit = match.group(2)
        if unit == "M":
            return value / 1024.0
        return value
    except Exception as exc:
        logger.error("swap parse exception: %s", exc)
        return None


def compute_cumulative_gb(history, window_seconds):
    now = time.time()
    total = 0
    for ts, delta_bytes in history:
        if (now - ts) <= window_seconds:
            total += delta_bytes
    return total / (1024 * 1024 * 1024)


def load_libproc(logger):
    try:
        libname = ctypes.util.find_library("proc") or "libproc.dylib"
        lib = ctypes.CDLL(libname)
        lib.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        lib.proc_pid_rusage.restype = ctypes.c_int
        return lib
    except Exception as exc:
        logger.error("libproc load failed: %s", exc)
        return None


def list_processes(logger):
    try:
        proc = subprocess.run(
            ["/bin/ps", "-axo", "pid=,comm="],
            capture_output=True,
            text=True,
            check=False
        )
        if proc.returncode != 0:
            logger.error("ps failed: %s", proc.stderr.strip())
            return []
        processes = []
        for line in proc.stdout.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) != 2:
                continue
            pid = int(parts[0])
            name = os.path.basename(parts[1])
            processes.append((pid, name))
        return processes
    except Exception as exc:
        logger.error("ps exception: %s", exc)
        return []


def get_pid_stats(proc_lib, pid):
    info = RusageInfoV2()
    result = proc_lib.proc_pid_rusage(pid, RUSAGE_INFO_V2, ctypes.byref(info))
    if result != 0:
        return None
    memory_bytes = int(info.ri_phys_footprint or info.ri_resident_size)
    return int(info.ri_diskio_byteswritten), memory_bytes, int(info.ri_proc_start_abstime)


def make_process_key(pid, start_abstime):
    return "%s:%s" % (pid, int(start_abstime))


def normalize_process_name(name):
    return os.path.basename(name).lower()


def matches_any(name, patterns):
    value = normalize_process_name(name)
    for pattern in patterns:
        if pattern is None:
            continue
        pat = pattern.lower()
        if pat.endswith("*") and value.startswith(pat[:-1]):
            return True
        if value == pat:
            return True
    return False


def is_safe_process(name, config):
    return matches_any(name, config.get("safe_processes", []))


def is_dangerous_process(name, config):
    return matches_any(name, config.get("dangerous_processes", []))


def is_excluded_system_process(name, config):
    return matches_any(name, config.get("excluded_system_processes", []))


def is_kill_candidate(item, config):
    if item["pid"] == os.getpid():
        return False
    return not is_excluded_system_process(item["name"], config)


def rank_highest_writer_candidates(metrics, config):
    candidates = [
        item for item in metrics
        if is_kill_candidate(item, config) and item["rate_mb_s"] > 0
    ]
    return sorted(candidates, key=lambda item: item["rate_mb_s"], reverse=True)


def rank_daily_culprit_candidates(metrics, sample, config):
    daily_config = config.get("daily", {})
    min_rate_mb_s = float(daily_config.get("action_min_rate_mb_s", 10))
    min_process_gb = float(daily_config.get("action_min_process_gb", 100))
    min_share = float(daily_config.get("action_min_share", 0.25))
    total_daily_bytes = max(1.0, float(sample.get("daily_written_gb", 0.0)) * 1024 * 1024 * 1024)
    min_process_bytes = min_process_gb * 1024 * 1024 * 1024

    candidates = []
    for item in metrics:
        if not is_kill_candidate(item, config):
            continue
        if item["rate_mb_s"] < min_rate_mb_s:
            continue
        daily_bytes = max(
            float(item.get("daily_written_bytes", 0)),
            float(item.get("daily_group_written_bytes", 0))
        )
        daily_share = daily_bytes / total_daily_bytes
        if daily_bytes < min_process_bytes and daily_share < min_share:
            continue
        candidate = dict(item)
        candidate["daily_culprit_bytes"] = daily_bytes
        candidate["daily_share"] = daily_share
        candidates.append(candidate)

    return sorted(
        candidates,
        key=lambda item: (item["daily_culprit_bytes"], item["rate_mb_s"]),
        reverse=True
    )


def rank_highest_memory_candidates(metrics, config):
    candidates = [
        item for item in metrics
        if is_kill_candidate(item, config)
    ]
    return sorted(candidates, key=lambda item: item["memory_bytes"], reverse=True)


def select_highest_writer_process(metrics, config):
    candidates = rank_highest_writer_candidates(metrics, config)
    return candidates[0] if candidates else None


def select_daily_culprit_process(metrics, sample, config):
    candidates = rank_daily_culprit_candidates(metrics, sample, config)
    return candidates[0] if candidates else None


def select_highest_memory_process(metrics, config):
    candidates = rank_highest_memory_candidates(metrics, config)
    return candidates[0] if candidates else None


def describe_process_candidate(item):
    if not item:
        return "pid=- name=- rate=0.00MB/s memory=0.00GB day=0.00GB groupday=0.00GB"
    return (
        "pid=%s name=%s rate=%.2fMB/s memory=%.2fGB day=%.2fGB groupday=%.2fGB" % (
            item.get("pid"),
            item.get("name"),
            float(item.get("rate_mb_s", 0.0)),
            float(item.get("memory_bytes", 0.0)) / (1024 * 1024 * 1024),
            float(item.get("daily_written_bytes", 0.0)) / (1024 * 1024 * 1024),
            float(item.get("daily_group_written_bytes", 0.0)) / (1024 * 1024 * 1024),
        )
    )


def summarize_triggers(sample, config):
    triggers = []
    yellow = config.get("yellow", {})
    red = config.get("red", {})
    daily = config.get("daily", {})

    effective_rate = float(sample.get("effective_rate_mb_s", 0.0))
    cumulative_60 = float(sample.get("cumulative_60_gb", 0.0))
    cumulative_120 = float(sample.get("cumulative_120_gb", 0.0))
    swap_gb = float(sample.get("swap_gb", 0.0))
    daily_written_gb = float(sample.get("daily_written_gb", 0.0))

    if sample.get("rate_red_live"):
        triggers.append(
            "rate-red %.2f>=%.2fMB/s" % (
                effective_rate,
                float(red.get("disk_write_mb_s", 0.0))
            )
        )
    elif effective_rate >= float(yellow.get("disk_write_mb_s", 0.0)):
        triggers.append(
            "rate-yellow %.2f>=%.2fMB/s" % (
                effective_rate,
                float(yellow.get("disk_write_mb_s", 0.0))
            )
        )

    if cumulative_120 >= float(red.get("cumulative_gb", 0.0)):
        triggers.append(
            "c120-red %.2f>=%.2fGB" % (
                cumulative_120,
                float(red.get("cumulative_gb", 0.0))
            )
        )
    elif cumulative_60 >= float(yellow.get("cumulative_gb", 0.0)):
        triggers.append(
            "c60-yellow %.2f>=%.2fGB" % (
                cumulative_60,
                float(yellow.get("cumulative_gb", 0.0))
            )
        )

    if sample.get("swap_red_live"):
        triggers.append(
            "swap-red %.2f>=%.2fGB" % (
                swap_gb,
                float(red.get("swap_gb", 0.0))
            )
        )
    elif swap_gb >= float(yellow.get("swap_gb", 0.0)):
        triggers.append(
            "swap-yellow %.2f>=%.2fGB" % (
                swap_gb,
                float(yellow.get("swap_gb", 0.0))
            )
        )

    if sample.get("daily_red_live"):
        triggers.append(
            "day-red-live %.2f>=%.2fGB and rate>=%.2fMB/s" % (
                daily_written_gb,
                float(daily.get("red_gb", 0.0)),
                float(daily.get("action_min_rate_mb_s", 0.0))
            )
        )
    elif sample.get("daily_red_hit"):
        triggers.append(
            "day-red %.2f>=%.2fGB" % (
                daily_written_gb,
                float(daily.get("red_gb", 0.0))
            )
        )
    elif sample.get("daily_yellow_hit"):
        triggers.append(
            "day-yellow %.2f>=%.2fGB" % (
                daily_written_gb,
                float(daily.get("yellow_gb", 0.0))
            )
        )

    if sample.get("dangerous_writer_hit"):
        triggers.append("dangerous-writer-escalation")

    return triggers or ["no-trigger-details"]


def kill_process(pid, config, logger):
    try:
        if config.get("enable_safe_kill", True):
            os.kill(pid, signal.SIGTERM)
            timeout = time.time() + config.get("kill_timeout_seconds", 10)
            while time.time() < timeout:
                if not is_process_alive(pid):
                    return True
                time.sleep(0.2)
            os.kill(pid, signal.SIGKILL)
            return True
        os.kill(pid, signal.SIGKILL)
        return True
    except Exception as exc:
        logger.error("kill failed pid=%s: %s", pid, exc)
        return False


def is_process_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def main():
    args = parse_args()
    if args.version:
        print(__version__)
        return 0
    if args.runtime_info:
        print(json.dumps(build_runtime_info(args.config, args.state), sort_keys=True))
        return 0
    if not args.once and not args.dry_run:
        setup_daemon_stdio(load_config(args.config))

    protector = SSDProtector(args.config, args.state, once=args.once, dry_run=args.dry_run)
    protector.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

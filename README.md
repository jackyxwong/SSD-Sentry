# SSD Sentry

SSD Sentry is a macOS protection daemon for runaway disk writes. It watches whole-machine write pressure, per-process write activity, rolling cumulative write windows, swap growth, and daily written volume, then reacts before a bad process quietly burns through SSD endurance.

It is designed for unattended Macs, including Mac mini servers, workstations, build boxes, and remote hosts where nobody is watching Activity Monitor all day.

## Disclaimer

> [!WARNING]
> SSD Sentry can kill user processes and can trigger `fdesetup authrestart`.
> Use it at your own risk.
> You are responsible for reviewing thresholds, exclusions, and restart policy before enabling it on any machine that matters.
> A bad configuration can interrupt workloads, terminate important applications, or restart the host.
> Always validate in `dry-run` mode first.

## Why this exists

SSD failures are rarely dramatic at first. A single process can write aggressively for minutes, or write modestly for hours, while nobody notices. By the time the machine feels wrong, the SSD may already have absorbed hundreds of gigabytes or terabytes of avoidable writes.

SSD Sentry exists to enforce a hard operational boundary:

- detect abnormal write pressure early
- identify the most likely culprit
- stop the machine from silently destroying its own storage

## What it does

- Monitors total disk write rate using `ioreg`.
- Tracks per-process write rate using `proc_pid_rusage`.
- Maintains rolling 60-second and 120-second cumulative write windows.
- Tracks daily written volume to catch slow, persistent writers.
- Kills the highest-risk process when RED conditions become actionable.
- Enters an observation window after every kill to avoid kill storms.
- Escalates to `authrestart` if actionable RED cannot be resolved.
- Exposes a live status dashboard with `ssd-sentry status --watch`.
- Writes explainable decision logs, including trigger reasons and top candidates.

## Reaction model

SSD Sentry does not kill on every threshold crossing. It uses staged enforcement.

| State | Meaning | Default action |
| --- | --- | --- |
| `NORMAL` | No threshold breach | Monitor only |
| `YELLOW` | Warning pressure | Monitor only |
| `RED` actionable | Live rate, swap, or daily rule indicates active risk | Kill one process, then observe |
| `OBSERVATION` | Cooling window after a kill | No further kills during the observation period |
| persistent actionable `RED` | RED remains unresolved for `post_kill_restart_seconds` | `fdesetup authrestart` |

### Kill order

1. On the first actionable RED sample, SSD Sentry kills the current highest write-rate process.
2. It then waits for the observation window, default `7` seconds.
3. If RED is still actionable after observation, it switches to memory-ranked cleanup and kills the highest-RAM non-excluded process.
4. If RED is daily-only, it does not blindly kill every writer. It only acts when a dominant current culprit still exists and meets the configured daily-action thresholds.

## Safety model

SSD Sentry deliberately avoids a few bad ideas.

- It never kills itself.
- It never kills core system processes such as `kernel_task`, `launchd`, and `WindowServer`.
- It excludes common remote-access tools, including TeamViewer, AnyDesk, RustDesk, and Google Remote Desktop host patterns.
- It does not manually reset the rolling cumulative windows. Old samples expire naturally.
- It does not keep killing just because daily written volume is already high. Daily RED still requires ongoing live writes.

## Requirements

- macOS with `python3` available on `PATH`
- root access for install and daemon management
- FileVault enabled if you want unattended `authrestart`

## Installation

## Official install: Homebrew

```bash
brew tap jackyxwong/ssd-sentry https://github.com/jackyxwong/SSD-Sentry
brew install jackyxwong/ssd-sentry/ssd-sentry
sudo "$(brew --prefix)/bin/ssd-sentry-setup"
```

Homebrew is the supported installation path for normal users.

## Source checkout: advanced use only

```bash
./ssd-sentry-dry-run.sh
sudo ./ssd-sentry-setup.sh
```

## Quick start

Validate first, enforce second.

```bash
ssd-sentry dry-run
ssd-sentry status
ssd-sentry status --watch
ssd-sentry logs
```

## Commands

| Command | Purpose |
| --- | --- |
| `ssd-sentry status` | One-shot dashboard snapshot |
| `ssd-sentry status --watch` | Live dashboard view |
| `ssd-sentry logs` | Follow main decision log |
| `ssd-sentry logs --err` | Follow daemon stderr log |
| `sudo "$(brew --prefix)/bin/ssd-sentry" reload` | Reload config without full restart |
| `sudo "$(brew --prefix)/bin/ssd-sentry" restart` | Restart the daemon |
| `sudo "$(brew --prefix)/bin/ssd-sentry" stop` | Stop the daemon |
| `sudo "$(brew --prefix)/bin/ssd-sentry" start` | Start the daemon |
| `ssd-sentry dry-run` | Run one non-enforcing test cycle |
| `ssd-sentry config` | Print installed config |
| `sudo "$(brew --prefix)/bin/ssd-sentry" edit-config` | Edit installed config with `nano` |
| `sudo "$(brew --prefix)/bin/ssd-sentry-uninstall"` | Remove SSD Sentry |

## Dashboard and logs

`ssd-sentry status --watch` prefers the daemon's in-memory live snapshot, then falls back to the latest on-disk sample if the live socket is unavailable.

The dashboard shows:

- daemon state and PID
- alert level and operating mode
- live physical and per-process write rate
- rolling 60-second and 120-second cumulative writes
- daily written volume
- top visible writers
- trigger state and observation state
- install consistency between repo and installed copies

## Log files

- Main decision log: `/var/log/ssd-sentry/ssd_sentry_monitor.log`
- Daemon stdout: `/var/log/ssd-sentry/ssd_sentry_daemon.log`
- Daemon stderr: `/var/log/ssd-sentry/ssd_sentry_daemon.err.log`
- Live status socket: `/var/run/ssd-sentry/status.sock`
- State file: `/var/db/ssd-sentry/state.json`

### Log capacity

The main decision log rotates at `50 MB` with `5` backups.

- active file: up to `50 MB`
- backups: `5 x 50 MB`
- total retained main log volume: about `300 MB`

Daemon stdout and stderr also rotate internally at `10 MB` with `5` backups each.

- stdout retained volume: about `60 MB`
- stderr retained volume: about `60 MB`

## Configuration

Edit before install:

```bash
nano ./config.json
```

Edit after install:

```bash
sudo nano /usr/local/ssd-sentry/config.json
```

Important defaults:

- `sample_interval_seconds`: `2`
- `summary_log_interval_seconds`: `10`
- `observation_seconds`: `7`
- `yellow.disk_write_mb_s`: `150`
- `yellow.cumulative_gb`: `20`
- `red.disk_write_mb_s`: `150`
- `red.cumulative_gb`: `40`
- `daily.yellow_gb`: `200`
- `daily.red_gb`: `300`
- `daily.action_min_rate_mb_s`: `10`
- `daily.action_min_process_gb`: `100`
- `daily.action_min_share`: `0.25`
- `post_kill_restart_seconds`: `300`
- `restart_cooldown_seconds`: `3600`

## How the numbers compare to Activity Monitor

Not exactly one-to-one.

SSD Sentry uses different sampling sources and windows than Activity Monitor:

- whole-machine write counters come from `ioreg`
- per-process write counters come from `proc_pid_rusage`
- write rates are calculated over sampled deltas, not Activity Monitor's UI smoothing

The trend should usually agree. Exact numbers at any given second may differ because of caching, sampling interval, and different aggregation windows.

## Explainability

Every kill or restart decision should be reviewable afterward.

SSD Sentry logs:

- which trigger fired
- the chosen strategy
- top candidates considered
- why the selected process was chosen
- when observation mode started
- when restart escalation happened

That makes it practical to tune thresholds instead of guessing.

## Operational recommendations

- Start with `dry-run` on every new machine.
- Review `excluded_system_processes` and add your own must-not-kill tools.
- Tune daily thresholds for the machine's actual workload profile.
- Do not enable automatic restart until FileVault and remote access are confirmed working.
- Treat this as an enforcement tool, not as a substitute for normal capacity monitoring.

## Troubleshooting

Reload after config changes:

```bash
sudo "$(brew --prefix)/bin/ssd-sentry" reload
```

Full restart:

```bash
sudo "$(brew --prefix)/bin/ssd-sentry" restart
```

Check the service directly:

```bash
launchctl print system/com.ssdsentry.daemon
```

Tail the main log:

```bash
tail -f /var/log/ssd-sentry/ssd_sentry_monitor.log
```

## Author

Created and maintained by Jacky Wong.

Official repository:

- [jackyxwong/SSD-Sentry](https://github.com/jackyxwong/SSD-Sentry)

## License

Copyright 2026 Jacky Wong.

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

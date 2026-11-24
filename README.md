# CyberShield — Gold SOC Edition

**Operating Systems semester project** — C++17 concurrent firewall packet simulator with PySide6 Security Operations Center dashboard. This project is a simulator: it does **not** inspect real traffic, block actual network packets, or geolocate network IP addresses.

## Team
- Sidratun Muntaha (24K-2007): SOC dashboard, map visualization, GUI integration.
- Abeeha Shaikh (24K-2031): C++ engine, producer-consumer workers, synchronization, semaphores, priority queues, adaptive workers, benchmarks.
- Fatima Javaid (24K-2032): Firewall and security scenario module, synthetic attack alerts, scenario testing.

## Quick start
See **LAUNCH_ON_KALI.md**.

```bash
cd ~/Desktop/CyberShield
./launch.sh
```

## Features

- C++17 engine with bounded concurrent producer-consumer queue, mutex-protected shared rules, condition variables, 4-worker fixed / adaptive worker pools, per-worker counters, rate limiter built from a mutex/condition-variable counting semaphore, and starvation-aware priority queue.
- First-enabled-match ALLOW/DENY rules, configurable in the GUI. **Rules are persisted** in `config/firewall_rules.json` and restored at startup, including enabled state and order.
- Premium black-and-gold Command Center with responsive six counters, a detailed world map for schematic **synthetic packet routes** (gold ALLOW, red DENY), real engine-derived completion and blocked percentage gauges, and measured allowed/denied packet-rate chart.
- Packet Inspector with ALLOW/DENY filter, matched rule, packet priority and CSV export.
- Worker Monitor with per-thread activity, queue utilization, fixed/adaptive mode, semaphore rate controls, priority packets and engine-backed benchmark.
- Attack Simulator with packet-count presets and three security scenario buttons (port-scan alerts / failed-login alerts modeled, high-traffic workload run in an isolated C++ process).
- Activity Logs and CSV export.

## Tests

Run `make && python3 -m unittest discover -s tests -v` in the project folder. Included tests check engine correctness, 10,000 packet backpressure, semaphore ordering, adaptive workers, priorities, rule matching, simulation modules and rule persistence. Any Python `ResourceWarning` from an unclosed test subprocess stream is non-fatal test harness noise.

## Scope

All packets and attack alerts are synthetic. The map is a visualization of generated events, **not live threat intelligence**. High-traffic scenario runs in a separate engine process so its counts do not increase normal dashboard totals. CSV export of packet decisions is manual, using the GUI buttons.

## Corrections in this build (24 November 2026)

- **Semaphore rate control GUI:** The user-entered rate is no longer erased by
  background STATS polling. Apply sends an explicit `RATE` command and waits for
  the C++ engine to report the requested rate. Engine errors are shown.
- **Queue monitor:** STATS and WORKERS updates now use the same queue format.
  A small history plot shows observed shared queue depth, and the engine's
  reported historical peak remains visible after the queue drains.
- **Unbiased map:** Packet decisions are sampled with equal probability for
  ALLOW and DENY. Old logic sampled every DENY but few ALLOW packets, grossly
  exaggerating the red routes. Routes now fade after approximately 5.5 seconds.
  The diagram is a *schematic* view of selected engine events, not a real map
  of packet origins and destinations or an exact count of decisions.
- **Clock:** Dashboard, main event stream and activity log use local 12-hour
  times with AM/PM. Scenario UTC timestamps are converted to local time for
  display; raw UTC events are preserved in their Python dictionaries.
- **Traffic visualization:** The chart reflects rolling samples from real
  engine counters, and the caption always displays cumulative ALLOW and DENY
  totals beside the current per-second rates. No fabricated live activity.
- **Progress clarity:** A packet status text distinguishes PROCESSING from
  COMPLETE. After COMPLETE, recent sampled route animations may still fade.
- **Scenario table:** Consistent column widths, wrapping and a detailed alert
  evidence panel on selection. Running multiple scenarios reports both new
  and cumulative alert counts in the current GUI session.
- **Worker history:** Per-worker counters explicitly include benchmark work;
  inactive workers can retain prior completed work. BENCH reports its separate
  measured work rather than changing the normal firewall dashboard counters.

The C++ engine's processing logic, Abeeha's synchronisation/rate implementation,
and Fatima's scenario backend are identical to the previously tested Polished
Gold release. All modifications are GUI presentation, GUI interaction and tests.

Run the full automated suite and the short manual Kali checks in
`FINAL_ACCEPTANCE.md` before handing the project in. PySide6 could not be
launched on the build host, so *interactive Kali verification is still required*.

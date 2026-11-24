# CyberShield — final manual Kali acceptance checks

These checks use **synthetic** packets. No real network packet capture,
blocking or geolocation occurs.

## Start

```bash
cd ~/Desktop/CyberShield
chmod +x launch.sh
./launch.sh
```

Run automatic tests at any time:

```bash
make
python3 -m unittest discover -s tests -v
```

## 1. Command Center

- Select 1,000 packets and run. Once finished, Generated and Processed should
  increase by 1,000. ALLOW + DENY = Processed.
- The status should show `COMPLETE` once processing has finished. The map may
  continue **fading recent sampled decisions for a few seconds**; this is not
  ongoing firewall processing.
- The packet map uses a decision-*independent* sample, so 8% DENY traffic
  should not automatically produce almost exclusively red routes. Individual
  samples can differ from the overall ratio.
- `Current ALLOW / DENY pkt/s` will reach zero when idle; the session totals
  below should retain the full counts. Check both the chart spike and totals.
- Top time must show `hh:mm:ss AM/PM` in the correct Kali local zone.

## 2. Firewall Rules and Packet Inspector

- Add `Source IP=*`, `Port=22`, `Protocol=TCP`, `Action=DENY`.
- Run 1,000 packets. DENY records in Packet Inspector should be TCP:22 and
  reference that rule. UDP:22 should continue to be allowed.
- Toggle the rule off and generate more packets; with no other DENY rule,
  the blocked count should not increase.
- Restart CyberShield with the rule disabled: it must remain saved as disabled.
  Re-enable/delete it and restart again to confirm persistence.
- Export Packet Inspector CSV; verify its header and the records in the file.

## 3. Worker Monitor and rate control

- Change fixed pool size and observe `4 active C++ workers`, worker counters,
  and historical inactive workers when applicable.
- Queue history should use **one consistent label** at every update, including
  current total queued, normal queue capacity and engine-reported peak.
- Enter `200` in the RATE spin box. Click APPLY RATE LIMIT. It must **not jump
  back to Unlimited**. Wait until the status confirms **200 packets/sec**.
- Run 1,000 packets. The batch should finish more gradually, approximately
  five seconds at 200 packets/s (runtime depends on engine token bucket and VM).
  Set the rate back to `0` and confirm Unlimited afterward.
- Queue 20 priority packets. The button itself injects those packets; no
  additional RUN PACKETS click is necessary.
- Run `BENCH 4,000 packets, 300 µs` from the GUI. Compare fixed and adaptive
  measured seconds. Worker counters include benchmark processing; normal
  Command Center counters exclude BENCH packets.

## 4. Security Scenario Lab

- Click PORT SCAN, FAILED LOGINS (12), and HIGH TRAFFIC (1,000).
- Three alerts should appear; the top label shows a cumulative alert count.
- Select each row: complete evidence should appear beneath the table, even on
  narrower screens. Scenario table timestamps use **local 12h time**.
- Port scan and login alerts are modeled. High traffic is engine-backed but
  runs in a separate simulated-engine process; main dashboard counters stay unchanged.

## 5. Activity Logs and exports

- Check ENGINE, SIMULATOR, WORKER POOL, BENCHMARK and scenario logs.
- Export Activity Logs and open the CSV. Times should show AM/PM.
- Resize and maximize CyberShield, scroll every page and verify controls and
  panels remain accessible.

## Troubleshooting

- If PySide6 cannot install because Kali has no internet, `./launch.sh` tries
  working older CyberShield `.venv` interpreters automatically.
- If the Kali date/time is wrong, fix the OS timezone/clock first. The app
  does not independently modify system time.
- Every new ZIP extracts into a **separate folder**. Saved rules from older
  folders are not copied automatically; see LAUNCH_ON_KALI.md.
- Screen appearance depends on Kali's font and resolution. If a button or
  graph behaves differently than described, capture its screenshot and the
  terminal output before submitting your assignment.

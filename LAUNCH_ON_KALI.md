# CyberShield — Gold Edition | Kali quick start

This is a **new folder** so the previous Gold/Integrated builds are not overwritten.

## Install (extract the ZIP to the Kali Desktop first)

```bash
cd ~/Desktop
unzip -o CyberShield.zip
cd CyberShield
chmod +x launch.sh setup_kali.sh
./launch.sh
```

The launcher builds `engine/cybershield` with C++17/pthreads and looks for PySide6 in these locations:

1. `./.venv/bin/python` (current project)
2. `../CyberShield_V3_Final_Polished/.venv/bin/python` (previous Polished build, when available)
3. `../CyberShield_V3_Final/.venv/bin/python` (previous Gold build)
4. `../CyberShield_V3_Integrated/.venv/bin/python`
5. `../CyberShield_V3/.venv/bin/python`
6. System Python

**No internet is needed** when one of those interpreters has a working PySide6 installation. If none does, obtain internet connectivity and run `./setup_kali.sh` before launching.

If you receive an `unzip: replace ...?` prompt, you are extracting into an existing folder. You can type `A` for all or use the `-o` option above. The prompt is not a Python or C++ error.

### Running again

```bash
cd ~/Desktop/CyberShield
./launch.sh
```

## Smoke tests

```bash
cd ~/Desktop/CyberShield
make
python3 -m unittest discover -s tests -v
```

### Suggested full acceptance checks

1. Generate 1,000 packets in Command Center; Generated and Processed should catch up to the same cumulative count.
2. Add a wildcard DENY rule for TCP port 22. Generate 1,000; the blocked counter, Packet Inspector DENY filter, and red synthetic map routes should respond.
3. Restart the app: the rule should return. Disable it, restart, and verify that it stays disabled; delete it and restart to check removal.
4. On Worker Monitor, type `200` or `500` in the semaphore rate field, click APPLY RATE LIMIT, and check for the matching confirmed engine value. Generate 1,000 packets. Completion should take about 2 seconds, subject to startup and VM overhead. Set RATE back to 0 afterward.
5. Queue 20 high-priority packets; check the priority counters and Packet Inspector.
6. Run Fixed/Adaptive benchmark (4,000 packets / 300 microseconds); compare the real returned times.
7. On Attack Simulator, run three **synthetic** scenarios. Port scan and failed logins are modeled alerts; high traffic runs an isolated C++ engine process and does not change main dashboard counters.
8. Export the Packet Inspector and Activity Logs CSV files. Try both maximized and smaller windows and check scrollbar behavior.

### Rule storage

Saved firewall rules are written to `config/firewall_rules.json` in **this new project folder**. Existing rules from another CyberShield folder do not move automatically. The C++ engine still evaluates rules in memory; the GUI replays the saved policy when it starts.

### Carry over existing saved rules (optional)

Each release uses its **own** `config/firewall_rules.json`.
If you want the previous saved policy in the corrected build, make sure the
new application is closed, then run:

```bash
mkdir -p ~/Desktop/CyberShield/config
cp ~/Desktop/CyberShield_V3_Final_Polished/config/firewall_rules.json \
   ~/Desktop/CyberShield/config/firewall_rules.json
```

Skip this step if the old policy was deleted or you want a fresh empty rule set.

### Scope and rollback

This is a **synthetic Operating Systems simulator**, not a live kernel firewall or threat-intelligence service. Its map shows schematic packet paths, not actual IP geolocation. Older project folders are untouched; to roll back, simply launch the prior version.

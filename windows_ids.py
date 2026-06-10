"""
Console entry point for the Sentinellama hybrid IDS sensor.

Thin wrapper around monitor.IDSMonitor (forward seek-read watcher) and
core.analyze_log (shared RAG + Ollama brain). Each alert is printed to the
console and persisted to ids_alerts.json by core.

NOTE: Reading the 'Security' event log requires an elevated (Administrator)
terminal; without it the monitor stops with an access-denied error.
"""
import sys
import time

import core
import monitor


def print_alert(alert):
    print(f"\n[ALERT] Event {alert['id']} at {alert['time']}")
    print(f"Cloud Context: {alert['context'][:100]}...")
    print(f"AI Verdict ({alert['risk']}):\n{alert['analysis']}\n" + "-" * 50)


def run_ids():
    print("Initializing Hybrid IDS Sensor...")
    try:
        core.get_index()  # fail fast if the knowledge base isn't seeded yet
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    ids_monitor = monitor.IDSMonitor(on_alert=print_alert)
    ids_monitor.start()
    print("Hybrid IDS is LIVE. Listening for Security Events... (Ctrl+C to stop)")

    try:
        while ids_monitor.running:
            time.sleep(0.5)
        if ids_monitor.last_error:
            print(f"Monitor stopped: {ids_monitor.last_error}")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        ids_monitor.stop()
        while ids_monitor.running:
            time.sleep(0.2)


if __name__ == "__main__":
    run_ids()

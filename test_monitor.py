"""
Integration test for monitor.IDSMonitor's read loop.

Runs the real watcher against the 'Application' log (readable without admin)
and writes real test events into it, verifying:
  1. events existing BEFORE start are ignored,
  2. every event written AFTER start is caught - including successive ones
     (regression: the old backwards-sequential read only ever saw the first).

core.analyze_log is stubbed so no Ollama/Pinecone is needed.
"""
import time

import win32evtlogutil

import core
import monitor

TEST_SOURCE = "SentinellamaTest"
TEST_EVENT_ID = 777


def fake_analyze(log_data, event_id=None, timestamp=None, persist=True):
    return {"id": event_id, "time": timestamp, "log": log_data,
            "context": "stub", "risk": "CLEAN", "analysis": "stub verdict"}


def write_event(msg, event_id=TEST_EVENT_ID, event_type=4):  # 4 = INFORMATION
    win32evtlogutil.ReportEvent(TEST_SOURCE, event_id, eventType=event_type,
                                strings=[msg])


def test_id_matching():
    """Events after start with a watched ID are caught; earlier ones are not."""
    caught = []
    m = monitor.IDSMonitor(on_alert=caught.append,
                           log_name="Application",
                           event_ids={TEST_EVENT_ID},
                           event_types=set(), exclude_ids=set())

    # This event exists BEFORE start - must be ignored.
    write_event("BEFORE-START marker")
    time.sleep(1.0)

    assert m.start(), "monitor failed to start"
    time.sleep(2.0)  # let the thread open the log and snapshot the position
    assert m.running, f"monitor thread died: {m.last_error}"

    # Three successive events - the old backwards read would miss #2 and #3.
    for i in range(1, 4):
        write_event(f"AFTER-START event {i}")
        time.sleep(1.5)

    deadline = time.time() + 10
    while len(caught) < 3 and time.time() < deadline:
        time.sleep(0.3)

    m.stop()
    time.sleep(1.5)

    logs = [a["log"] for a in caught]
    print(f"[id-matching] caught {len(caught)} alerts:")
    for entry in logs:
        print("  -", entry)

    assert not any("BEFORE-START" in s for s in logs), "FAIL: pre-existing event was processed"
    for i in range(1, 4):
        assert any(f"AFTER-START event {i}" in s for s in logs), f"FAIL: missed event {i}"
    assert not m.running, "FAIL: monitor did not stop"
    assert all(a["source"] == "Application" for a in caught), "FAIL: alert missing source log"


def test_type_matching():
    """Severity-based watching: ERROR events caught, INFO ignored, excludes honored."""
    caught = []
    m = monitor.IDSMonitor(on_alert=caught.append,
                           log_name="Application",
                           event_ids=set(),
                           event_types={1},        # ERROR
                           exclude_ids={999})

    assert m.start(), "monitor failed to start"
    time.sleep(2.0)
    assert m.running, f"monitor thread died: {m.last_error}"

    write_event("TYPE-TEST error event", event_id=555, event_type=1)    # caught
    time.sleep(1.5)
    write_event("TYPE-TEST info event", event_id=556, event_type=4)     # ignored
    time.sleep(1.5)
    write_event("TYPE-TEST excluded error", event_id=999, event_type=1) # excluded
    time.sleep(1.5)

    deadline = time.time() + 8
    while not caught and time.time() < deadline:
        time.sleep(0.3)

    m.stop()
    time.sleep(1.5)

    logs = [a["log"] for a in caught]
    print(f"[type-matching] caught {len(caught)} alerts:")
    for entry in logs:
        print("  -", entry)

    assert any("TYPE-TEST error event" in s for s in logs), "FAIL: ERROR-type event missed"
    assert not any("TYPE-TEST info event" in s for s in logs), "FAIL: INFO-type event processed"
    assert not any("TYPE-TEST excluded" in s for s in logs), "FAIL: excluded ID processed"
    assert caught[0]["etype"] == "ERROR", "FAIL: alert missing event type"


def main():
    core.analyze_log = fake_analyze  # stub the heavy path
    test_id_matching()
    test_type_matching()
    print("ALL PASS")


if __name__ == "__main__":
    main()

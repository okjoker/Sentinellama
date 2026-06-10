"""
Windows event-log monitors for Sentinellama.

IDSMonitor wraps one event log ('Security', 'System', 'Application', ...) in a
start/stoppable background thread. Each matching event is analyzed via
core.analyze_log and handed to an optional on_alert callback for live
broadcast.

Matching policy (per log, see LOG_CONFIGS): an event is analyzed when its ID
is in event_ids OR its type is in event_types, unless its ID is in
exclude_ids. Security needs an ID whitelist (audit volume is huge); System and
Application are watched by severity instead, since any app can log errors.

NOTE: Reading the 'Security' log requires the process to run elevated
(Administrator); 'System' and 'Application' do not. A monitor that fails keeps
the failure in .last_error, which the UI surfaces per log.
"""
import threading

import win32event
import win32evtlog
import win32evtlogutil

import core

EVENT_TYPE_NAMES = {
    win32evtlog.EVENTLOG_ERROR_TYPE: "ERROR",
    win32evtlog.EVENTLOG_WARNING_TYPE: "WARNING",
    win32evtlog.EVENTLOG_INFORMATION_TYPE: "INFORMATION",
    win32evtlog.EVENTLOG_AUDIT_SUCCESS: "AUDIT_SUCCESS",
    win32evtlog.EVENTLOG_AUDIT_FAILURE: "AUDIT_FAILURE",
}

LOG_CONFIGS = {
    "Security": {
        # 1102 audit log cleared, 4625 failed logon, 4648 explicit-credential
        # logon, 4698 scheduled task created, 4720 account created, 4724
        # password reset attempt, 4732 added to security-enabled group,
        # 4740 account locked out, 5382 vault credentials read.
        "event_ids": {1102, 4625, 4648, 4698, 4720, 4724, 4732, 4740, 5382},
        "event_types": set(),
        "exclude_ids": set(),
    },
    "System": {
        "event_ids": {7045},  # new service installed - classic persistence
        "event_types": {win32evtlog.EVENTLOG_ERROR_TYPE,
                        win32evtlog.EVENTLOG_WARNING_TYPE},
        "exclude_ids": {10010, 10016},  # chronic DCOM permission noise
    },
    "Application": {
        "event_ids": set(),
        "event_types": {win32evtlog.EVENTLOG_ERROR_TYPE,
                        win32evtlog.EVENTLOG_WARNING_TYPE},
        "exclude_ids": set(),
    },
}

# Backwards-compat alias: the original Security whitelist.
WATCH_EVENT_IDS = LOG_CONFIGS["Security"]["event_ids"]


class IDSMonitor:
    def __init__(self, on_alert=None, log_name="Security",
                 event_ids=None, event_types=None, exclude_ids=None):
        cfg = LOG_CONFIGS.get(log_name, {})
        self.on_alert = on_alert
        self.log_name = log_name
        self.event_ids = set(cfg.get("event_ids", ())) if event_ids is None else set(event_ids)
        self.event_types = set(cfg.get("event_types", ())) if event_types is None else set(event_types)
        self.exclude_ids = set(cfg.get("exclude_ids", ())) if exclude_ids is None else set(exclude_ids)
        self._thread = None
        self._stop = threading.Event()
        self._running = False
        self.last_error = None

    @property
    def running(self):
        return self._running

    def start(self):
        if self._running:
            return False
        self.last_error = None
        self._stop.clear()
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        if not self._running:
            return False
        self._stop.set()
        return True

    # --- internal ---
    def _run(self):
        try:
            handle = win32evtlog.OpenEventLog(None, self.log_name)
            h_event = win32event.CreateEvent(None, 0, 0, None)
            win32evtlog.NotifyChangeEventLog(handle, h_event)

            # Only analyze events that arrive AFTER we start. Track the newest
            # record number and seek-read FORWARDS past it on each wake-up.
            # (A sequential BACKWARDS read on a persistent handle keeps moving
            # further into the past and never sees newly appended records.)
            last_record = self._newest_record(handle)

            while not self._stop.is_set():
                # The notification is only an accelerator: we also poll on the
                # 1s timeout, so a missed notification can't stall the feed
                # and stop() stays responsive.
                win32event.WaitForSingleObject(h_event, 1000)
                last_record = self._drain_new(handle, last_record)
        except Exception as e:
            self.last_error = str(e)
        finally:
            self._running = False

    @staticmethod
    def _newest_record(handle):
        oldest = win32evtlog.GetOldestEventLogRecord(handle)
        count = win32evtlog.GetNumberOfEventLogRecords(handle)
        return oldest + count - 1 if count else 0

    def _drain_new(self, handle, last_record):
        """Read and process every record newer than last_record."""
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
        while not self._stop.is_set():
            try:
                events = win32evtlog.ReadEventLog(handle, flags, last_record + 1)
            except Exception:
                # Seek target gone (log cleared/rotated) - resync to the end.
                return self._newest_record(handle)
            if not events:
                break
            for event in events:
                if event.RecordNumber > last_record:
                    last_record = event.RecordNumber
                eid = event.EventID & 0xFFFF
                if self._matches(eid, event.EventType):
                    self._process(eid, event)
            # Continue forward from the current position for the next batch.
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        return last_record

    def _matches(self, eid, etype):
        if eid in self.exclude_ids:
            return False
        return eid in self.event_ids or etype in self.event_types

    def _format_event(self, event):
        """Render the full event message; fall back to raw string inserts."""
        message = None
        try:
            message = win32evtlogutil.SafeFormatMessage(event, self.log_name)
        except Exception:
            pass
        if not message:
            message = " | ".join(str(s) for s in (event.StringInserts or []))
        return " ".join(str(message).split())[:2000]

    def _process(self, eid, event):
        etype = EVENT_TYPE_NAMES.get(event.EventType, str(event.EventType))
        timestamp = event.TimeGenerated.Format("%Y-%m-%d %H:%M:%S")
        message = self._format_event(event)
        log_data = (f"[{self.log_name} log] Source: {event.SourceName} | "
                    f"Type: {etype} | Event ID {eid}: {message}")
        try:
            alert = core.analyze_log(log_data, event_id=eid, timestamp=timestamp,
                                     source=self.log_name, etype=etype,
                                     query_text=message)
        except Exception as e:
            alert = {
                "id": eid,
                "time": timestamp,
                "log": log_data,
                "context": "",
                "source": self.log_name,
                "etype": etype,
                "risk": "ERROR",
                "analysis": f"Analysis error: {e}",
            }
            core.append_alert(alert)

        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception:
                pass

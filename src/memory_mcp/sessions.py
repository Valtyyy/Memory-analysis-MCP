"""Thread-safe registry of attached processes and value scans."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanSession:
    scan_id: str
    scanner: Any
    handle_id: str
    type: str
    created: float = field(default_factory=time.time)


class SessionRegistry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._procs: dict[str, Any] = {}
        self._scans: dict[str, ScanSession] = {}
        self._next_handle = 1
        self._next_scan = 1

    # ---- processes
    def add_process(self, process: Any) -> str:
        with self._lock:
            hid = f"h{self._next_handle}"
            self._next_handle += 1
            self._procs[hid] = process
            return hid

    def find_handle(self, pid: int) -> str | None:
        with self._lock:
            for hid, p in self._procs.items():
                if p.pid == pid:
                    return hid
        return None

    def get_process(self, handle_id: str) -> Any:
        with self._lock:
            proc = self._procs.get(handle_id)
        if proc is None:
            raise ValueError(f"Unknown handle_id {handle_id!r}; use attach_process first")
        if not proc.is_alive():
            self.detach(handle_id)
            raise ValueError(f"Process for handle {handle_id!r} (pid {proc.pid}) has exited; handle was released")
        return proc

    def detach(self, handle_id: str) -> int:
        """Remove a handle and its scans. Returns number of scans removed."""
        with self._lock:
            if handle_id not in self._procs:
                raise ValueError(f"Unknown handle_id {handle_id!r}")
            del self._procs[handle_id]
            dead = [s for s, v in self._scans.items() if v.handle_id == handle_id]
            for s in dead:
                del self._scans[s]
            return len(dead)

    def list_handles(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._procs)

    # ---- scans
    def add_scan(self, scanner: Any, handle_id: str, type_: str) -> str:
        with self._lock:
            sid = f"s{self._next_scan}"
            self._next_scan += 1
            self._scans[sid] = ScanSession(sid, scanner, handle_id, type_)
            return sid

    def get_scan(self, scan_id: str) -> ScanSession:
        with self._lock:
            s = self._scans.get(scan_id)
            if s is None:
                raise ValueError(f"Unknown scan_id {scan_id!r}; start one with scan_value")
            hid = s.handle_id
        self.get_process(hid)  # raises if the process is gone (and drops the scan)
        with self._lock:
            s = self._scans.get(scan_id)
        if s is None:
            raise ValueError(f"Unknown scan_id {scan_id!r}")
        return s

    def delete_scan(self, scan_id: str) -> None:
        with self._lock:
            if scan_id not in self._scans:
                raise ValueError(f"Unknown scan_id {scan_id!r}")
            del self._scans[scan_id]

    def list_scans(self) -> list[ScanSession]:
        with self._lock:
            return list(self._scans.values())


registry = SessionRegistry()

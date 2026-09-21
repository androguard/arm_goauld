#!/usr/bin/env python3
"""Compare goauld/quickjs, goauld/symbiote, and Frida on the Android emulator.

Metrics per engine (fresh `toybox sleep` pid each time):
  - binary size on disk (agent .so / frida-server)
  - process memory: baseline → after agent → after workload (Rss / Pss / RssAnon)
  - host: inject or attach wall time
  - host: script-load ping median (5 samples, agent already live)
  - in-process: compute / memory / alloc / send (identical JS fixture)

Usage:
  python3 scripts/bench-js-engines.py
  python3 scripts/bench-js-engines.py --engines quickjs,symbiote
  python3 scripts/bench-js-engines.py --out dist/bench.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import statistics
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / "target" / "release" / "goauld"
SCRIPT = ROOT / "scripts" / "fixtures" / "bench_engines.js"
PING = ROOT / "scripts" / "fixtures" / "bench_ping.js"
ADB = os.environ.get("ADB", "adb")
SDK = Path.home() / "Library/Android/sdk/platform-tools"
os.environ["PATH"] = f"{SDK}:{os.environ.get('PATH', '')}"

# Expected sinks for correctness (add stays in int32; add_acc wraps).
EXPECTED_SINK = {
    "add": 5000000,
    "prop": 6000000,
    "call": 1000000,
    "addr_add": 0x1000 + 4 * 1000000,
    "np_add": 0x1000 + 4 * 1000000,
    "str": 50000,
    "alloc": 100000,
}
# add_acc: sum(0..n-1)|0 with JS ToInt32 wrap → 1642668640 for n=5e6
EXPECTED_SINK_ADD_ACC = 1642668640

BENCH_NAMES = [
    "add",
    "add_acc",
    "prop",
    "call",
    "readU32",
    "addr_add",
    "np_add",
    "str",
    "alloc",
    "send",
]


def run(cmd, timeout=60, check=True):
    p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    if check and p.returncode != 0:
        raise SystemExit(
            f"command failed ({p.returncode}): {' '.join(map(str, cmd))}\n"
            f"{p.stdout}\n{p.stderr}"
        )
    return p


def adb(*args, timeout=30, check=True):
    return run([ADB, *args], timeout=timeout, check=check)


def start_sleep() -> int:
    adb("shell", "pkill -9 -f 'toybox sleep 3600'", check=False)
    time.sleep(0.3)
    p = adb("shell", "toybox sleep 3600 >/dev/null 2>&1 & echo $!")
    pid = int(p.stdout.strip().splitlines()[-1])
    time.sleep(0.4)
    return pid


def kill_pid(pid: int):
    adb("shell", f"kill -9 {pid}", check=False)


def parse_mem(text: str) -> dict:
    out = {}
    for key in ("Rss", "Pss", "RssAnon", "Private_Dirty"):
        m = re.search(rf"^{key}:\s+(\d+)\s+kB", text, re.M)
        if m:
            out[key.lower() + "_kb"] = int(m.group(1))
    return out


def mem_snapshot(pid: int) -> dict:
    p = adb("shell", f"cat /proc/{pid}/smaps_rollup", check=False)
    snap = parse_mem(p.stdout)
    st = adb("shell", f"grep -E '^(VmRSS|VmSize|VmPeak):' /proc/{pid}/status", check=False)
    for line in st.stdout.splitlines():
        m = re.match(r"(Vm\w+):\s+(\d+)\s+kB", line.strip())
        if m:
            snap[m.group(1).lower() + "_kb"] = int(m.group(2))
    # Agent-mapped size if present in maps.
    maps = adb("shell", f"grep -E 'libgoauld_agent|frida-agent|frida-gadget' /proc/{pid}/maps || true", check=False)
    mapped = 0
    libs = set()
    for line in maps.stdout.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        start, end = parts[0].split("-")
        mapped += int(end, 16) - int(start, 16)
        libs.add(parts[-1])
    if mapped:
        snap["agent_mapped_kb"] = mapped // 1024
        snap["agent_maps"] = sorted(libs)
    return snap


def delta_kb(after: dict, before: dict, key: str) -> int | None:
    if key not in after or key not in before:
        return None
    return after[key] - before[key]


def file_size(path: Path) -> int | None:
    return path.stat().st_size if path.is_file() else None


def parse_payloads(text: str) -> list:
    payloads = []
    for line in text.splitlines():
        if "send[" not in line or "{" not in line:
            # also accept bare JSON send lines
            if not (line.strip().startswith("{") and '"type"' in line):
                continue
            raw = line.strip()
        else:
            raw = line.split(":", 1)[-1].strip()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                continue
        if isinstance(payload, dict):
            payloads.append(payload)
    return payloads


def benches_from_payloads(payloads: list) -> dict:
    out = {}
    for payload in payloads:
        if payload.get("type") != "bench":
            continue
        ms = payload["ms"]
        out[payload["name"]] = {
            "iters": payload["iters"],
            "ms": ms,
            "median_ms": statistics.median(ms),
            "min_ms": min(ms),
            "max_ms": max(ms),
            "sink": payload.get("sink"),
        }
    return out


def errors_from_payloads(payloads: list) -> list:
    return [
        {"name": p.get("name"), "err": p.get("err")}
        for p in payloads
        if p.get("type") == "bench-error"
    ]


def meta_from_payloads(payloads: list) -> dict:
    for payload in payloads:
        if payload.get("type") == "bench-meta":
            return payload
    return {}


def goauld_inject(dist: Path, pid: int) -> float:
    t0 = time.perf_counter()
    run(
        [
            str(HOST),
            "inject",
            "--pid",
            str(pid),
            "--injector",
            str(dist / "goauld-injector"),
            "--agent",
            str(dist / "libgoauld_agent.so"),
        ],
        timeout=40,
    )
    return time.perf_counter() - t0


def goauld_attach(
    pid: int, port: int, script: Path, needle: str, wait: int, check: bool = True
) -> tuple[float, str, int]:
    t0 = time.perf_counter()
    p = run(
        [
            str(HOST),
            "attach",
            "--pid",
            str(pid),
            "--port",
            str(port),
            "--script",
            str(script),
            "--expect-send",
            needle,
            "--max-wait-secs",
            str(wait),
        ],
        timeout=wait + 30,
        check=check,
    )
    return time.perf_counter() - t0, p.stdout + p.stderr, p.returncode


MSG_HELLO = 0x01
MSG_SCRIPT_LOAD = 0x02
MSG_SEND = 0x06
MSG_LOG = 0x07


class GoauldSession:
    """Persistent agent connection — same shape as Frida session.create_script."""

    def __init__(self, sock: socket.socket, hello: dict, port: int):
        self.sock = sock
        self.hello = hello
        self.port = port
        self._script_id = 1
        self._buf = bytearray()

    @classmethod
    def open(cls, pid: int, port: int, timeout: float = 8.0) -> "GoauldSession":
        ensure_forward(pid, port)
        deadline = time.perf_counter() + timeout
        last_err: Exception | None = None
        while time.perf_counter() < deadline:
            sock = None
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=0.4)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.settimeout(1.0)
                sess = cls(sock, {}, port)
                msg = sess._read_msg()
                if msg.get("type") != "hello":
                    sock.close()
                    raise RuntimeError(f"expected hello, got {msg}")
                sess.hello = msg.get("hello") or {}
                sock.settimeout(60.0)
                return sess
            except Exception as e:
                last_err = e
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
                time.sleep(0.05)
        raise RuntimeError(f"goauld session open failed: {last_err}")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def load_expect(self, source: str, needle: str, wait: float = 30.0) -> tuple[float, list]:
        """ScriptLoad on this live session; return (seconds, payloads)."""
        self._script_id += 1
        sid = self._script_id
        frame = _encode_script_load(sid, source)
        payloads = []
        t0 = time.perf_counter()
        self.sock.sendall(frame)
        deadline = time.perf_counter() + wait
        while time.perf_counter() < deadline:
            try:
                msg = self._read_msg()
            except socket.timeout:
                continue
            if msg.get("type") == "send":
                payloads.append(msg.get("payload"))
                raw = msg.get("payload")
                text = raw if isinstance(raw, str) else json.dumps(raw, separators=(",", ":"))
                if needle in text:
                    return time.perf_counter() - t0, payloads
            elif msg.get("type") == "log" and "error" in str(msg.get("level", "")).lower():
                raise RuntimeError(msg.get("message") or "agent log error")
        raise TimeoutError(f"timed out waiting for {needle!r}")

    def _read_msg(self) -> dict:
        while True:
            if len(self._buf) >= 4:
                total = struct.unpack_from("<I", self._buf, 0)[0]
                need = 4 + total
                if len(self._buf) >= need:
                    frame = bytes(self._buf[:need])
                    del self._buf[:need]
                    return _decode_frame(frame)
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("agent closed connection")
            self._buf.extend(chunk)


def ensure_forward(pid: int, port: int):
    spec = f"tcp:{port}"
    local = f"localabstract:goauld-agent-{pid}"
    # Always refresh — a stale forward to a dead abstract socket accepts TCP then
    # never delivers Hello (looks like a hang / "timed out").
    adb("forward", "--remove", spec, check=False)
    run([ADB, "forward", spec, local])


def _encode_script_load(script_id: int, source: str) -> bytes:
    payload = json.dumps({"script_id": script_id, "source": source}, separators=(",", ":")).encode()
    body = bytes([MSG_SCRIPT_LOAD]) + payload
    return struct.pack("<I", len(body)) + body


def _decode_frame(frame: bytes) -> dict:
    total = struct.unpack_from("<I", frame, 0)[0]
    msg_type = frame[4]
    payload = frame[5 : 4 + total]
    if msg_type == MSG_HELLO:
        return {"type": "hello", "hello": json.loads(payload)}
    if msg_type == MSG_LOG:
        return {"type": "log", **json.loads(payload)}
    if msg_type == MSG_SEND:
        if len(payload) < 8:
            return {"type": "send", "payload": None}
        json_len = struct.unpack_from("<I", payload, 0)[0]
        meta = json.loads(payload[4 : 4 + json_len])
        raw = meta.get("payload_json", "")
        try:
            parsed = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            parsed = raw
        return {"type": "send", "payload": parsed, "script_id": meta.get("script_id")}
    return {"type": f"0x{msg_type:02x}"}


def wait_agent_ready(pid: int, seconds: float = 2.0):
    deadline = time.perf_counter() + seconds
    while time.perf_counter() < deadline:
        time.sleep(0.15)
        # abstract socket exists once ctor has listened
        p = adb(
            "shell",
            f"cat /proc/net/unix 2>/dev/null | grep -F goauld-agent-{pid} || true",
            check=False,
        )
        if f"goauld-agent-{pid}" in p.stdout:
            return
    time.sleep(0.3)


def artifact_info(kind: str, dist: Path | None = None) -> dict:
    if kind.startswith("goauld"):
        assert dist is not None
        agent = dist / "libgoauld_agent.so"
        injector = dist / "goauld-injector"
        ver = (dist / "VERSION.txt").read_text().strip() if (dist / "VERSION.txt").is_file() else ""
        return {
            "agent_path": str(agent),
            "agent_bytes": file_size(agent),
            "injector_bytes": file_size(injector),
            "version_txt": ver,
        }
    # Frida: prefer known download, else device binary size via stat
    candidates = [
        Path(f"/tmp/frida-server-{os.environ.get('FRIDA_VERSION', '17.18.0')}-android-arm64"),
        Path("/tmp/frida-server-android-arm64"),
        ROOT / "dist" / "frida-server-android-arm64",
    ]
    local = next((p for p in candidates if p.is_file()), None)
    info = {"agent_path": str(local) if local else "/data/local/tmp/frida-server"}
    if local:
        info["agent_bytes"] = file_size(local)
    else:
        p = adb("shell", "stat -c %s /data/local/tmp/frida-server 2>/dev/null || echo 0", check=False)
        try:
            info["agent_bytes"] = int(p.stdout.strip() or "0") or None
        except ValueError:
            info["agent_bytes"] = None
    info["injector_bytes"] = None
    info["version_txt"] = ""
    return info


def bench_goauld(name: str, dist: Path, port: int) -> dict:
    if not (dist / "libgoauld_agent.so").is_file():
        raise SystemExit(f"missing agent: {dist / 'libgoauld_agent.so'}")
    arts = artifact_info(name, dist)
    pid = start_sleep()
    session = None
    try:
        mem_base = mem_snapshot(pid)
        inject_s = goauld_inject(dist, pid)
        wait_agent_ready(pid)
        mem_after_agent = mem_snapshot(pid)

        # One live session for ping + workload, matching Frida's session.create_script.
        session = GoauldSession.open(pid, port)
        hello_obj = session.hello
        hello = (
            f"pid={hello_obj.get('pid')} pkg={hello_obj.get('package')} "
            f"sdk={hello_obj.get('sdk_int')} abi={hello_obj.get('abi')} "
            f"version={hello_obj.get('version')}"
        )

        ping_src = PING.read_text()
        # Warm the session once (compile/eval path), then time steady-state loads —
        # same shape as Frida's create_script after attach.
        session.load_expect(ping_src, "ping", wait=15)
        pings = []
        for _ in range(5):
            dt, _payloads = session.load_expect(ping_src, "ping", wait=15)
            pings.append(dt)
        mem_after_ping = mem_snapshot(pid)

        src = SCRIPT.read_text()
        wall, payloads = session.load_expect(src, "bench-ok", wait=180)
        # payloads may be dicts already
        dict_payloads = []
        for p in payloads:
            if isinstance(p, dict):
                dict_payloads.append(p)
            elif isinstance(p, str):
                try:
                    v = json.loads(p)
                    if isinstance(v, dict):
                        dict_payloads.append(v)
                except json.JSONDecodeError:
                    pass
        benches = benches_from_payloads(dict_payloads)
        meta = meta_from_payloads(dict_payloads)
        errors = errors_from_payloads(dict_payloads)
        if "add" not in benches:
            raise SystemExit(f"{name}: no bench results\n{payloads[-12:]}")
        mem_after_bench = mem_snapshot(pid)
        return {
            "engine": name,
            "kind": "goauld",
            "hello": hello,
            "meta": meta,
            "errors": errors,
            "artifacts": arts,
            "pid": pid,
            "inject_or_attach_s": inject_s,
            "ping_s": pings,
            "ping_median_s": statistics.median(pings),
            "script_wall_s": wall,
            "benches": benches,
            "memory": {
                "baseline": mem_base,
                "after_agent": mem_after_agent,
                "after_ping": mem_after_ping,
                "after_bench": mem_after_bench,
                "delta_agent_pss_kb": delta_kb(mem_after_agent, mem_base, "pss_kb"),
                "delta_agent_rss_kb": delta_kb(mem_after_agent, mem_base, "rss_kb"),
                "delta_bench_pss_kb": delta_kb(mem_after_bench, mem_base, "pss_kb"),
                "delta_bench_rss_kb": delta_kb(mem_after_bench, mem_base, "rss_kb"),
            },
        }
    finally:
        if session is not None:
            session.close()
        kill_pid(pid)


def ensure_frida_server():
    p = adb("shell", "pidof frida-server", check=False)
    if p.stdout.strip():
        return
    adb("shell", "setenforce 0", check=False)
    adb(
        "shell",
        "/data/local/tmp/frida-server -D >/data/local/tmp/frida-server.log 2>&1 &",
        check=False,
    )
    time.sleep(1.0)
    p = adb("shell", "pidof frida-server", check=False)
    if not p.stdout.strip():
        raise SystemExit("frida-server is not running on the device")


def bench_frida() -> dict:
    import frida

    ensure_frida_server()
    arts = artifact_info("frida")
    arts["version_txt"] = f"frida {frida.__version__}"
    pid = start_sleep()
    try:
        mem_base = mem_snapshot(pid)
        device = frida.get_usb_device(timeout=10)
        t0 = time.perf_counter()
        session = device.attach(pid)
        attach_s = time.perf_counter() - t0
        time.sleep(0.4)
        mem_after_agent = mem_snapshot(pid)

        ping_src = PING.read_text()
        pings = []
        for _ in range(5):
            box = {"hit": False}

            def on_message(message, _data, box=box):
                if message.get("type") == "send":
                    box["hit"] = True

            script = session.create_script(ping_src)
            script.on("message", on_message)
            t0 = time.perf_counter()
            script.load()
            deadline = time.perf_counter() + 15
            while not box["hit"] and time.perf_counter() < deadline:
                time.sleep(0.005)
            pings.append(time.perf_counter() - t0)
            script.unload()
        mem_after_ping = mem_snapshot(pid)

        src = SCRIPT.read_text()
        messages = []
        errors = []

        def on_bench(message, _data):
            if message.get("type") == "error":
                errors.append(message.get("description") or str(message))
            elif message.get("type") == "send":
                messages.append(message.get("payload"))

        script = session.create_script(src)
        script.on("message", on_bench)
        t0 = time.perf_counter()
        script.load()
        deadline = time.perf_counter() + 180
        while time.perf_counter() < deadline:
            if errors:
                raise SystemExit(f"frida script error: {errors[0]}")
            if any(isinstance(m, dict) and m.get("type") == "bench-ok" for m in messages):
                break
            time.sleep(0.02)
        wall = time.perf_counter() - t0
        payloads = [m for m in messages if isinstance(m, dict)]
        benches = benches_from_payloads(payloads)
        meta = meta_from_payloads(payloads)
        errors = errors_from_payloads(payloads)
        if "add" not in benches:
            raise SystemExit(f"frida: no bench results: {messages[-12:]}")
        mem_after_bench = mem_snapshot(pid)
        return {
            "engine": "frida",
            "kind": "frida",
            "hello": f"frida {frida.__version__}",
            "meta": meta,
            "errors": errors,
            "artifacts": arts,
            "pid": pid,
            "inject_or_attach_s": attach_s,
            "ping_s": pings,
            "ping_median_s": statistics.median(pings),
            "script_wall_s": wall,
            "benches": benches,
            "memory": {
                "baseline": mem_base,
                "after_agent": mem_after_agent,
                "after_ping": mem_after_ping,
                "after_bench": mem_after_bench,
                "delta_agent_pss_kb": delta_kb(mem_after_agent, mem_base, "pss_kb"),
                "delta_agent_rss_kb": delta_kb(mem_after_agent, mem_base, "rss_kb"),
                "delta_bench_pss_kb": delta_kb(mem_after_bench, mem_base, "pss_kb"),
                "delta_bench_rss_kb": delta_kb(mem_after_bench, mem_base, "rss_kb"),
            },
        }
    finally:
        kill_pid(pid)


def ns_per(row: dict, name: str) -> float | None:
    b = row["benches"].get(name)
    if not b or b["median_ms"] <= 0:
        return None
    return (b["median_ms"] * 1_000_000.0) / b["iters"]


def fmt_ns(v: float | None) -> str:
    if v is None:
        return "n/a"
    if v >= 1000:
        return f"{v / 1000:.2f} µs"
    return f"{v:.1f} ns"


def fmt_bytes(n: int | None) -> str:
    if n is None:
        return "n/a"
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.2f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


def fmt_kb(n: int | None) -> str:
    if n is None:
        return "n/a"
    if abs(n) >= 1024:
        return f"{n / 1024:.2f} MB"
    return f"{n} KB"


def correctness(row: dict) -> list[str]:
    notes = []
    for name, expect in EXPECTED_SINK.items():
        b = row["benches"].get(name)
        if not b:
            notes.append(f"{name}: missing")
            continue
        if b["sink"] != expect:
            notes.append(f"{name}: sink={b['sink']} expected={expect}")
    b = row["benches"].get("add_acc")
    if b and b["sink"] != EXPECTED_SINK_ADD_ACC:
        notes.append(f"add_acc: sink={b['sink']} expected={EXPECTED_SINK_ADD_ACC} (ToInt32 wrap)")
    return notes


def print_report(results: list[dict], device: dict):
    print()
    print("=== device ===")
    for k, v in device.items():
        print(f"  {k}: {v}")

    print()
    print("=== artifacts ===")
    print(f"{'engine':<18} {'agent on disk':>14} {'injector':>12} version")
    for row in results:
        a = row["artifacts"]
        print(
            f"{row['engine']:<18} {fmt_bytes(a.get('agent_bytes')):>14} "
            f"{fmt_bytes(a.get('injector_bytes')):>12} {a.get('version_txt', '')[:60]}"
        )

    print()
    print("=== memory (target process) ===")
    print(
        f"{'engine':<18} {'ΔPss agent':>12} {'ΔRss agent':>12} "
        f"{'ΔPss after bench':>18} {'mapped':>10}"
    )
    for row in results:
        m = row["memory"]
        mapped = m["after_bench"].get("agent_mapped_kb")
        if mapped is None:
            mapped = m["after_agent"].get("agent_mapped_kb")
        print(
            f"{row['engine']:<18} {fmt_kb(m.get('delta_agent_pss_kb')):>12} "
            f"{fmt_kb(m.get('delta_agent_rss_kb')):>12} "
            f"{fmt_kb(m.get('delta_bench_pss_kb')):>18} "
            f"{fmt_kb(mapped):>10}"
        )
        print(
            f"  baseline Pss={fmt_kb(m['baseline'].get('pss_kb'))}  "
            f"after_agent Pss={fmt_kb(m['after_agent'].get('pss_kb'))}  "
            f"after_bench Pss={fmt_kb(m['after_bench'].get('pss_kb'))}"
        )

    print()
    print("=== host latency ===")
    print(f"{'engine':<18} {'inject/attach':>14} {'ping median':>12} {'script wall':>12}")
    for row in results:
        label = "inject" if row["kind"] == "goauld" else "attach"
        print(
            f"{row['engine']:<18} {row['inject_or_attach_s'] * 1000:10.0f} ms "
            f"{row['ping_median_s'] * 1000:8.1f} ms "
            f"{row['script_wall_s'] * 1000:8.0f} ms  ({label})"
        )
        print(f"  ping samples ms: {[round(x * 1000, 1) for x in row['ping_s']]}")
        if row.get("hello"):
            print(f"  hello: {row['hello']}")
        if row.get("meta"):
            print(f"  meta: {row['meta']}")

    print()
    print("=== in-process speed (median) ===")
    hdr = f"{'engine':<18}" + "".join(f"{n:>12}" for n in BENCH_NAMES)
    print(hdr)
    for row in results:
        cells = [f"{row['engine']:<18}"]
        for name in BENCH_NAMES:
            b = row["benches"].get(name)
            if not b:
                cells.append(f"{'missing':>12}")
            else:
                cells.append(f"{fmt_ns(ns_per(row, name)):>12}")
        print("".join(cells))

    print()
    print("=== in-process wall (median ms) ===")
    hdr = f"{'engine':<18}" + "".join(f"{n:>10}" for n in BENCH_NAMES)
    print(hdr)
    for row in results:
        cells = [f"{row['engine']:<18}"]
        for name in BENCH_NAMES:
            b = row["benches"].get(name)
            cells.append(f"{b['median_ms'] if b else float('nan'):>10.1f}" if b else f"{'n/a':>10}")
        print("".join(cells))
        for name in BENCH_NAMES:
            b = row["benches"].get(name)
            if b:
                print(f"  {name}: samples={ [round(x, 2) for x in b['ms']] } sink={b['sink']}")

    # Relative to Frida when present, else to first engine.
    base = next((r for r in results if r["engine"] == "frida"), results[0])
    print()
    print(f"=== relative to {base['engine']} (lower is better; <1 means faster/smaller) ===")
    print(f"{'metric':<28}" + "".join(f"{r['engine']:>16}" for r in results))
    metrics = [
        ("agent_bytes", lambda r: r["artifacts"].get("agent_bytes")),
        ("ΔPss agent", lambda r: r["memory"].get("delta_agent_pss_kb")),
        ("ΔPss after bench", lambda r: r["memory"].get("delta_bench_pss_kb")),
        ("inject/attach", lambda r: r["inject_or_attach_s"]),
        ("ping median", lambda r: r["ping_median_s"]),
    ]
    for name in BENCH_NAMES:
        metrics.append((f"speed:{name}", lambda r, n=name: ns_per(r, n)))
    for label, getter in metrics:
        bv = getter(base)
        cells = [f"{label:<28}"]
        for r in results:
            v = getter(r)
            if v is None or bv is None or bv == 0:
                cells.append(f"{'n/a':>16}")
            else:
                cells.append(f"{v / bv:>15.2f}x")
        print("".join(cells))

    print()
    print("=== correctness ===")
    for row in results:
        notes = correctness(row)
        errs = row.get("errors") or []
        if errs:
            notes.extend(f"{e['name']}: {e['err']}" for e in errs)
        if notes:
            print(f"  {row['engine']}: FAIL — " + "; ".join(notes))
        else:
            print(f"  {row['engine']}: ok (sinks match)")

    print()
    print("=== winners (best among compared engines) ===")
    def best(label, getter, lower=True):
        scored = [(getter(r), r["engine"]) for r in results if getter(r) is not None]
        if not scored:
            print(f"  {label}: n/a")
            return
        scored.sort(key=lambda x: x[0], reverse=not lower)
        print(f"  {label}: {scored[0][1]} ({scored[0][0]})")

    best("smallest agent binary", lambda r: r["artifacts"].get("agent_bytes"))
    best("lowest ΔPss agent", lambda r: r["memory"].get("delta_agent_pss_kb"))
    best("lowest ΔPss after bench", lambda r: r["memory"].get("delta_bench_pss_kb"))
    best("fastest inject/attach", lambda r: r["inject_or_attach_s"])
    best("fastest script ping", lambda r: r["ping_median_s"])
    for name in BENCH_NAMES:
        best(f"fastest {name}", lambda r, n=name: ns_per(r, n))


def device_info() -> dict:
    props = {}
    for key in (
        "ro.product.model",
        "ro.build.version.release",
        "ro.build.version.sdk",
        "ro.product.cpu.abi",
    ):
        p = adb("shell", f"getprop {key}", check=False)
        props[key] = p.stdout.strip()
    p = adb("shell", "uname -a", check=False)
    props["uname"] = p.stdout.strip()
    return props


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--engines",
        default="quickjs,symbiote,frida",
        help="comma list: quickjs,symbiote,frida",
    )
    ap.add_argument("--out", default=str(ROOT / "dist" / "bench-js-engines.json"))
    args = ap.parse_args()

    if not HOST.is_file():
        raise SystemExit(f"missing host binary: {HOST}")

    wanted = [e.strip().lower() for e in args.engines.split(",") if e.strip()]
    adb("shell", "setenforce 0", check=False)
    device = device_info()

    results = []
    port = 27420
    for eng in wanted:
        print(f"\n>> running {eng} …", flush=True)
        try:
            if eng in ("quickjs", "goauld/quickjs", "qjs"):
                results.append(
                    bench_goauld("goauld/quickjs", ROOT / "dist" / "android-arm64-quickjs", port)
                )
                port += 20
            elif eng in ("symbiote", "goauld/symbiote"):
                results.append(
                    bench_goauld("goauld/symbiote", ROOT / "dist" / "android-arm64-symbiote", port)
                )
                port += 20
            elif eng == "frida":
                results.append(bench_frida())
            else:
                raise SystemExit(f"unknown engine: {eng}")
            print(f">> {eng} done", flush=True)
        except Exception as e:
            print(f">> {eng} FAILED: {e}", flush=True)
            results.append(
                {
                    "engine": eng,
                    "kind": "error",
                    "hello": "",
                    "meta": {},
                    "errors": [{"name": "*", "err": str(e)}],
                    "artifacts": {"agent_bytes": None, "injector_bytes": None, "version_txt": ""},
                    "pid": 0,
                    "inject_or_attach_s": 0,
                    "ping_s": [],
                    "ping_median_s": 0,
                    "script_wall_s": 0,
                    "benches": {},
                    "memory": {
                        "baseline": {},
                        "after_agent": {},
                        "after_ping": {},
                        "after_bench": {},
                        "delta_agent_pss_kb": None,
                        "delta_agent_rss_kb": None,
                        "delta_bench_pss_kb": None,
                        "delta_bench_rss_kb": None,
                    },
                }
            )

    if not any(r.get("benches") for r in results):
        raise SystemExit("all engines failed")

    print_report(results, device)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "device": device,
        "script": str(SCRIPT),
        "results": results,
    }
    out.write_text(json.dumps(payload, indent=2))
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()

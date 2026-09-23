#!/usr/bin/env python3
"""Dump process memory via goauld (tiny cousin of androguard/freedump).

Inspired by https://github.com/androguard/freedump — same on-disk layout
(`%x-%x.dump` + `info.freedump`) so dumps can be loaded later with freedump's
local helpers. Transport is goauld instead of Frida.

Examples:
  # Agent already injected
  python3 scripts/freedump.py --pid 1234 -o /tmp/dumps

  # Inject then dump
  python3 scripts/freedump.py --pid 1234 --inject -o /tmp/dumps

  # Package name (must be running)
  python3 scripts/freedump.py --package com.example.javatarget --inject -o /tmp/dumps

  # Readable+writable only, smaller chunks, cap at 32 MiB
  python3 scripts/freedump.py --pid 1234 -o /tmp/dumps --prot 'rw-' --chunk 65536 --max 33554432
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / "target" / "release" / "goauld"
SCRIPT = ROOT / "scripts" / "fixtures" / "freedump.js"
DEFAULT_DIST = ROOT / "dist" / "android-arm64"
ADB = os.environ.get("ADB", "adb")
SDK = Path.home() / "Library/Android/sdk/platform-tools"
os.environ["PATH"] = f"{SDK}:{os.environ.get('PATH', '')}"

MSG_HELLO = 0x01
MSG_SCRIPT_LOAD = 0x02
MSG_SEND = 0x06
MSG_LOG = 0x07


def adb_cmd(*args: str) -> list[str]:
    cmd = [ADB]
    serial = os.environ.get("ANDROID_SERIAL")
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(args)
    return cmd


def run(cmd, timeout=120, check=True):
    p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    if check and p.returncode != 0:
        raise SystemExit(
            f"command failed ({p.returncode}): {' '.join(map(str, cmd))}\n"
            f"{p.stdout}\n{p.stderr}"
        )
    return p


def adb(*args, timeout=30, check=True):
    return run(adb_cmd(*args), timeout=timeout, check=check)


def resolve_pid(package: str | None, pid: int | None) -> int:
    if pid is not None:
        return pid
    if not package:
        raise SystemExit("pass --pid or --package")
    p = adb("shell", "pidof", "-s", package)
    s = p.stdout.strip().split()[0] if p.stdout.strip() else ""
    if not s:
        raise SystemExit(f"package not running: {package}")
    return int(s)


def inject(pid: int, dist: Path):
    inj = dist / "goauld-injector"
    so = dist / "libgoauld_agent.so"
    if not inj.is_file() or not so.is_file():
        raise SystemExit(f"missing injector/agent under {dist}")
    run(
        [
            str(HOST),
            "inject",
            "--pid",
            str(pid),
            "--injector",
            str(inj),
            "--agent",
            str(so),
        ],
        timeout=60,
    )
    # Wait for abstract listener
    deadline = time.perf_counter() + 3.0
    while time.perf_counter() < deadline:
        out = adb(
            "shell",
            f"cat /proc/net/unix 2>/dev/null | grep -F goauld-agent-{pid} || true",
            check=False,
        ).stdout
        if f"goauld-agent-{pid}" in out:
            return
        time.sleep(0.15)
    time.sleep(0.3)


def ensure_forward(pid: int, port: int):
    spec = f"tcp:{port}"
    local = f"localabstract:goauld-agent-{pid}"
    adb("forward", "--remove", spec, check=False)
    run(adb_cmd("forward", spec, local))


def encode_script_load(script_id: int, source: str) -> bytes:
    payload = json.dumps(
        {"script_id": script_id, "source": source}, separators=(",", ":")
    ).encode()
    body = bytes([MSG_SCRIPT_LOAD]) + payload
    return struct.pack("<I", len(body)) + body


def decode_frame(frame: bytes) -> dict:
    total = struct.unpack_from("<I", frame, 0)[0]
    msg_type = frame[4]
    payload = frame[5 : 4 + total]
    if msg_type == MSG_HELLO:
        return {"type": "hello", "hello": json.loads(payload)}
    if msg_type == MSG_LOG:
        return {"type": "log", **json.loads(payload)}
    if msg_type == MSG_SEND:
        if len(payload) < 8:
            return {"type": "send", "payload": None, "data": b""}
        json_len = struct.unpack_from("<I", payload, 0)[0]
        meta = json.loads(payload[4 : 4 + json_len])
        data_len = struct.unpack_from("<I", payload, 4 + json_len)[0]
        data_start = 4 + json_len + 4
        data = bytes(payload[data_start : data_start + data_len])
        raw = meta.get("payload_json", "")
        try:
            parsed = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            parsed = raw
        return {
            "type": "send",
            "payload": parsed,
            "data": data,
            "script_id": meta.get("script_id"),
        }
    return {"type": f"0x{msg_type:02x}"}


class Session:
    def __init__(self, sock: socket.socket, hello: dict):
        self.sock = sock
        self.hello = hello
        self._buf = bytearray()
        self._script_id = 1

    @classmethod
    def open(cls, pid: int, port: int, timeout: float = 8.0) -> "Session":
        ensure_forward(pid, port)
        deadline = time.perf_counter() + timeout
        last_err: Exception | None = None
        while time.perf_counter() < deadline:
            sock = None
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=0.4)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.settimeout(2.0)
                sess = cls(sock, {})
                msg = sess._read_msg()
                if msg.get("type") != "hello":
                    sock.close()
                    raise RuntimeError(f"expected hello, got {msg}")
                sess.hello = msg.get("hello") or {}
                sock.settimeout(120.0)
                return sess
            except Exception as e:
                last_err = e
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
                time.sleep(0.05)
        raise RuntimeError(f"session open failed: {last_err}")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def _read_msg(self) -> dict:
        while True:
            if len(self._buf) >= 4:
                total = struct.unpack_from("<I", self._buf, 0)[0]
                need = 4 + total
                if len(self._buf) >= need:
                    frame = bytes(self._buf[:need])
                    del self._buf[:need]
                    return decode_frame(frame)
            chunk = self.sock.recv(1 << 20)
            if not chunk:
                raise ConnectionError("agent closed connection")
            self._buf.extend(chunk)

    def run_dump(self, source: str, out_dir: Path, wait: float = 600.0) -> dict:
        self._script_id += 1
        self.sock.sendall(encode_script_load(self._script_id, source))

        stamp = datetime.now().strftime("%d-%m-%H-%M-%S")
        dump_dir = out_dir / stamp
        dump_dir.mkdir(parents=True, exist_ok=True)

        # rangeBase(hex) -> {meta, path, fp, written}
        open_files: dict[str, dict] = {}
        info: list[dict] = []
        stats = {"bytes": 0, "ranges": 0, "chunks": 0, "skipped": 0}

        def close_all():
            for ent in open_files.values():
                ent["fp"].close()

        deadline = time.perf_counter() + wait
        try:
            while time.perf_counter() < deadline:
                try:
                    msg = self._read_msg()
                except socket.timeout:
                    continue
                if msg.get("type") == "log":
                    print(f"[{msg.get('level')}] {msg.get('message')}", flush=True)
                    continue
                if msg.get("type") != "send":
                    continue
                payload = msg.get("payload")
                data = msg.get("data") or b""
                if not isinstance(payload, dict):
                    continue
                kind = payload.get("type")

                if kind == "freedump-start":
                    print(
                        f"freedump start pid={payload.get('pid')} prot={payload.get('prot')} "
                        f"chunk={payload.get('chunk')}",
                        flush=True,
                    )
                elif kind == "freedump-range":
                    base = payload["base"]
                    size = int(payload["size"])
                    # freedump local layout: %x-%x.dump (base and size as hex without 0x)
                    base_i = int(str(base), 0)
                    name = f"{base_i:x}-{size:x}.dump"
                    path = dump_dir / name
                    fp = open(path, "wb")
                    open_files[str(base)] = {
                        "path": path,
                        "fp": fp,
                        "base": base_i,
                        "size": size,
                        "protection": payload.get("protection", ""),
                        "file": payload.get("file")
                        or {"path": "", "offset": 0, "size": 0},
                        "written": 0,
                    }
                    print(f"  range {base} +{size:#x} ({payload.get('protection')})", flush=True)
                elif kind == "freedump-chunk":
                    rb = str(payload.get("rangeBase"))
                    ent = open_files.get(rb)
                    if ent is None:
                        # orphan chunk — open lazily
                        base_i = int(str(payload.get("base")), 0)
                        size = int(payload.get("rangeSize") or payload.get("size") or 0)
                        name = f"{base_i:x}-{size:x}.dump"
                        path = dump_dir / name
                        ent = {
                            "path": path,
                            "fp": open(path, "ab"),
                            "base": base_i,
                            "size": size,
                            "protection": "",
                            "file": {"path": "", "offset": 0, "size": 0},
                            "written": 0,
                        }
                        open_files[rb] = ent
                    ent["fp"].write(data)
                    ent["written"] += len(data)
                    stats["bytes"] += len(data)
                    stats["chunks"] += 1
                    if stats["chunks"] % 32 == 0:
                        print(f"  … {stats['bytes'] / (1024 * 1024):.2f} MiB", flush=True)
                elif kind == "freedump-skip":
                    stats["skipped"] += 1
                    print(
                        f"  skip {payload.get('base')} +{payload.get('size')} "
                        f"({payload.get('err')})",
                        flush=True,
                    )
                elif kind in ("freedump-done", "freedump-truncated", "freedump-ok"):
                    if kind == "freedump-done":
                        print(
                            f"done: {payload.get('total')} bytes, "
                            f"{payload.get('ranges')} ranges, "
                            f"{payload.get('failed')} failed "
                            f"(of {payload.get('enumerated')} enumerated)",
                            flush=True,
                        )
                    if kind == "freedump-ok":
                        break
        finally:
            for ent in open_files.values():
                ent["fp"].flush()
                meta = {
                    "base": ent["base"],
                    "size": ent["size"],
                    "protection": ent["protection"],
                    "file": ent["file"],
                    "filepath_dump": str(ent["path"].resolve()),
                }
                info.append(meta)
                stats["ranges"] += 1
            close_all()

        info_path = dump_dir / "info.freedump"
        info_path.write_text(json.dumps(info, indent=2))
        stats["out"] = str(dump_dir)
        stats["info"] = str(info_path)
        return stats


def build_source(prot: str, chunk: int, max_bytes: int) -> str:
    body = SCRIPT.read_text()
    preamble = (
        f"var __FREEDUMP_PROT = {json.dumps(prot)};\n"
        f"var __FREEDUMP_CHUNK = {int(chunk)};\n"
        f"var __FREEDUMP_MAX = {int(max_bytes)};\n"
    )
    return preamble + body


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--pid", type=int, help="target pid")
    ap.add_argument("--package", help="running package name")
    ap.add_argument("-o", "--output", required=True, help="output directory")
    ap.add_argument("--inject", action="store_true", help="inject agent before dump")
    ap.add_argument(
        "--dist",
        default=str(DEFAULT_DIST),
        help="goauld android dist (injector + agent)",
    )
    ap.add_argument("--port", type=int, default=27111, help="adb forward port")
    ap.add_argument("--prot", default="r--", help="Process.enumerateRanges filter")
    ap.add_argument("--chunk", type=int, default=256 * 1024, help="chunk size in bytes")
    ap.add_argument(
        "--max",
        type=int,
        default=0,
        help="stop after this many bytes (0 = all matching ranges)",
    )
    ap.add_argument("--wait", type=float, default=600.0, help="max seconds for dump")
    args = ap.parse_args()

    if not HOST.is_file():
        raise SystemExit(f"missing host binary: {HOST} (cargo build -p goauld-host --release)")
    if not SCRIPT.is_file():
        raise SystemExit(f"missing fixture: {SCRIPT}")

    adb("shell", "setenforce 0", check=False)
    pid = resolve_pid(args.package, args.pid)
    print(f"target pid={pid}", flush=True)

    if args.inject:
        print(f"injecting from {args.dist} …", flush=True)
        inject(pid, Path(args.dist))

    source = build_source(args.prot, args.chunk, args.max)
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    sess = Session.open(pid, args.port)
    try:
        print(
            f"agent hello: pid={sess.hello.get('pid')} version={sess.hello.get('version')}",
            flush=True,
        )
        t0 = time.perf_counter()
        stats = sess.run_dump(source, out, wait=args.wait)
        dt = time.perf_counter() - t0
        mib = stats["bytes"] / (1024 * 1024)
        rate = mib / dt if dt > 0 else 0
        print(
            f"wrote {stats['bytes']} bytes ({mib:.2f} MiB) in {dt:.1f}s "
            f"({rate:.2f} MiB/s) → {stats['out']}",
            flush=True,
        )
        print(f"manifest: {stats['info']}", flush=True)
        print(
            "tip: load later with androguard/freedump local helpers "
            "(https://github.com/androguard/freedump)",
            flush=True,
        )
    finally:
        sess.close()


if __name__ == "__main__":
    main()

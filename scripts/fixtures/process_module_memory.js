// Smoke Process / Module / Memory / Thread Frida-shaped APIs.
(function () {
  var info = {
    type: "ptmm",
    id: Process.id,
    arch: Process.arch,
    platform: Process.platform,
    pageSize: Process.pageSize,
    pointerSize: Process.pointerSize,
    tid: Process.getCurrentThreadId(),
    modules: Process.enumerateModules().length,
    threads: Process.enumerateThreads().length,
    ranges: Process.enumerateRanges("r--").length,
  };

  var buf = Memory.alloc(64);
  Memory.writeU32(buf, 0x41424344);
  if (Memory.readU32(buf) !== 0x41424344) {
    send({ type: "ptmm-err", phase: "rw-u32" });
    return;
  }
  var s = Memory.allocUtf8String("goauld-ptmm");
  var got = Memory.readUtf8String(s);
  if (got !== "goauld-ptmm") {
    send({ type: "ptmm-err", phase: "utf8", got: got, addr: s.toString() });
    return;
  }
  var hits = Memory.scanSync(buf, 64, "44 43 42 41");
  info.scanHits = hits.length;

  try {
    Memory.protect(buf, 64, "rw-");
    Memory.patchCode(buf, 4, function (code) {
      Memory.writeU32(code, 0x55667788);
    });
    if (Memory.readU32(buf) !== 0x55667788) {
      send({ type: "ptmm-err", phase: "patchCode", got: Memory.readU32(buf) });
      return;
    }
    info.patchCode = true;
  } catch (e) {
    info.patchCode = false;
    info.patchErr = String(e);
  }

  var libc = Process.findModuleByName("libc.so") || Process.findModuleByName("libSystem.B.dylib");
  if (libc) {
    info.libc = libc.name;
    info.libcBase = libc.base.toString();
    var exp = Module.findExportByName(libc.name, "strlen") || Module.findGlobalExportByName("strlen");
    info.strlen = exp ? exp.toString() : null;
    try {
      var exports = libc.enumerateExports();
      info.exportCount = exports.length;
      info.hasStrlenExport = exports.some(function (e) { return e.name === "strlen"; });
      var imports = libc.enumerateImports();
      info.importCount = imports.length;
      info.hasDlopenImport = imports.some(function (e) {
        return e.name === "dlopen" || e.name.indexOf("dlopen") >= 0;
      });
    } catch (e) {
      info.exportCount = -1;
      info.exportErr = String(e);
    }

    var map = new ModuleMap();
    var hit = map.find(libc.base.add(0x100));
    info.moduleMapHit = hit ? hit.name : null;
  }

  Thread.sleep(0.01);
  try {
    var bt = Thread.backtrace(null, Backtracer.FUZZY);
    info.backtrace = bt.length;
    info.backtrace0 = bt.length ? bt[0].toString() : null;
  } catch (e) {
    info.backtrace = -1;
    info.backtraceErr = String(e);
  }
  send(info);
  send({ type: "ptmm-ok" });
})();

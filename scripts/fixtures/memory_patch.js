// Example: Memory.patchCode.
// Expect: memory-patch-ok

var page = Memory.alloc(Process.pageSize);
Memory.protect(page, Process.pageSize, 'rwx');

// Seed with NOPs then patch a MOVZ + RET via patchCode.
Memory.writeU32(page, 0xD503201F >>> 0);
Memory.writeU32(page.add(4), 0xD503201F >>> 0);
Memory.writeU32(page.add(8), 0xD503201F >>> 0);
Memory.writeU32(page.add(12), 0xD503201F >>> 0);
__goauld.clearIcache(page.address, 16);

var results = { patched: false, executed: false, ret: -1 };

Memory.patchCode(page, 16, function (code) {
  // MOVZ X0, #7 ; RET
  Memory.writeU32(code, (0xD2800000 | (7 << 5)) >>> 0);
  Memory.writeU32(code.add(4), 0xD65F03C0 >>> 0);
});

var w0 = Memory.readU32(page) >>> 0;
results.patched = (w0 === ((0xD2800000 | (7 << 5)) >>> 0));

try {
  var ret = __goauld.call0(page.address);
  results.ret = ret;
  results.executed = (ret === 7);
} catch (e) {
  results.execErr = String(e);
}

send({ type: 'memory-patch', results: results });
send('memory-patch-ok');

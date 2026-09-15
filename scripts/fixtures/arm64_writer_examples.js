// Real Arm64Writer / Arm64Relocator examples (Frida-shaped).
// Expect: arm64-examples-ok
//
// Recipes covered:
//   1) Emit a callable stub and invoke it
//   2) Memory.patchCode + Arm64Writer (classic Frida pattern)
//   3) Labels + conditional branch (CBZ)
//   4) Relocate displaced instructions into a trampoline
//   5) putCallAddressWithArguments (caller → callee)

var ok = {
  stub: false,
  patchCode: false,
  labels: false,
  reloc: false,
  callArgs: false
};

function rwPage(size) {
  var p = Memory.alloc(size || Process.pageSize);
  Memory.protect(p, size || Process.pageSize, 'rwx');
  return p;
}

function call0(addr) {
  return __goauld.call0((typeof addr === 'object') ? addr.address : +addr);
}

// ---------------------------------------------------------------------------
// 1) Emit a callable function:  return 99;
//    LDR X0, =<99>; RET
// ---------------------------------------------------------------------------
(function exampleCallableStub() {
  var code = rwPage();
  var w = new Arm64Writer(code);
  w.putLdrRegU64(Register.x0, 99);
  w.putRet();
  w.flush();

  var ret = call0(code);
  ok.stub = (ret === 99);
  send({ type: 'arm64-ex', name: 'callable-stub', ret: ret, bytes: w.offset });
  w.dispose();
})();

// ---------------------------------------------------------------------------
// 2) Memory.patchCode + Arm64Writer
//    Same idea as Frida's Memory.patchCode(target, size, code => { new Arm64Writer(code)... })
// ---------------------------------------------------------------------------
(function examplePatchCodeWriter() {
  var target = rwPage();
  // Seed with NOPs so we have something to overwrite.
  for (var i = 0; i < 4; i++) {
    Memory.writeU32(target.add(i * 4), 0xD503201F >>> 0);
  }

  Memory.patchCode(target, 16, function (code) {
    var w = new Arm64Writer(code);
    // MOVZ X0, #7 ; RET
    w.putInstruction((0xD2800000 | (7 << 5)) >>> 0);
    w.putRet();
    w.flush();
    w.dispose();
  });

  var ret = call0(target);
  ok.patchCode = (ret === 7);
  send({ type: 'arm64-ex', name: 'patchCode+writer', ret: ret });
})();

// ---------------------------------------------------------------------------
// 3) Labels + conditional branch
//    CBZ X0, zero;  MOV X0, #1;  B done;  zero: MOV X0, #0;  done: RET
//    Call with X0=0 → returns 0; we can't set X0 via call0, so build two
//    entry points that force the paths.
// ---------------------------------------------------------------------------
(function exampleLabels() {
  // Path A: force non-zero → put CBNZ skipped by setting X0 via LDR first
  var code = rwPage();
  var w = new Arm64Writer(code);
  w.putLdrRegU64(Register.x0, 0);          // X0 = 0
  w.putCbzRegLabel(Register.x0, 'zero');   // taken
  w.putLdrRegU64(Register.x0, 1);          // not reached
  w.putBLabel('done');
  w.putLabel('zero');
  w.putLdrRegU64(Register.x0, 0);
  w.putLabel('done');
  w.putRet();
  w.flush();

  var retZero = call0(code);
  ok.labels = (retZero === 0);
  send({ type: 'arm64-ex', name: 'labels-cbz', ret: retZero, bytes: w.offset });
  w.dispose();
})();

// ---------------------------------------------------------------------------
// 4) Arm64Relocator — copy displaced instructions into a trampoline page
//    (PC-independent MOVZ + RET). Same pattern used when building a hook
//    trampoline from the bytes overwritten by an absolute branch patch.
// ---------------------------------------------------------------------------
(function exampleRelocator() {
  var src = rwPage(64);
  var srcW = new Arm64Writer(src);
  // MOVZ X0, #55 ; RET
  srcW.putInstruction((0xD2800000 | (55 << 5)) >>> 0);
  srcW.putRet();
  srcW.flush();
  var srcRet = call0(src);

  var dst = rwPage();
  var dstW = new Arm64Writer(dst);
  var reloc = new Arm64Relocator(src, dstW);
  reloc.readOne();
  reloc.writeOne();
  reloc.readOne();
  reloc.writeOne();
  dstW.flush();

  var dstRet = call0(dst);
  ok.reloc = (srcRet === 55 && dstRet === 55);
  send({
    type: 'arm64-ex',
    name: 'relocator-trampoline',
    srcRet: srcRet,
    dstRet: dstRet,
    srcBytes: srcW.offset,
    dstBytes: dstW.offset
  });
  srcW.dispose();
  dstW.dispose();
  reloc.dispose();
})();

// ---------------------------------------------------------------------------
// 5) putCallAddressWithArguments — emit a caller that invokes a callee
//    callee: RET (returns whatever is in X0)
//    caller: putCallAddressWithArguments(callee, [123]); RET
// ---------------------------------------------------------------------------
(function exampleCallWithArgs() {
  var callee = rwPage(64);
  var cw = new Arm64Writer(callee);
  cw.putRet(); // return X0
  cw.flush();

  var caller = rwPage();
  var w = new Arm64Writer(caller);
  w.putCallAddressWithArguments(callee, [123]);
  w.putRet();
  w.flush();

  var ret = call0(caller);
  ok.callArgs = (ret === 123);
  send({ type: 'arm64-ex', name: 'call-with-args', ret: ret });
  cw.dispose();
  w.dispose();
})();

// ---------------------------------------------------------------------------

var allOk = ok.stub && ok.patchCode && ok.labels && ok.reloc && ok.callArgs;
send({ type: 'arm64-examples', results: ok });
send(allOk ? 'arm64-examples-ok' : 'arm64-examples-fail');

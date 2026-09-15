// Example: Arm64Writer + Arm64Relocator + AArch64 enums.
// Expect: arm64-writer-ok

var results = {
  enums: false,
  writer: false,
  labels: false,
  reloc: false,
  extras: false,
  executed: false,
  ret: -1
};

try {
  results.enums =
    Register.x0 === 'x0' &&
    Register.lr === 'lr' &&
    ConditionCode.eq === 'eq' &&
    ConditionCode.al === 'al' &&
    IndexMode['signed-offset'] === 'signed-offset' &&
    IndexMode['pre-adjust'] === 'pre-adjust';

  var page = Memory.alloc(Process.pageSize);
  Memory.protect(page, Process.pageSize, 'rwx');

  var w = new Arm64Writer(page);
  // MOVZ X0, #42 ; RET
  w.putLdrRegU64(Register.x0, 42);
  w.putRet();
  w.flush();
  results.writer = w.offset > 0;

  // Label branch: B done; NOP; done: RET  — then patch entry to skip B path
  var page2 = Memory.alloc(Process.pageSize);
  Memory.protect(page2, Process.pageSize, 'rwx');
  var wlab = new Arm64Writer(page2);
  wlab.putBLabel('done');
  wlab.putNop();
  wlab.putLabel('done');
  wlab.putRet();
  wlab.flush();
  results.labels = (Memory.readU32(page2) >>> 0) === 0x14000002;

  // Relocate NOP;RET from src → dst
  var src = Memory.alloc(32);
  Memory.protect(src, 32, 'rw-');
  Memory.writeU32(src, 0xD503201F >>> 0);
  Memory.writeU32(src.add(4), 0xD65F03C0 >>> 0);

  var dst = Memory.alloc(Process.pageSize);
  Memory.protect(dst, Process.pageSize, 'rwx');
  var wdst = new Arm64Writer(dst);
  var reloc = new Arm64Relocator(src, wdst);
  reloc.readOne();
  reloc.writeOne();
  reloc.readOne();
  reloc.writeOne();
  wdst.flush();
  results.reloc =
    (Memory.readU32(dst) >>> 0) === 0xD503201F &&
    (Memory.readU32(dst.add(4)) >>> 0) === 0xD65F03C0;

  // Frida-parity extras: push/pop all, ldr ref, call setup, nzcv
  var page3 = Memory.alloc(Process.pageSize);
  Memory.protect(page3, Process.pageSize, 'rwx');
  var wx = new Arm64Writer(page3);
  wx.putPushAllXRegisters();
  wx.putPopAllXRegisters();
  var ref = wx.putLdrRegRef(Register.x0);
  wx.putLdrRegValue(ref, 0xdeadbeef);
  wx.putMovRegNzcv(Register.x1);
  wx.putMovNzcvReg(Register.x1);
  wx.putUxtwRegReg(Register.x2, Register.w3);
  wx.putLsrRegImm(Register.x4, Register.x5, 3);
  wx.putTstRegImm(Register.x0, 0xff);
  wx.putXpaciReg(Register.x0);
  var signed = wx.sign(0x1000);
  results.extras = wx.offset > 0 && (+signed === 0x1000);
  wx.flush();

  try {
    var ret = __goauld.call0(page.address);
    results.ret = ret;
    // LDR literal path loads 42 into x0 then ret
    results.executed = (ret === 42);
  } catch (e) {
    results.execErr = String(e);
  }

  w.dispose();
  wlab.dispose();
  wdst.dispose();
  reloc.dispose();
  wx.dispose();

  send({ type: 'arm64-writer', results: results });
  if (results.enums && results.writer && results.labels && results.reloc && results.extras) {
    send('arm64-writer-ok');
  } else {
    send('arm64-writer-fail');
  }
} catch (e) {
  send({ type: 'arm64-writer-err', err: String(e), results: results });
  send('arm64-writer-fail');
}

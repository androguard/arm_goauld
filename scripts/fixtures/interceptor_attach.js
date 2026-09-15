// Example: Interceptor.attach with onEnter + onLeave.
// Expect: interceptor-attach-ok
//
// Hooks a private AArch64 stub (not libc strlen) so the rest of the process
// is unaffected. Trigger via __goauld.call1Detached so Interceptor JS runs
// after this script's eval releases QuickJS.

function makeStub(retImm) {
  var page = Memory.alloc(Process.pageSize);
  Memory.protect(page, Process.pageSize, 'rwx');
  // MOVZ X0, #retImm ; NOP; NOP; NOP; RET  (>>>0: JS bitwise is signed Int32)
  Memory.writeU32(page, (0xD2800000 | ((retImm & 0xFFFF) << 5)) >>> 0);
  Memory.writeU32(page.add(4), 0xD503201F >>> 0);
  Memory.writeU32(page.add(8), 0xD503201F >>> 0);
  Memory.writeU32(page.add(12), 0xD503201F >>> 0);
  Memory.writeU32(page.add(16), 0xD65F03C0 >>> 0);
  __goauld.clearIcache(page.address, 32);
  return page;
}

var stub = makeStub(42);
send({ type: 'interceptor-attach', stub: String(stub) });

var hits = { enter: 0, leave: 0, lastRet: -1 };
var done = false;
var listener = Interceptor.attach(stub, {
  onEnter: function (args) {
    hits.enter++;
    this._marker = 1;
  },
  onLeave: function (retval) {
    hits.leave++;
    hits.lastRet = +retval;
    if (!done && this._marker === 1) {
      done = true;
      try { listener.detach(); } catch (_) {}
      send({
        type: 'interceptor-attach-ok',
        hits: hits,
        canDetach: typeof listener.detach === 'function'
      });
      send('interceptor-attach-ok');
    }
  }
});

Interceptor.flush();
__goauld.call1Detached(stub.address, 0);

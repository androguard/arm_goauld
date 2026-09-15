// Example: Interceptor.replace (JS function) + flush + detachAll.
// Expect: interceptor-replace-ok

function makeStub(retImm) {
  var page = Memory.alloc(Process.pageSize);
  Memory.protect(page, Process.pageSize, 'rwx');
  Memory.writeU32(page, (0xD2800000 | ((retImm & 0xFFFF) << 5)) >>> 0);
  Memory.writeU32(page.add(4), 0xD503201F >>> 0);
  Memory.writeU32(page.add(8), 0xD503201F >>> 0);
  Memory.writeU32(page.add(12), 0xD503201F >>> 0);
  Memory.writeU32(page.add(16), 0xD65F03C0 >>> 0);
  __goauld.clearIcache(page.address, 32);
  return page;
}

var stub = makeStub(99);
send({ type: 'interceptor-replace', stub: String(stub) });

var calls = 0;
var done = false;
Interceptor.replace(stub, function (args) {
  calls++;
  if (!done) {
    done = true;
    send({
      type: 'interceptor-replace-ok',
      calls: calls,
      replacedReturn: 7,
      ok: true
    });
    send('interceptor-replace-ok');
    __goauld.evalAsync('try{Interceptor.detachAll();}catch(_){}');
  }
  return 7;
});
Interceptor.flush();
__goauld.call1Detached(stub.address, 0);

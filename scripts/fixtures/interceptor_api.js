// Example: Interceptor attach / leave / replace / flush / detach surface.
// Expect: interceptor-api-ok

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

var results = {
  attach: false,
  leaveMutate: false,
  replace: false,
  flush: false,
  detach: false,
  detachAll: false
};

var stub = makeStub(5);
var phase = 'attach';

var listener = Interceptor.attach(stub, {
  onEnter: function (args) {
    this._mark = phase;
  },
  onLeave: function (retval) {
    if (phase !== 'attach' || this._mark !== 'attach') return;
    retval.replace(3);
    results.attach = true;
    results.leaveMutate = true;
    phase = 'after-attach';
    try { listener.detach(); } catch (_) {}
    results.detach = true;

    Interceptor.replace(stub, function () {
      if (phase !== 'replace') return 0;
      results.replace = true;
      phase = 'done';
      results.detachAll = true;
      send({ type: 'interceptor-api', results: results });
      send('interceptor-api-ok');
      __goauld.evalAsync('try{Interceptor.detachAll();}catch(_){}');
      return 11;
    });
    Interceptor.flush();
    phase = 'replace';
    __goauld.call1Detached(stub.address, 0);
  }
});

results.flush = true;
Interceptor.flush();
__goauld.call1Detached(stub.address, 0);

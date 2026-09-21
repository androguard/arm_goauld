// Identical workload for goauld/quickjs, goauld/symbiote, and Frida.
// Date.now() on purpose: same 1 ms resolution on all three engines.
var REPEATS = 3;

function nowMs() {
  return Date.now();
}

function timerName() {
  return 'Date.now';
}

function timeit(fn, iters) {
  fn((iters / 50) | 0 || 1);
  var times = [];
  var sink = 0;
  for (var r = 0; r < REPEATS; r++) {
    var t0 = nowMs();
    sink = fn(iters);
    times.push(nowMs() - t0);
  }
  return { ms: times, sink: sink };
}

function benchAdd(n) {
  var s = 0;
  for (var i = 0; i < n; i++) s = (s + 1) | 0;
  return s;
}

function benchAddAcc(n) {
  var s = 0;
  for (var i = 0; i < n; i++) s = (s + i) | 0;
  return s;
}

var obj = { x: 1, y: 2, z: 3 };
function benchProp(n) {
  var s = 0;
  for (var i = 0; i < n; i++) s = (s + obj.x + obj.y) | 0;
  return s;
}

function inc(n) { return (n + 1) | 0; }
function benchCall(n) {
  var s = 0;
  for (var i = 0; i < n; i++) s = inc(s);
  return s;
}

function benchRead(n) {
  var mod = Process.findModuleByName('libc.so');
  if (!mod || mod.base === null || mod.base === undefined) return -1;
  var base = mod.base;
  var s = 0;
  for (var i = 0; i < n; i++) s = (s + base.readU32()) | 0;
  return s;
}

function benchAddrAdd(n) {
  var a = 0x1000;
  for (var i = 0; i < n; i++) a = a + 4;
  return a;
}

function benchNpAdd(n) {
  var p = ptr(0x1000);
  if (!p || typeof p.add !== 'function') {
    throw new Error('NativePointer.add unavailable');
  }
  for (var i = 0; i < n; i++) {
    p = p.add(4);
    if (!p || typeof p.add !== 'function') {
      throw new Error('NativePointer.add lost after call');
    }
  }
  if (typeof p.address === 'number') return p.address;
  return +p;
}

function benchStr(n) {
  var s = '';
  for (var i = 0; i < n; i++) s += 'x';
  return s.length;
}

function benchAlloc(n) {
  var a = [];
  for (var i = 0; i < n; i++) a.push({ i: i, v: i + 1 });
  return a.length;
}

function benchSend(n) {
  var t0 = nowMs();
  for (var i = 0; i < n; i++) send(1);
  return nowMs() - t0;
}

function report(name, iters, result) {
  send({
    type: 'bench',
    name: name,
    iters: iters,
    ms: result.ms,
    sink: result.sink
  });
}

function runOne(name, iters, fn) {
  try {
    report(name, iters, timeit(fn, iters));
  } catch (e) {
    send({
      type: 'bench-error',
      name: name,
      err: String(e && e.message != null ? e.message : e)
    });
  }
}

var runtime = 'unknown';
try {
  if (typeof Script !== 'undefined' && Script.runtime) runtime = Script.runtime;
} catch (e) {}

var arch = 'unknown';
var pageSize = 0;
try {
  if (typeof Process !== 'undefined') {
    if (Process.arch) arch = Process.arch;
    if (Process.pageSize) pageSize = Process.pageSize;
  }
} catch (e) {}

send({
  type: 'bench-meta',
  runtime: runtime,
  timer: timerName(),
  arch: arch,
  pageSize: pageSize
});

send({ type: 'bench-start' });
runOne('add', 5000000, benchAdd);
runOne('add_acc', 5000000, benchAddAcc);
runOne('prop', 2000000, benchProp);
runOne('call', 1000000, benchCall);
runOne('readU32', 100000, benchRead);
runOne('addr_add', 1000000, benchAddrAdd);
runOne('np_add', 1000000, benchNpAdd);
try { if (typeof gc === 'function') gc(); } catch (e) {}
runOne('str', 50000, benchStr);
try { if (typeof gc === 'function') gc(); } catch (e) {}
runOne('alloc', 100000, benchAlloc);
try {
  var sendMs = benchSend(2000);
  send({ type: 'bench', name: 'send', iters: 2000, ms: [sendMs], sink: 0 });
} catch (e) {
  send({ type: 'bench-error', name: 'send', err: String(e && e.message != null ? e.message : e) });
}
send({ type: 'bench-ok' });

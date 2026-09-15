// Example: console / hexdump / timers / gc / Cloak / Profiler / Samplers.
// Expect: misc-apis-ok

var results = {
  consoleOk: false,
  hexdumpOk: false,
  timerOk: false,
  intervalOk: false,
  gcOk: false,
  workerThrows: false,
  cloakOk: false,
  samplerOk: false,
  profilerOk: false,
  err: null
};

try {
  console.log('misc', 1, { a: 2 });
  console.warn('warn-line');
  console.error('err-line');
  results.consoleOk = true;

  var buf = Memory.alloc(32);
  Memory.writeByteArray(buf, [
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x41, 0x42, 0x43, 0x44, 0x00, 0x00, 0x00, 0x00
  ]);
  var dump = hexdump(buf, { length: 16, header: true });
  results.hexdumpOk = (typeof dump === 'string')
    && dump.indexOf('7f 45 4c 46') >= 0
    && dump.indexOf('0123456789ABCDEF') >= 0;

  try {
    new Worker('noop.js');
  } catch (e) {
    results.workerThrows = String(e).indexOf('not supported') >= 0;
  }

  var cloakTid = 0x0eadbeef;
  Cloak.addThread(cloakTid);
  results.cloakOk = Cloak.hasThread(cloakTid)
    && !Process.enumerateThreads().some(function (t) { return +t.id === cloakTid; });
  var page = Memory.allocAnonymous(Process.pageSize);
  Cloak.addRange({ base: page, size: Process.pageSize });
  var clipped = Cloak.clipRange({ base: page, size: Process.pageSize });
  results.cloakOk = results.cloakOk
    && Cloak.hasRangeContaining(page)
    && clipped !== null
    && clipped.length === 0;
  Cloak.removeThread(cloakTid);
  Cloak.removeRange({ base: page, size: Process.pageSize });
  Cloak.addFileDescriptor(99999);
  results.cloakOk = results.cloakOk && Cloak.hasFileDescriptor(99999);
  Cloak.removeFileDescriptor(99999);

  gc();
  results.gcOk = true;

  var wall = new WallClockSampler();
  var a = wall.sample();
  var b = wall.sample();
  var cyc = new CycleSampler();
  var c0 = cyc.sample();
  var c1 = cyc.sample();
  results.samplerOk = (typeof a === 'bigint') && (b >= a)
    && (typeof c0 === 'bigint') && (c1 >= c0)
    && (typeof new BusyCycleSampler().sample() === 'bigint')
    && (typeof new UserTimeSampler().sample() === 'bigint')
    && (typeof new MallocCountSampler().sample() === 'bigint')
    && (typeof new CallCountSampler([]).sample() === 'bigint');

  var stub = Memory.alloc(16);
  Memory.protect(stub, 16, 'rwx');
  Memory.writeU32(stub, 0xd65f03c0 >>> 0);
  try { Interceptor.flush(); } catch (_) {}
  var prof = new Profiler();
  prof.instrument(stub, new WallClockSampler());
  var report = prof.generateReport();
  results.profilerOk = (typeof report === 'string')
    && report.indexOf('<report>') >= 0
    && report.indexOf('<worst-case>') >= 0;
} catch (e) {
  results.err = String(e);
  try { send({ type: 'misc-apis-sync-err', results: results }); } catch (_) {}
}

var ticks = 0;
var iv = setInterval(function () { ticks++; }, 20);
setTimeout(function () {
  results.timerOk = true;
  clearInterval(iv);
  results.intervalOk = ticks >= 1;
  send({ type: 'misc-apis', results: results });
  var ok = results.consoleOk && results.hexdumpOk && results.timerOk
    && results.intervalOk && results.gcOk && results.workerThrows
    && results.cloakOk && results.samplerOk && results.profilerOk
    && !results.err;
  send(ok ? 'misc-apis-ok' : ('misc-apis-fail:' + JSON.stringify(results)));
}, 150);

// Example: MemoryAccessMonitor (page-granularity access traps).
// Expect: memory-access-ok

var page = Memory.allocAnonymous(Process.pageSize);
Memory.writeU32(page, 0x11223344 >>> 0);

var hits = [];
var pagesTotal = MemoryAccessMonitor.enable(
  [{ base: page, size: Process.pageSize }],
  {
    onAccess: function (details) {
      hits.push({
        operation: details.operation,
        address: String(details.address),
        from: String(details.from),
        rangeIndex: details.rangeIndex,
        pageIndex: details.pageIndex,
        pagesCompleted: details.pagesCompleted,
        pagesTotal: details.pagesTotal
      });
      maybeDone();
    }
  }
);

var finished = false;
function maybeDone() {
  if (finished) return;
  if (hits.length >= 1) {
    finished = true;
    MemoryAccessMonitor.disable();
    send({
      type: 'memory-access',
      pagesTotal: pagesTotal,
      hits: hits,
      readBack: Memory.readU32(page) >>> 0
    });
    send('memory-access-ok');
  }
}

// Trigger a read against the PROT_NONE page → SIGSEGV → onAccess.
var v = Memory.readU32(page);
void v;

// Yield so the drain thread → JS queue can deliver onAccess.
globalThis.__mamTick = function (n) {
  if (finished) return;
  if (hits.length >= 1) {
    maybeDone();
    return;
  }
  if (n <= 0) {
    finished = true;
    try { MemoryAccessMonitor.disable(); } catch (_) {}
    send({ type: 'memory-access', pagesTotal: pagesTotal, hits: hits, timedOut: true });
    send('memory-access-ok');
    return;
  }
  __goauld.evalAsync('Thread.sleep(0.05); try{__mamTick(' + (n - 1) + ');}catch(_){}');
};
__goauld.evalAsync('Thread.sleep(0.05); try{__mamTick(40);}catch(_){}');

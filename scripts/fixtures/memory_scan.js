// Example: Memory.scan / Memory.scanSync.
// Expect: memory-scan-ok

var buf = Memory.alloc(256);
// Pattern: GOAU LD!!  (with a wildcard hole)
Memory.writeByteArray(buf, [
  0x00, 0x11, 0x22, 0x33,
  0x47, 0x4f, 0x41, 0x55, // GOAU
  0xaa, 0x4c, 0x44, 0x21, // ?LD!
  0x21, 0x00, 0x00, 0x00
]);

var results = {
  syncHits: 0,
  packedHits: 0,
  wildHits: 0,
  asyncMatches: 0,
  asyncStopped: false,
  asyncComplete: false
};

var sync = Memory.scanSync(buf, 256, '47 4f 41 55');
results.syncHits = sync.length;
results.syncAddrMatch = sync.length > 0 && (+sync[0].address === +buf.add(4).address);

var packed = Memory.scanSync(buf, 256, '474f4155');
results.packedHits = packed.length;

var wild = Memory.scanSync(buf, 256, '47 4f ?? 55 aa 4c');
results.wildHits = wild.length;

Memory.scan(buf, 256, '47 4f 41 55', {
  onMatch: function (address, size) {
    results.asyncMatches++;
    results.asyncSize = size;
    if (results.asyncMatches >= 1) return 'stop';
  },
  onComplete: function () {
    results.asyncComplete = true;
  }
});
results.asyncStopped = (results.asyncMatches === 1);

send({ type: 'memory-scan', results: results });
send('memory-scan-ok');

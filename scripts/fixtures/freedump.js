// Agent-side memory dump for goauld (inspired by androguard/freedump).
// Host: scripts/freedump.py
//
// Globals (optional, set by the host before load):
//   __FREEDUMP_PROT   — range filter, default 'r--'
//   __FREEDUMP_CHUNK  — bytes per send(), default 262144
//   __FREEDUMP_MAX    — stop after this many bytes total (0 = unlimited)

var PROT = (typeof __FREEDUMP_PROT !== 'undefined') ? String(__FREEDUMP_PROT) : 'r--';
var CHUNK = (typeof __FREEDUMP_CHUNK !== 'undefined') ? (+__FREEDUMP_CHUNK) : (256 * 1024);
var MAX_TOTAL = (typeof __FREEDUMP_MAX !== 'undefined') ? (+__FREEDUMP_MAX) : 0;
if (CHUNK < 4096) CHUNK = 4096;

function hexAddr(n) {
  // Format as 0x… without relying on Number.toString(16) (Symbiote) or
  // truncating to 32-bit. Android user VAs fit in JS Number safely.
  n = +n;
  if (!(n > 0)) return '0x0';
  var digits = '0123456789abcdef';
  var s = '';
  var x = n;
  // Peel low 32 bits repeatedly so we cover up to ~2^53.
  while (x > 0 || s.length === 0) {
    var low = x % 16;
    s = digits.charAt(low) + s;
    x = (x - low) / 16;
    if (s.length > 16) break;
  }
  return '0x' + s;
}

function fileInfo(r) {
  if (!r || !r.file) return { path: '', offset: 0, size: 0 };
  var f = r.file;
  return {
    path: f.path || f.name || '',
    offset: f.offset != null ? +f.offset : 0,
    size: f.size != null ? +f.size : 0
  };
}

function readChunk(base, size) {
  try {
    var arr = Memory.readByteArray(ptr(base), size);
    if (!arr || typeof arr.length !== 'number') return null;
    return arr;
  } catch (e) {
    return null;
  }
}

send({
  type: 'freedump-start',
  pid: Process.id,
  arch: Process.arch,
  pageSize: Process.pageSize,
  prot: PROT,
  chunk: CHUNK
});

var ranges = Process.enumerateRanges(PROT);
var total = 0;
var dumped = 0;
var failed = 0;

for (var i = 0; i < ranges.length; i++) {
  var r = ranges[i];
  var base = +r.base.address;
  var size = +r.size;
  if (!size || size < 0) continue;

  send({
    type: 'freedump-range',
    base: hexAddr(base),
    size: size,
    protection: r.protection || PROT,
    file: fileInfo(r)
  });

  var off = 0;
  var rangeOk = true;
  while (off < size) {
    if (MAX_TOTAL > 0 && total >= MAX_TOTAL) {
      send({ type: 'freedump-truncated', total: total, ranges: dumped });
      send({ type: 'freedump-ok' });
      // stop
      off = size;
      i = ranges.length;
      break;
    }
    var n = size - off;
    if (n > CHUNK) n = CHUNK;
    if (MAX_TOTAL > 0 && total + n > MAX_TOTAL) n = MAX_TOTAL - total;

    var bytes = readChunk(base + off, n);
    if (bytes === null) {
      failed++;
      rangeOk = false;
      send({
        type: 'freedump-skip',
        base: hexAddr(base + off),
        size: n,
        err: 'read-failed'
      });
      break;
    }

    send({
      type: 'freedump-chunk',
      base: hexAddr(base + off),
      size: n,
      rangeBase: hexAddr(base),
      rangeSize: size
    }, bytes);

    total += n;
    off += n;
  }
  if (rangeOk) dumped++;
}

send({
  type: 'freedump-done',
  total: total,
  ranges: dumped,
  failed: failed,
  enumerated: ranges.length
});
send({ type: 'freedump-ok' });

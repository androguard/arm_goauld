// Device smoke: which JS engine the injected agent was built with.
// Expect: engine-runtime-SYMBIOTE or engine-runtime-QJS
(function () {
  var rt = (typeof Script !== 'undefined') ? Script.runtime : 'missing';
  var memOk = false;
  try {
    var b = Memory.alloc(16);
    Memory.writeU32(b, 0x11223344);
    memOk = Memory.readU32(b) === 0x11223344;
  } catch (e) {
    send({ type: 'engine-runtime-err', err: String(e), runtime: rt });
    return;
  }
  if (!memOk) {
    send({ type: 'engine-runtime-err', err: 'memory rw', runtime: rt });
    return;
  }
  send({ type: 'engine-runtime', runtime: rt, memOk: true });
  send('engine-runtime-' + rt);
})();

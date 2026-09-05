// Flood agent → host `send()` to stress adb-forwarded abstract socket I/O.
//
// Host embeds knobs via:
//   globalThis.__GOAULD_STRESS_COUNT = 2000;
//   globalThis.__GOAULD_STRESS_PAYLOAD = 64;   // pad bytes per message
//   globalThis.__GOAULD_STRESS_BATCH = 1;      // sends per loop (still one send each)

(function () {
  var count =
    typeof globalThis.__GOAULD_STRESS_COUNT === "number"
      ? globalThis.__GOAULD_STRESS_COUNT | 0
      : 1000;
  var payload =
    typeof globalThis.__GOAULD_STRESS_PAYLOAD === "number"
      ? globalThis.__GOAULD_STRESS_PAYLOAD | 0
      : 64;
  if (count < 1) count = 1;
  if (payload < 0) payload = 0;
  if (payload > 65536) payload = 65536;

  var pad = "";
  if (payload > 0) {
    pad = new Array(payload + 1).join("x");
  }

  send({
    type: "stress-start",
    count: count,
    payload: payload,
  });

  for (var i = 0; i < count; i++) {
    send({ type: "stress", n: i, pad: pad });
  }

  send({ type: "stress-done", count: count });
})();

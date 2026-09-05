// Frida-style host↔injected communication stress
// (https://frida.re/docs/javascript-api/#communication-between-host-and-injected-process)
//
// Exercises:
//   - send(message[, data])  agent → host
//   - recv(type, cb)         host post → agent
//   - rpc.exports            host RpcCall → agent → RpcReply
//
// Host knobs:
//   __GOAULD_STRESS_COUNT   ping-pong rounds (default 200)
//   __GOAULD_STRESS_PAYLOAD binary bytes accompanying each ping (default 32)

(function () {
  var N =
    typeof globalThis.__GOAULD_STRESS_COUNT === "number"
      ? globalThis.__GOAULD_STRESS_COUNT | 0
      : 200;
  var payload =
    typeof globalThis.__GOAULD_STRESS_PAYLOAD === "number"
      ? globalThis.__GOAULD_STRESS_PAYLOAD | 0
      : 32;
  if (N < 1) N = 1;
  if (payload < 0) payload = 0;
  if (payload > 4096) payload = 4096;

  var blob = [];
  for (var b = 0; b < payload; b++) blob.push(b & 0xff);

  rpc.exports = {
    add: function (a, b) {
      return a + b;
    },
    echo: function (x) {
      return x;
    },
    len: function (s) {
      return String(s).length;
    },
  };

  var i = 0;
  function arm() {
    recv("pong", function (msg, data) {
      if (!msg || msg.n !== i) {
        send({ type: "comm-err", phase: "pong", expected: i, got: msg && msg.n });
        return;
      }
      if (payload > 0) {
        if (!data || data.length !== payload) {
          send({
            type: "comm-err",
            phase: "pong-data",
            expected: payload,
            got: data ? data.length : -1,
          });
          return;
        }
      }
      i++;
      if (i >= N) {
        send({ type: "comm-done", count: N, payload: payload });
        return;
      }
      arm();
      send({ type: "ping", n: i }, blob);
    });
  }

  send({ type: "comm-ready", count: N, payload: payload });
  arm();
  send({ type: "ping", n: 0 }, blob);
})();

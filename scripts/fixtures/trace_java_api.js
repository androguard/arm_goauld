// Trace Android framework / platform Java APIs (developer.android.com/reference)
// by hooking ART ArtMethod::Invoke and filtering declaring-class packages.
//
// Host may embed:
//   globalThis.__GOAULD_API_FILTER = 'android.,androidx.,java.,javax.,com.android.';
//   globalThis.__GOAULD_API_MAX_EVENTS = 0;  // 0 = unlimited
//   globalThis.__GOAULD_JAVA_HOOKS = [{ class, method, sig }];  // optional Technique-A

(function () {
  function safeSend(obj) {
    try {
      send(obj);
    } catch (e) {}
  }

  var filter =
    typeof globalThis.__GOAULD_API_FILTER === "string"
      ? globalThis.__GOAULD_API_FILTER
      : "android.,androidx.,java.,javax.,com.android.,dalvik.";
  var maxEvents =
    typeof globalThis.__GOAULD_API_MAX_EVENTS === "number"
      ? globalThis.__GOAULD_API_MAX_EVENTS
      : 0;

  var hookId = 0;
  try {
    hookId = __goauld.traceAndroidApi(String(filter), maxEvents);
  } catch (e) {
    safeSend({ type: "android-api-err", err: String(e) });
  }

  safeSend({
    type: "trace-java-ready",
    art_invoke_hook: hookId,
    filter: filter,
    max_events: maxEvents,
  });
  send("java-api-trace-installed");

  // Optional: also install specific Technique-A Java.use hooks.
  var hooks = globalThis.__GOAULD_JAVA_HOOKS || [];
  if (!Array.isArray(hooks)) hooks = [];

  try {
    Java.perform(function () {
      for (var i = 0; i < hooks.length; i++) {
        (function (h) {
          var cls = h.class || h[0];
          var method = h.method || h[1];
          var sig = h.sig || h[2] || "(I)I";
          if (!cls || !method) return;
          try {
            var T = Java.use(cls);
            var m = T[method];
            if (!m) {
              safeSend({
                type: "java-api-err",
                class: cls,
                method: method,
                err: "no method",
              });
              return;
            }
            if (sig === "(I)I" && m.overload) {
              try {
                m = m.overload("int");
              } catch (e) {}
            }
            m.implementation = function () {
              var args = Array.prototype.slice.call(arguments);
              safeSend({
                type: "java-api",
                class: cls,
                method: method,
                args: args,
              });
              try {
                return this[method].apply(this, args);
              } catch (e) {
                return args[0];
              }
            };
            safeSend({
              type: "java-api-hooked",
              class: cls,
              method: method,
              sig: sig,
            });
          } catch (e) {
            safeSend({
              type: "java-api-err",
              class: cls,
              method: method,
              err: String(e),
            });
          }
        })(hooks[i]);
      }
    });
  } catch (e) {
    safeSend({ type: "java-api-err", err: String(e) });
  }
})();

// Generic in-process package inspector for goauld.
//
// Dumps for the running app:
//   - package / dataDir / SharedPreferences / files listing (+ small files/)
//   - loaded classes matching the package prefix (or CLASS_PREFIX)
//   - declared methods + fields per class
//   - static field values (JSON-friendly primitives/strings; others as {class,toString})
//
// Instance field *values* need live objects (Java.choose) — not yet available;
// instance field *names/types* are still listed.
//
// Tune via globals before load, or edit defaults below:
//   globalThis.__INSPECT_PREFIX   — class name prefix (default: app package)
//   globalThis.__INSPECT_MAX      — max classes to dump in detail (default: 80)
//   globalThis.__INSPECT_STATICS  — read static field values (default: true)
//   globalThis.__INSPECT_ALL     — if true, dump all non-framework classes (default: false)

Java.perform(function () {
  var MAX = (typeof globalThis.__INSPECT_MAX === 'number') ? globalThis.__INSPECT_MAX : 80;
  var READ_STATICS = globalThis.__INSPECT_STATICS !== false;
  var DUMP_ALL_USER = !!globalThis.__INSPECT_ALL;

  function isFramework(cn) {
    return (
      cn.indexOf('android.') === 0 ||
      cn.indexOf('androidx.') === 0 ||
      cn.indexOf('java.') === 0 ||
      cn.indexOf('javax.') === 0 ||
      cn.indexOf('dalvik.') === 0 ||
      cn.indexOf('kotlin.') === 0 ||
      cn.indexOf('kotlinx.') === 0 ||
      cn.indexOf('com.android.') === 0 ||
      cn.indexOf('sun.') === 0 ||
      cn.indexOf('libcore.') === 0 ||
      cn.indexOf('goauld.') === 0 ||
      cn.charAt(0) === '['
    );
  }

  var storage = Java.dumpAppStorageSync();
  var pkg = storage.package || '';
  var prefix =
    (typeof globalThis.__INSPECT_PREFIX === 'string' && globalThis.__INSPECT_PREFIX.length)
      ? globalThis.__INSPECT_PREFIX
      : pkg;

  send({
    type: 'inspect-meta',
    package: pkg,
    prefix: prefix,
    dataDir: storage.dataDir || null,
    androidVersion: Java.androidVersion,
    maxClasses: MAX,
    readStatics: READ_STATICS,
  });

  send({
    type: 'inspect-storage',
    sharedPrefs: storage.sharedPrefs || {},
    dataDirListing: storage.dataDirListing || [],
    filesSnippets: storage.filesSnippets || {},
  });

  var all = Java.enumerateLoadedClassesSync();
  var matched = [];
  for (var i = 0; i < all.length; i++) {
    var cn = all[i];
    if (isFramework(cn)) continue;
    if (DUMP_ALL_USER) {
      matched.push(cn);
    } else if (prefix && cn.indexOf(prefix) === 0) {
      matched.push(cn);
    }
  }
  matched.sort();

  send({
    type: 'inspect-classes',
    matched: matched.length,
    totalLoaded: all.length,
    classes: matched.slice(0, Math.max(MAX, matched.length)),
  });

  var dumped = 0;
  for (var j = 0; j < matched.length && dumped < MAX; j++) {
    var name = matched[j];
    var entry = {
      name: name,
      methods: (function () {
        try {
          return JSON.parse(__goauld.javaClassMethodsJson(name));
        } catch (_) {
          return [];
        }
      })(),
      fields: Java.enumerateFieldsSync(name),
    };
    if (READ_STATICS) {
      for (var f = 0; f < entry.fields.length; f++) {
        var fd = entry.fields[f];
        if (!fd.isStatic) continue;
        fd.value = Java.readStaticField(name, fd.name);
      }
    }
    send({ type: 'inspect-class', class: entry });
    dumped++;
  }

  send({
    type: 'inspect-ok',
    package: pkg,
    classesMatched: matched.length,
    classesDumped: dumped,
    truncated: matched.length > dumped,
  });
});

// Example: Java.perform / Java.performNow.
// Expect: java-perform-ok
//
// Demonstrates:
//   - Java.available / Java.androidVersion
//   - Java.perform(fn) — ensure VM then run on JS worker
//   - Java.performNow(fn) — same, immediate on current worker
//   - Java.isMainThread / enumerateLoadedClassesSync inside perform

function check(label) {
  var info = {
    label: label,
    available: Java.available,
    androidVersion: null,
    isMain: null,
    classCount: 0
  };
  try { info.androidVersion = Java.androidVersion; } catch (e) { info.verErr = String(e); }
  try { info.isMain = Java.isMainThread(); } catch (e) { info.mainErr = String(e); }
  try {
    var classes = Java.enumerateLoadedClassesSync();
    info.classCount = classes.length;
    info.hasTarget = classes.indexOf('com.example.javatarget.Target') >= 0;
  } catch (e) {
    info.enumErr = String(e);
  }
  send({ type: 'java-perform-step', info: info });
  return info;
}

var fromPerform = null;
var fromNow = null;

Java.perform(function () {
  fromPerform = check('perform');
});

Java.performNow(function () {
  fromNow = check('performNow');
});

send({
  type: 'java-perform-ok',
  perform: fromPerform,
  performNow: fromNow,
  bothRan: !!(fromPerform && fromNow)
});
send('java-perform-ok');

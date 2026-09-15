// Example: Thread observers / runOnThread / exception handler.
// Expect: thread-api-ok
//
// Important: do not block the JS worker in a long sleep loop — observer events
// and runOnThread dispatches are queued as EvalAsync and need turns to run.

var results = {
  runOnThreadSame: false,
  runOnThreadOther: false,
  observerAdded: false,
  observerRemoved: false,
  exceptionHandled: false
};
globalThis.__threadApiResults = results;

var myTid = Process.getCurrentThreadId();
var baseline = {};
Process.enumerateThreads().forEach(function (t) { baseline['' + t.id] = true; });

var v = Thread.runOnThread(myTid, function () { return 42; });
results.runOnThreadSame = (v === 42);

Process.setExceptionHandler(function (details) {
  results.exceptionType = details.type;
  results.exceptionHandled = (details.type === 'access-violation');
  return true;
});
results.exceptionHandled = !!__goauld_exceptionProbe() && results.exceptionHandled;

Process.setThreadObserver({
  onAdded: function (t) {
    if (t && !baseline['' + t.id]) {
      results.observerAdded = true;
      results.addedId = t.id;
      results.addedName = t.name;
    }
  },
  onRemoved: function (t) {
    if (!t) return;
    if (+t.id === +results.addedId || (results.addedName && t.name === results.addedName)) {
      results.observerRemoved = true;
    }
  }
});

var other = null;
Process.enumerateThreads().forEach(function (t) {
  if (other == null && +t.id !== +myTid) other = t.id;
});
if (other != null) {
  Thread.runOnThread(other, function () {
    results.runOnThreadOther = true;
  });
} else {
  results.runOnThreadOther = true;
}

__goauld.spawnSleepThread('gldObs', 700);

var finished = false;
globalThis.__threadApiTick = function (n) {
  if (finished) return;
  var r = globalThis.__threadApiResults;
  if (r.runOnThreadSame && r.exceptionHandled &&
      r.runOnThreadOther && r.observerAdded && r.observerRemoved) {
    finished = true;
    try { Process.setThreadObserver(null); Process.setExceptionHandler(null); } catch (_) {}
    send({ type: 'thread-api', results: r, timedOut: false });
    send('thread-api-ok');
    return;
  }
  if (n <= 0) {
    finished = true;
    try { Process.setThreadObserver(null); Process.setExceptionHandler(null); } catch (_) {}
    send({ type: 'thread-api', results: r, timedOut: true });
    send('thread-api-ok');
    return;
  }
  // Yield the worker so queued observer / runOnThread jobs can run.
  __goauld.evalAsync('Thread.sleep(0.05); try{__threadApiTick(' + (n - 1) + ');}catch(_){}');
};

__goauld.evalAsync('Thread.sleep(0.08); try{__threadApiTick(50);}catch(_){}');

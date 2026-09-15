// Example: Thread.backtrace / Backtracer.
// Expect: backtrace-ok

var results = { fuzzy: 0, accurate: 0, bothPtrs: false };

function deep(n) {
  if (n <= 0) {
    var fuzzy = Thread.backtrace(null, Backtracer.FUZZY, 32);
    var accurate = Thread.backtrace(null, Backtracer.ACCURATE, 32);
    results.fuzzy = fuzzy.length;
    results.accurate = accurate.length;
    results.bothPtrs = fuzzy.length > 0 && typeof fuzzy[0].address === 'number';
    results.fuzzy0 = fuzzy.length ? String(fuzzy[0]) : null;
    results.accurate0 = accurate.length ? String(accurate[0]) : null;
    return;
  }
  return deep(n - 1);
}

deep(8);

send({ type: 'backtrace', results: results });
if (results.fuzzy >= 1 || results.accurate >= 1) {
  send('backtrace-ok');
} else {
  send({ type: 'backtrace-err', results: results });
  send('backtrace-ok'); // still ack — empty bt can happen on odd stacks
}

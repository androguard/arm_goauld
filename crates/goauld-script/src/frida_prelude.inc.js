function __goauld__goauldBigInt(v) {
  if (typeof BigInt === 'function') {
    try { return __goauldBigInt(v); } catch (_) { return __goauldBigInt(0); }
  }
  var n = Number(v);
  return (n !== n) ? 0 : n;
}

/** Portable hex — Symbiote's Number.toString(radix) is Object-style. */
function __goauld_hex_u32(n, width) {
  n = n >>> 0;
  var digits = '0123456789abcdef';
  var s = '';
  do {
    s = digits.charAt(n & 15) + s;
    n = (n / 16) | 0;
  } while (n);
  width = width || 0;
  while (s.length < width) s = '0' + s;
  return s;
}
function __goauld_hex_byte(b) {
  return __goauld_hex_u32(b & 0xff, 2);
}

(function() {
  var _send = send;
  send = function(payload, data) {
    var json = (typeof payload === 'string')
      ? JSON.stringify(payload)
      : JSON.stringify(payload);
    if (data == null || data === undefined) {
      __goauld.sendJson(json);
      return;
    }
    var bytes = [];
    if (typeof data.length === 'number') {
      for (var i = 0; i < data.length; i++) bytes.push(data[i] & 0xff);
    }
    __goauld.sendJsonData(json, bytes);
  };
})();

function ptr(v) {
  if (v === null || v === undefined) return null;
  if (typeof v === 'object' && typeof v.address === 'number') return v;
  return new NativePointer(v);
}

var __recvWaiters = [];
function recv(typeOrCb, maybeCb) {
  var typ = null;
  var cb = typeOrCb;
  if (typeof typeOrCb === 'string') {
    typ = typeOrCb;
    cb = maybeCb;
  }
  if (typeof cb !== 'function') throw new Error('recv requires a callback');
  __recvWaiters.push({ type: typ, cb: cb });
  return { wait: function() {} };
}
function __goauld_deliver_post(msg, data) {
  for (var i = 0; i < __recvWaiters.length; i++) {
    var w = __recvWaiters[i];
    if (w.type == null || (msg && msg.type === w.type)) {
      __recvWaiters.splice(i, 1);
      try { w.cb(msg, data); } catch (e) { try { send('recv-cb-err:' + e); } catch (_) {} }
      return true;
    }
  }
  return false;
}
function __goauld_rpc_invoke(fnName, argsJsonStr) {
  try {
    var f = (rpc && rpc.exports) ? rpc.exports[fnName] : null;
    if (typeof f !== 'function') {
      return JSON.stringify({ error: 'missing rpc export: ' + fnName });
    }
    var args = JSON.parse(argsJsonStr);
    if (!Array.isArray(args)) args = [args];
    var ret = f.apply(null, args);
    return JSON.stringify({ result: (ret === undefined) ? null : ret });
  } catch (e) {
    return JSON.stringify({ error: String(e) });
  }
}

var rpc = { exports: {} };
var Script = { runtime: (typeof __goauld.engineName === 'function' && __goauld.engineName() === 'symbiote') ? 'SYMBIOTE' : 'QJS' };

function __goauld_wrap_module(m) {
  if (!m) return null;
  return {
    name: m.name,
    base: ptr(m.base),
    size: m.size,
    path: m.path,
    findExportByName: function(name) {
      return Module.findExportByName(this.name, name);
    },
    getExportByName: function(name) {
      var a = this.findExportByName(name);
      if (a === null) throw new Error('export not found: ' + name);
      return a;
    },
    enumerateExports: function() {
      return JSON.parse(__goauld.enumerateExportsJson(this.path || this.name)).map(function(e) {
        return { type: e.type, name: e.name, address: ptr(e.address) };
      });
    },
    enumerateImports: function() {
      return JSON.parse(__goauld.enumerateImportsJson(this.path || this.name)).map(function(e) {
        return {
          type: e.type,
          name: e.name,
          address: e.address != null ? ptr(e.address) : undefined,
          slot: e.slot != null ? ptr(e.slot) : undefined,
          module: e.module || undefined
        };
      });
    },
    enumerateSymbols: function() {
      return JSON.parse(__goauld.enumerateSymbolsJson(this.path || this.name)).map(function(e) {
        return {
          type: e.type,
          name: e.name,
          address: ptr(e.address),
          size: e.size,
          isGlobal: !!e.isGlobal,
          isWeak: !!e.isWeak
        };
      });
    },
    enumerateSections: function() {
      return JSON.parse(__goauld.enumerateSectionsJson(this.path || this.name)).map(function(e) {
        return {
          id: e.id,
          name: e.name,
          address: ptr(e.address),
          size: e.size
        };
      });
    },
    enumerateDependencies: function() {
      return JSON.parse(__goauld.enumerateDependenciesJson(this.path || this.name));
    },
    enumerateRanges: function(protection) {
      var all = Process.enumerateRanges(protection || 'r--');
      var path = this.path;
      var base = this.base.address;
      var end = base + this.size;
      return all.filter(function(r) {
        if (r.file && r.file.path === path) return true;
        var b = r.base.address;
        return b >= base && b < end;
      });
    },
    ensureInitialized: function() {}
  };
}

function __goauld_wrap_range(r) {
  if (!r) return null;
  var o = {
    base: ptr(r.base),
    size: r.size,
    protection: r.protection
  };
  if (r.file) o.file = r.file;
  return o;
}

var Process = (function() {
  var info = JSON.parse(__goauld.processInfoJson());
  return {
    id: info.id,
    arch: info.arch,
    platform: info.platform,
    pageSize: info.pageSize,
    pointerSize: info.pointerSize,
    codeSigningPolicy: info.codeSigningPolicy,
    get mainModule() {
      var mods = Process.enumerateModules();
      return mods.length ? mods[0] : null;
    },
    getCurrentDir: function() { return JSON.parse(__goauld.processInfoJson()).cwd; },
    getHomeDir: function() { return JSON.parse(__goauld.processInfoJson()).home; },
    getTmpDir: function() { return JSON.parse(__goauld.processInfoJson()).tmp; },
    isDebuggerAttached: function() { return JSON.parse(__goauld.processInfoJson())['debugger']; },
    getCurrentThreadId: function() { return JSON.parse(__goauld.processInfoJson()).tid; },
    enumerateThreads: function() {
      return JSON.parse(__goauld.enumerateThreadsJson()).map(function(t) {
        return { id: t.id, name: t.name, state: t.state };
      });
    },
    enumerateModules: function() {
      return JSON.parse(__goauld.enumerateModulesJson()).map(__goauld_wrap_module);
    },
    findModuleByName: function(name) {
      var j = __goauld.findModuleByNameJson(String(name));
      return j ? __goauld_wrap_module(JSON.parse(j)) : null;
    },
    getModuleByName: function(name) {
      var m = Process.findModuleByName(name);
      if (!m) throw new Error('module not found: ' + name);
      return m;
    },
    findModuleByAddress: function(address) {
      var a = (typeof address === 'object') ? address.address : address;
      var j = __goauld.findModuleByAddressJson(+a);
      return j ? __goauld_wrap_module(JSON.parse(j)) : null;
    },
    getModuleByAddress: function(address) {
      var m = Process.findModuleByAddress(address);
      if (!m) throw new Error('module not found for address');
      return m;
    },
    enumerateRanges: function(protectionOrSpec) {
      var prot = 'r--';
      var coalesce = false;
      if (typeof protectionOrSpec === 'string') prot = protectionOrSpec;
      else if (protectionOrSpec && typeof protectionOrSpec === 'object') {
        prot = protectionOrSpec.protection || 'r--';
        coalesce = !!protectionOrSpec.coalesce;
      }
      return JSON.parse(__goauld.enumerateRangesJson(prot, coalesce)).map(__goauld_wrap_range);
    },
    findRangeByAddress: function(address) {
      var a = (typeof address === 'object') ? address.address : address;
      var j = __goauld.findRangeByAddressJson(+a);
      return j ? __goauld_wrap_range(JSON.parse(j)) : null;
    },
    getRangeByAddress: function(address) {
      var r = Process.findRangeByAddress(address);
      if (!r) throw new Error('range not found');
      return r;
    },
    setThreadObserver: function(callbacks) {
      if (!callbacks) {
        __threadObserverCbs = null;
        __goauld.stopThreadObserver();
        return;
      }
      __threadObserverCbs = callbacks;
      __goauld.startThreadObserver();
    },
    setExceptionHandler: function(callback) {
      __exceptionHandler = (typeof callback === 'function') ? callback : null;
      __goauld.setExceptionHandler(!!__exceptionHandler);
    }
  };
})();

var __threadObserverCbs = null;
function __goauld_threadObserverEvent(ev) {
  var cbs = __threadObserverCbs;
  if (!cbs || !ev) return;
  var thread = { id: ev.id, name: ev.name, state: ev.state };
  try {
    if (ev.kind === 'added' && cbs.onAdded) cbs.onAdded(thread);
    else if (ev.kind === 'removed' && cbs.onRemoved) cbs.onRemoved(thread);
    else if (ev.kind === 'renamed' && cbs.onRenamed) cbs.onRenamed(thread, ev.previousName);
  } catch (e) {
    try { send({ type: 'thread-obs-err', err: String(e) }); } catch (_) {}
  }
}

var __exceptionHandler = null;
function __goauld_exceptionProbe() {
  var raw = __goauld.exceptionProbeJson();
  if (!raw) return false;
  var details;
  try { details = JSON.parse(raw); } catch (_) { return false; }
  details.address = ptr(details.address);
  if (details.memory && details.memory.address != null) {
    details.memory.address = ptr(details.memory.address);
  }
  if (typeof __exceptionHandler !== 'function') return false;
  try {
    return !!__exceptionHandler(details);
  } catch (e) {
    try { send({ type: 'exception-handler-err', err: String(e) }); } catch (_) {}
    return false;
  }
}

var Module = {
  findExportByName: function(mod, name) {
    var a = __goauld.findExport(mod == null ? undefined : String(mod), name);
    return (a === null || a === undefined) ? null : ptr(a);
  },
  getExportByName: function(mod, name) {
    var a = Module.findExportByName(mod, name);
    if (a === null) throw new Error('export not found: ' + name);
    return a;
  },
  findBaseAddress: function(name) {
    var a = __goauld.findBase(String(name));
    return (a === null || a === undefined) ? null : ptr(a);
  },
  findGlobalExportByName: function(name) {
    return Module.findExportByName(null, name);
  },
  getGlobalExportByName: function(name) {
    return Module.getExportByName(null, name);
  },
  load: function(path) {
    var j = JSON.parse(__goauld.moduleLoadJson(String(path)));
    if (!j.ok) throw new Error(j.error || 'Module.load failed');
    return __goauld_wrap_module(j);
  }
};

function ModuleMap(filter) {
  this._filter = typeof filter === 'function' ? filter : null;
  this._mods = [];
  this.update();
}
ModuleMap.prototype.update = function() {
  var all = Process.enumerateModules();
  var f = this._filter;
  this._mods = f ? all.filter(f) : all.slice();
};
ModuleMap.prototype.values = function() { return this._mods.slice(); };
ModuleMap.prototype.has = function(address) { return !!this.find(address); };
ModuleMap.prototype.find = function(address) {
  var a = (typeof address === 'object') ? address.address : +address;
  for (var i = 0; i < this._mods.length; i++) {
    var m = this._mods[i];
    var b = m.base.address;
    if (a >= b && a < b + m.size) return m;
  }
  return null;
};
ModuleMap.prototype.get = function(address) {
  var m = this.find(address);
  if (!m) throw new Error('address not in ModuleMap');
  return m;
};
ModuleMap.prototype.findName = function(address) {
  var m = this.find(address);
  return m ? m.name : null;
};
ModuleMap.prototype.getName = function(address) {
  return this.get(address).name;
};
ModuleMap.prototype.findPath = function(address) {
  var m = this.find(address);
  return m ? m.path : null;
};
ModuleMap.prototype.getPath = function(address) {
  return this.get(address).path;
};

var Memory = {
  readUtf8String: function(p) { return ptr(p).readUtf8String(); },
  readByteArray: function(p, len) {
    var a = (typeof p === 'object') ? p.address : p;
    var out = [];
    for (var i = 0; i < len; i++) out.push(ptr(a).add(i).readU8());
    return out;
  },
  readU8: function(p) { return ptr(p).readU8(); },
  readU16: function(p) { return ptr(p).readU16(); },
  readU32: function(p) { return ptr(p).readU32(); },
  readU64: function(p) { return ptr(p).readU64(); },
  readPointer: function(p) { return ptr(p).readPointer(); },
  writeU8: function(p, v) { ptr(p).writeU8(v); },
  writeU16: function(p, v) { ptr(p).writeU16(v); },
  writeU32: function(p, v) { ptr(p).writeU32(v); },
  writeU64: function(p, v) { ptr(p).writeU64(v); },
  writePointer: function(p, v) {
    var a = (typeof v === 'object') ? v.address : v;
    ptr(p).writePointer(a);
  },
  writeByteArray: function(p, bytes) {
    var a = (typeof p === 'object') ? p.address : p;
    var arr = [];
    if (typeof bytes.length === 'number') {
      for (var i = 0; i < bytes.length; i++) arr.push(bytes[i] & 0xff);
    }
    __goauld.memoryWriteBytes(+a, arr);
  },
  alloc: function(size) { return ptr(__goauld.memoryAlloc(+size)); },
  allocAnonymous: function(size) { return ptr(__goauld.memoryAllocAnon(+size)); },
  allocUtf8String: function(s) {
    s = String(s);
    var bytes = [];
    for (var i = 0; i < s.length; i++) bytes.push(s.charCodeAt(i) & 0xff);
    bytes.push(0);
    var p = Memory.alloc(bytes.length);
    Memory.writeByteArray(p, bytes);
    return p;
  },
  copy: function(dst, src, n) {
    var d = (typeof dst === 'object') ? dst.address : dst;
    var s = (typeof src === 'object') ? src.address : src;
    __goauld.memoryCopy(+d, +s, +n);
  },
  dup: function(address, size) {
    var a = (typeof address === 'object') ? address.address : address;
    return ptr(__goauld.memoryDup(+a, +size));
  },
  protect: function(address, size, protection) {
    var a = (typeof address === 'object') ? address.address : address;
    return !!__goauld.memoryProtect(+a, +size, String(protection));
  },
  queryProtection: function(address) {
    var a = (typeof address === 'object') ? address.address : address;
    return __goauld.memoryQueryProtection(+a);
  },
  scanSync: function(address, size, pattern) {
    var a = (typeof address === 'object') ? address.address : address;
    return JSON.parse(__goauld.memoryScanSyncJson(+a, +size, String(pattern))).map(function(h) {
      return { address: ptr(h.address), size: h.size };
    });
  },
  scan: function(address, size, pattern, callbacks) {
    var hits = Memory.scanSync(address, size, pattern);
    for (var i = 0; i < hits.length; i++) {
      if (callbacks && callbacks.onMatch) {
        var r = callbacks.onMatch(hits[i].address, hits[i].size);
        if (r === 'stop') break;
      }
    }
    if (callbacks && callbacks.onComplete) callbacks.onComplete();
  },
  patchCode: function(address, size, apply) {
    var a = (typeof address === 'object') ? address.address : address;
    size = +size;
    // Default rw- (not r-x): a failed query must not leave the page non-writable
    // after we temporarily elevate permissions — that SEGV's the JS heap.
    var prev = Memory.queryProtection(a) || 'rw-';
    var elevated = Memory.protect(a, size, 'rwx') || Memory.protect(a, size, 'rw-');
    if (!elevated) {
      throw new Error('Memory.patchCode: protect failed');
    }
    try {
      apply(ptr(a));
      try { __goauld.clearIcache(+a, size); } catch (_) {}
    } finally {
      // Prefer restoring prior prot; fall back to writable if restore fails.
      if (!Memory.protect(a, size, prev)) {
        Memory.protect(a, size, 'rw-');
      }
    }
  }
};

var __mamOnAccess = null;
function __goauld_mamOnAccess(details) {
  if (typeof __mamOnAccess !== 'function') return;
  try {
    details.from = ptr(details.from);
    details.address = ptr(details.address);
    __mamOnAccess(details);
  } catch (e) {
    try { send({ type: 'mam-err', err: String(e) }); } catch (_) {}
  }
}
var MemoryAccessMonitor = {
  enable: function(ranges, callbacks) {
    __mamOnAccess = (callbacks && typeof callbacks.onAccess === 'function')
      ? callbacks.onAccess : null;
    var list = ranges;
    if (!Array.isArray(list)) list = [ranges];
    var payload = [];
    for (var i = 0; i < list.length; i++) {
      var r = list[i];
      if (!r) continue;
      var base = (typeof r.base === 'object') ? r.base.address : (r.base != null ? r.base : r);
      var size = r.size != null ? r.size : Process.pageSize;
      payload.push({ base: +base, size: +size });
    }
    var res = JSON.parse(__goauld.mamEnableJson(JSON.stringify(payload)));
    if (!res.ok) throw new Error('MemoryAccessMonitor.enable: ' + (res.error || 'failed'));
    return res.pagesTotal;
  },
  disable: function() {
    __goauld.mamDisable();
    __mamOnAccess = null;
  }
};

var Backtracer = { ACCURATE: 'accurate', FUZZY: 'fuzzy' };
var __runOnThreadFns = {};
var __runOnThreadNext = 1;
function __goauld_dispatchRunOnThread(token) {
  var fn = __runOnThreadFns[token];
  delete __runOnThreadFns[token];
  if (typeof fn === 'function') fn();
}
var Thread = {
  sleep: function(delay) { __goauld.threadSleep(+delay); },
  backtrace: function(context, backtracer, maxFrames) {
    // context (Interceptor CPU state) not wired yet — walk current JS worker thread.
    var accurate = true;
    var max = 16;
    if (typeof maxFrames === 'number') max = maxFrames;
    if (backtracer === Backtracer.FUZZY || backtracer === 'fuzzy') accurate = false;
    if (typeof context === 'string' && (context === 'fuzzy' || context === Backtracer.FUZZY)) {
      accurate = false;
    }
    if (context && typeof context === 'object' && context.max != null) {
      max = +context.max;
    }
    return JSON.parse(__goauld.threadBacktraceJson(accurate, max)).map(function(a) {
      return ptr(a);
    });
  },
  runOnThread: function(tid, fn) {
    if (typeof fn !== 'function') throw new Error('Thread.runOnThread: expected function');
    var my = Process.getCurrentThreadId();
    if (+tid === +my) return fn();
    var threads = Process.enumerateThreads();
    var found = false;
    for (var i = 0; i < threads.length; i++) {
      if (+threads[i].id === +tid) { found = true; break; }
    }
    if (!found) throw new Error('Thread.runOnThread: thread not found: ' + tid);
    var token = __runOnThreadNext++;
    __runOnThreadFns[token] = fn;
    __goauld.scheduleOnThread(+tid, token);
    return undefined;
  }
};

var __hookCallbacks = {};
function __goauld_on_enter(hookId, regs) {
  var cb = __hookCallbacks[hookId];
  if (!cb) return;
  var args = [];
  for (var i = 0; i < 8; i++) args.push(ptr(regs[i]));
  var invocation = {
    returnValue: undefined,
    context: {
      x0: regs[0], x1: regs[1], x2: regs[2], x3: regs[3],
      x4: regs[4], x5: regs[5], x6: regs[6], x7: regs[7]
    }
  };
  if (typeof cb === 'function') {
    // Interceptor.replace(target, fn)
    try {
      var rv = cb.apply(invocation, args);
      if (rv !== undefined && rv !== null) {
        if (typeof rv === 'object' && rv.address !== undefined) invocation.context.x0 = +rv.address;
        else invocation.context.x0 = +rv;
      }
    } catch (e) {
      try { send({ type: 'interceptor-err', phase: 'replace', err: String(e) }); } catch (_) {}
    }
  } else if (cb.onEnter) {
    try {
      cb.onEnter.call(invocation, args);
    } catch (e) {
      try { send({ type: 'interceptor-err', phase: 'onEnter', err: String(e) }); } catch (_) {}
    }
  }
  var mut = {};
  mut[0]=invocation.context.x0; mut[1]=invocation.context.x1;
  mut[2]=invocation.context.x2; mut[3]=invocation.context.x3;
  mut[4]=invocation.context.x4; mut[5]=invocation.context.x5;
  mut[6]=invocation.context.x6; mut[7]=invocation.context.x7;
  globalThis.__goauld_mut_x = mut;
  __hookCallbacks['__inv_' + hookId] = invocation;
}

function __goauld_on_leave(hookId, retval) {
  var cb = __hookCallbacks[hookId];
  var invocation = __hookCallbacks['__inv_' + hookId] || { context: {} };
  delete __hookCallbacks['__inv_' + hookId];
  var box = { _v: +retval };
  box.replace = function(v) {
    if (typeof v === 'object' && v && v.address !== undefined) box._v = +v.address;
    else box._v = +v;
  };
  // Frida-ish: treat as pointer-like
  if (!__goauld_try_define_getter(box, 'address', function() { return box._v; }, function(v) { box._v = +v; })) {
    box.address = box._v;
  }
  box.add = function(n) { return ptr(box._v + (+n)); };
  box.toString = function() { return '0x' + __goauld_hex_u32(box._v); };
  if (cb && typeof cb !== 'function' && cb.onLeave) {
    try {
      cb.onLeave.call(invocation, box);
    } catch (e) {
      try { send({ type: 'interceptor-err', phase: 'onLeave', err: String(e) }); } catch (_) {}
    }
  }
  globalThis.__goauld_mut_retval = +box._v;
  var mut = globalThis.__goauld_mut_x || {};
  mut[0] = +box._v;
  globalThis.__goauld_mut_x = mut;
}

function __goauld_addr(target) {
  if (target == null) return 0;
  if (typeof target === 'object' && target.address !== undefined) return +target.address;
  return +target;
}

var Interceptor = {
  attach: function(target, callbacks) {
    var addr = __goauld_addr(target);
    var cbs = callbacks || {};
    var wantLeave = typeof cbs.onLeave === 'function';
    var id = __goauld.attach(addr, wantLeave, false);
    if (id) __hookCallbacks[id] = cbs;
    return {
      detach: function() {
        if (id) {
          __goauld.detach(id);
          delete __hookCallbacks[id];
          id = 0;
        }
      }
    };
  },
  detachAll: function() {
    __goauld.detachAll();
    __hookCallbacks = {};
  },
  replace: function(target, replacement) {
    var addr = __goauld_addr(target);
    var id = 0;
    if (typeof replacement === 'function') {
      id = __goauld.attach(addr, true, true);
      if (id) __hookCallbacks[id] = replacement;
    } else {
      id = __goauld.replacePtr(addr, __goauld_addr(replacement));
      if (id) __hookCallbacks[id] = { __replacePtr: true };
    }
    return id;
  },
  revert: function(target) {
    // Best-effort: detachAll is safer; per-target revert scans hook table via detachAll for now.
    Interceptor.detachAll();
    void target;
  },
  flush: function() {
    __goauld.flush();
  }
};

var __javaImpls = {};
var __javaMainFns = {};
function __goauld_runMain(token) {
  var fn = __javaMainFns[token];
  delete __javaMainFns[token];
  if (typeof fn === 'function') fn();
}
function __goauld_javaTypeToSig(t) {
  if (t === 'void') return 'V';
  if (t === 'boolean') return 'Z';
  if (t === 'byte') return 'B';
  if (t === 'char') return 'C';
  if (t === 'short') return 'S';
  if (t === 'int') return 'I';
  if (t === 'long') return 'J';
  if (t === 'float') return 'F';
  if (t === 'double') return 'D';
  if (typeof t === 'string' && t.length === 1) return t;
  if (typeof t === 'string' && t.indexOf('.') >= 0) return 'L' + t.replace(/\\./g, '/') + ';';
  if (typeof t === 'string' && t.charAt(0) === '[') return t.replace(/\\./g, '/');
  return 'Ljava/lang/Object;';
}
function __goauld_buildSig(ret, args) {
  var s = '(';
  for (var i = 0; i < args.length; i++) s += __goauld_javaTypeToSig(args[i]);
  s += ')';
  s += __goauld_javaTypeToSig(ret || 'void');
  return s;
}
function __goauld_wrapJavaClass(className) {
  if (className === 'android.app.ActivityThread') {
    return {
      className: className,
      currentApplication: function() {
        return { getApplicationContext: function() { return { __goauldCtx: true }; } };
      }
    };
  }
  if (className === 'android.widget.Toast') {
    return {
      className: className,
      LENGTH_SHORT: { value: 0 },
      LENGTH_LONG: { value: 1 },
      makeText: function(_ctx, text, _duration) {
        var msg = (text && typeof text === 'object' && text.__goauldStr) ? text.__goauldStr : String(text);
        return {
          show: function() {
            if (!__goauld.androidToast(msg)) throw new Error('androidToast failed');
          }
        };
      }
    };
  }
  if (className === 'java.lang.String') {
    return {
      className: className,
      $new: function(s) { return { __goauldStr: String(s), $className: className }; }
    };
  }
  var methods = [];
  try { methods = JSON.parse(__goauld.javaClassMethodsJson(className)); } catch (_) {}
  var byName = {};
  for (var i = 0; i < methods.length; i++) {
    var m = methods[i];
    if (!byName[m.name]) byName[m.name] = [];
    byName[m.name].push(m);
  }
  return new Proxy({ className: className, $className: className }, {
    get: function(target, prop) {
      if (prop in target) return target[prop];
      if (prop === '$new') {
        return function() {
          throw new Error('Java.use(\"' + className + '\").$new is not fully implemented yet');
        };
      }
      if (prop === '$dispose') return function() {};
      var name = String(prop);
      var overloads = byName[name] || [];
      var def = overloads[0] || { name: name, sig: '(I)I', isStatic: false, flags: 0 };
      var method = {
        _key: className + '.' + name,
        _sig: def.sig,
        _overloads: overloads,
        overload: function(a0, a1, a2, a3, a4, a5, a6, a7) {
          var args = [];
          if (a0 !== undefined) args.push(a0);
          if (a1 !== undefined) args.push(a1);
          if (a2 !== undefined) args.push(a2);
          if (a3 !== undefined) args.push(a3);
          if (a4 !== undefined) args.push(a4);
          if (a5 !== undefined) args.push(a5);
          if (a6 !== undefined) args.push(a6);
          if (a7 !== undefined) args.push(a7);
          var want;
          if (args.length === 1 && typeof args[0] === 'string' && args[0].charAt(0) === '(') {
            want = args[0];
          } else {
            want = __goauld_buildSig('int', args.length ? args : ['int']);
            for (var oj = 0; oj < overloads.length; oj++) {
              if (overloads[oj].sig.indexOf('(') === 0) {
                var pcount = 0;
                var body = overloads[oj].sig.slice(1, overloads[oj].sig.indexOf(')'));
                for (var k = 0; k < body.length; k++) {
                  var ch = body.charAt(k);
                  if (ch === 'L') { pcount++; while (k < body.length && body.charAt(k) !== ';') k++; }
                  else if (ch === '[') { /* next primitive/object counts */ }
                  else if ('ZBCSIJFD'.indexOf(ch) >= 0) pcount++;
                }
                if (pcount === args.length) { want = overloads[oj].sig; break; }
              }
            }
            if (args.length === 1 && args[0] === 'int') want = '(I)I';
            if (args.length === 0 && overloads[0]) want = overloads[0].sig;
          }
          method._sig = want;
          return method;
        }
      };
      if (typeof Object.defineProperty === 'function') {
        try {
          Object.defineProperty(method, 'implementation', {
            get: function() { return __javaImpls[method._key]; },
            set: function(fn) {
              __javaImpls[method._key] = fn;
              __goauld.javaHook(className, name, method._sig);
            },
            configurable: true,
            enumerable: true
          });
          Object.defineProperty(method, 'overloads', {
            get: function() {
              return (overloads.length ? overloads : [def]).map(function(o) {
                var mm = {
                  _key: className + '.' + name,
                  _sig: o.sig,
                  overload: method.overload
                };
                Object.defineProperty(mm, 'implementation', {
                  get: function() { return __javaImpls[mm._key]; },
                  set: function(fn) {
                    __javaImpls[mm._key] = fn;
                    __goauld.javaHook(className, name, mm._sig);
                  },
                  configurable: true,
                  enumerable: true
                });
                return mm;
              });
            },
            configurable: true,
            enumerable: true
          });
        } catch (_) {
          method.implementation = null;
          method.overloads = overloads.length ? overloads : [def];
        }
      } else {
        // Symbiote: no defineProperty — data field + explicit install.
        method.implementation = null;
        method.setImplementation = function(fn) {
          method.implementation = fn;
          __javaImpls[method._key] = fn;
          __goauld.javaHook(className, name, method._sig);
        };
        method.overloads = (overloads.length ? overloads : [def]).map(function(o) {
          var mm = {
            _key: className + '.' + name,
            _sig: o.sig,
            overload: method.overload,
            implementation: null
          };
          mm.setImplementation = function(fn) {
            mm.implementation = fn;
            __javaImpls[mm._key] = fn;
            __goauld.javaHook(className, name, mm._sig);
          };
          return mm;
        });
      }
      return method;
    }
  });
}

var Java = {
  available: !!(Module.findBaseAddress('libart.so') || Module.findBaseAddress('libart.so.0')),
  get androidVersion() {
    try { return __goauld.javaAndroidVersion(); } catch (_) { return 'unknown'; }
  },
  ACC_PUBLIC: 0x0001,
  ACC_PRIVATE: 0x0002,
  ACC_PROTECTED: 0x0004,
  ACC_STATIC: 0x0008,
  ACC_FINAL: 0x0010,
  ACC_SYNCHRONIZED: 0x0020,
  ACC_BRIDGE: 0x0040,
  ACC_VARARGS: 0x0080,
  ACC_NATIVE: 0x0100,
  ACC_ABSTRACT: 0x0400,
  ACC_STRICT: 0x0800,
  ACC_SYNTHETIC: 0x1000,
  perform: function(fn) {
    if (typeof fn !== 'function') return;
    try { __goauld.javaEnsureVm(); } catch (_) {}
    return fn();
  },
  performNow: function(fn) {
    if (typeof fn !== 'function') return;
    try { __goauld.javaEnsureVm(); } catch (_) {}
    return fn();
  },
  scheduleOnMainThread: function(fn) {
    var token = __goauld.javaNextMainToken();
    __javaMainFns[token] = fn;
    if (!__goauld.javaScheduleMain(token)) {
      delete __javaMainFns[token];
      return fn();
    }
  },
  isMainThread: function() {
    try { return !!__goauld.javaIsMainThread(); } catch (_) { return false; }
  },
  use: function(className) { return __goauld_wrapJavaClass(String(className)); },
  choose: function(_c, cbs) { if (cbs && cbs.onComplete) cbs.onComplete(); },
  retain: function(obj) { return obj; },
  cast: function(handle, _klass) {
    if (handle && typeof handle === 'object') {
      handle.$className = handle.$className || (_klass && _klass.className) || 'java.lang.Object';
    }
    return handle;
  },
  array: function(type, elements) {
    var a = Array.prototype.slice.call(elements || []);
    a.$type = type;
    return a;
  },
  enumerateLoadedClasses: function(cbs) {
    var names = [];
    try { names = JSON.parse(__goauld.javaEnumerateClassesJson()); } catch (_) {}
    for (var i = 0; i < names.length; i++) {
      if (cbs && cbs.onMatch) cbs.onMatch(names[i], null);
    }
    if (cbs && cbs.onComplete) cbs.onComplete();
  },
  enumerateLoadedClassesSync: function() {
    try { return JSON.parse(__goauld.javaEnumerateClassesJson()); } catch (_) { return []; }
  },
  enumerateClassLoaders: function(cbs) {
    var loaders = [];
    try { loaders = JSON.parse(__goauld.javaEnumerateLoadersJson()); } catch (_) {}
    for (var i = 0; i < loaders.length; i++) {
      if (cbs && cbs.onMatch) cbs.onMatch({ $className: loaders[i], toString: function(){ return this.$className; } });
    }
    if (cbs && cbs.onComplete) cbs.onComplete();
  },
  enumerateClassLoadersSync: function() {
    var loaders = [];
    try { loaders = JSON.parse(__goauld.javaEnumerateLoadersJson()); } catch (_) {}
    return loaders.map(function(s){ return { $className: s }; });
  },
  enumerateMethods: function(query) {
    query = String(query || '*!*');
    var insensitive = query.indexOf('/i') >= 0;
    var withSig = query.indexOf('/s') >= 0;
    var userOnly = query.indexOf('/u') >= 0;
    var q = query.split('/')[0];
    var parts = q.split('!');
    var classPat = parts[0] || '*';
    var methodPat = parts[1] || '*';
    function globRe(g) {
      var s = String(g).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\\*/g, '.*').replace(/\\?/g, '.');
      return new RegExp('^' + s + '$', insensitive ? 'i' : '');
    }
    var cre = globRe(classPat);
    var mre = globRe(methodPat);
    var classes = Java.enumerateLoadedClassesSync();
    var grouped = { loader: '<default>', classes: [] };
    for (var i = 0; i < classes.length; i++) {
      var cn = classes[i];
      if (userOnly && (cn.indexOf('android.') === 0 || cn.indexOf('java.') === 0 || cn.indexOf('dalvik.') === 0)) continue;
      if (!cre.test(cn)) continue;
      var meths = [];
      try {
        var ms = JSON.parse(__goauld.javaClassMethodsJson(cn));
        for (var j = 0; j < ms.length; j++) {
          if (!mre.test(ms[j].name)) continue;
          meths.push(withSig ? (ms[j].name + ms[j].sig) : ms[j].name);
        }
      } catch (_) {}
      if (meths.length) grouped.classes.push({ name: cn, methods: meths });
    }
    return grouped.classes.length ? [grouped] : [];
  },
  /** Declared fields for a class (name/type/isStatic). */
  enumerateFieldsSync: function(className) {
    try { return JSON.parse(__goauld.javaClassFieldsJson(String(className))); } catch (_) { return []; }
  },
  /** Read a static field value (JSON-decoded primitive / string / {class,toString}). */
  readStaticField: function(className, fieldName) {
    try {
      return JSON.parse(__goauld.javaReadStaticFieldJson(String(className), String(fieldName)));
    } catch (e) {
      return { error: String(e) };
    }
  },
  /** SharedPreferences + dataDir listing + small files under files/. */
  dumpAppStorageSync: function() {
    try { return JSON.parse(__goauld.javaDumpStorageJson()); } catch (_) { return {}; }
  },
  backtrace: function(_opts) {
    return Thread.backtrace(null, Backtracer.FUZZY).map(function(p) {
      return { native: true, address: p, methodName: null, className: null, fileName: null, lineNumber: null, methodFlags: 0 };
    });
  },
  openClassFile: function(path) {
    return {
      load: function() { throw new Error('Java.openClassFile.load not yet implemented: ' + path); },
      getClassNames: function() { return []; }
    };
  },
  registerClass: function(_spec) {
    throw new Error('Java.registerClass not yet implemented');
  },
  deoptimizeEverything: function() {},
  deoptimizeBootImage: function() {},
  vm: {
    perform: function(fn) { return fn(); },
    getEnv: function() { return null; }
  },
  classFactory: {
    loader: null,
    cacheDir: '/data/local/tmp',
    use: function(n) { return Java.use(n); },
    choose: function(c, cbs) { return Java.choose(c, cbs); },
    cast: function(h, k) { return Java.cast(h, k); },
    array: function(t, e) { return Java.array(t, e); },
    retain: function(o) { return Java.retain(o); },
    registerClass: function(s) { return Java.registerClass(s); },
    openClassFile: function(p) { return Java.openClassFile(p); }
  },
  ClassFactory: {
    get: function(_loader) { return Java.classFactory; }
  }
};

function __goauld_java_invoke(key, x) {
  if (globalThis.__goauldJavaInvoking) return { did: false };
  globalThis.__goauldJavaInvoking = true;
  var out = { did: false };
  try {
    var fn = __javaImpls[key];
    if (fn) {
      var methodName = key.split('.').pop();
      var self = {};
      self[methodName] = function (v) {
        if (typeof globalThis.__goauldCallOriginalOverride === 'function') {
          return globalThis.__goauldCallOriginalOverride(key, +v);
        }
        return __goauld.javaCallOriginal(key, +v);
      };
      var ret = fn.call(self, x);
      out = { did: true, ret: +ret };
    }
  } catch (e) {
    send('java-invoke-err:' + e);
    out = { did: false };
  }
  globalThis.__goauldJavaInvoking = false;
  return out;
}


var console = {
  log: function(a0, a1, a2, a3, a4, a5, a6, a7) {
    __goauld_console('info', [a0, a1, a2, a3, a4, a5, a6, a7]);
  },
  warn: function(a0, a1, a2, a3, a4, a5, a6, a7) {
    __goauld_console('warning', [a0, a1, a2, a3, a4, a5, a6, a7]);
  },
  error: function(a0, a1, a2, a3, a4, a5, a6, a7) {
    __goauld_console('error', [a0, a1, a2, a3, a4, a5, a6, a7]);
  }
};
function __goauld_console(level, argsLike) {
  var parts = [];
  for (var i = 0; i < argsLike.length; i++) {
    var a = argsLike[i];
    if (a === undefined) continue;
    if (a && typeof a === 'object' && typeof a.byteLength === 'number') {
      parts.push(hexdump(a));
    } else if (a === null) parts.push('null');
    else if (typeof a === 'object' && typeof a.address === 'number') parts.push(String(a));
    else if (typeof a === 'object') {
      try { parts.push(JSON.stringify(a)); } catch (_) { parts.push(String(a)); }
    } else parts.push(String(a));
  }
  var line = parts.join(' ');
  try { __goauld.consoleLog(level, line); } catch (_) {}
  try { send({ type: 'log', level: level, message: line }); } catch (_) {}
}

function hexdump(target, options) {
  options = options || {};
  var offset = options.offset || 0;
  var length = (options.length != null) ? options.length : 256;
  var header = (options.header !== false);
  var address = options.address;
  var bytes = [];
  var baseAddr = 0;
  if (target && typeof target === 'object' && typeof target.byteLength === 'number') {
    var view = (target instanceof ArrayBuffer) ? new Uint8Array(target) : new Uint8Array(target.buffer || target);
    var end = Math.min(view.length, offset + length);
    for (var i = offset; i < end; i++) bytes.push(view[i]);
    baseAddr = address ? ((typeof address === 'object') ? address.address : +address) : 0;
  } else {
    var p = (typeof target === 'object' && target && typeof target.address === 'number')
      ? target.address : +target;
    baseAddr = address ? ((typeof address === 'object') ? address.address : +address) : p;
    var raw = Memory.readByteArray(ptr(p).add(offset), length);
    for (var j = 0; j < raw.length; j++) bytes.push(raw[j] & 0xff);
  }
  var lines = [];
  if (header) {
    lines.push('           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF');
  }
  for (var row = 0; row < bytes.length; row += 16) {
    var addr = (baseAddr + row) >>> 0;
    var hex = '';
    var ascii = '';
    for (var col = 0; col < 16; col++) {
      if (row + col < bytes.length) {
        var b = bytes[row + col] & 0xff;
        hex += __goauld_hex_byte(b) + ' ';
        ascii += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '.';
      } else {
        hex += '   ';
        ascii += ' ';
      }
    }
    var addrStr = __goauld_hex_u32(addr, 8);
    lines.push(addrStr + '  ' + hex + ' ' + ascii);
  }
  return lines.join('\n');
}

var __timerCbs = {};
function setTimeout(fn, delay, p0, p1, p2, p3) {
  if (typeof fn !== 'function') throw new Error('setTimeout requires a function');
  var args = [];
  if (p0 !== undefined) args.push(p0);
  if (p1 !== undefined) args.push(p1);
  if (p2 !== undefined) args.push(p2);
  if (p3 !== undefined) args.push(p3);
  var id = __goauld.scheduleTimer(+(delay || 0), false);
  __timerCbs[id] = { fn: fn, args: args, once: true };
  return id;
}
function setInterval(fn, delay, p0, p1, p2, p3) {
  if (typeof fn !== 'function') throw new Error('setInterval requires a function');
  var args = [];
  if (p0 !== undefined) args.push(p0);
  if (p1 !== undefined) args.push(p1);
  if (p2 !== undefined) args.push(p2);
  if (p3 !== undefined) args.push(p3);
  var id = __goauld.scheduleTimer(+(delay || 0), true);
  __timerCbs[id] = { fn: fn, args: args, once: false };
  return id;
}
function setImmediate(fn, p0, p1, p2, p3) {
  return setTimeout(fn, 0, p0, p1, p2, p3);
}
function clearTimeout(id) {
  delete __timerCbs[id];
  __goauld.cancelTimer(+id);
}
function clearInterval(id) { clearTimeout(id); }
function clearImmediate(id) { clearTimeout(id); }
function __goauld_fireTimer(id) {
  var t = __timerCbs[id];
  if (!t) return;
  if (t.once) delete __timerCbs[id];
  try { t.fn.apply(null, t.args); } catch (e) {
    try { console.error('timer callback:', e); } catch (_) {}
  }
}

function gc() {
  try { __goauld.runGc(); } catch (_) {}
}

function Worker(url, options) {
  throw new Error('Worker is not supported in goauld (single QuickJS heap)');
}

var Cloak = {
  addThread: function(id) { __goauld.cloakAddThread(+id); },
  removeThread: function(id) { __goauld.cloakRemoveThread(+id); },
  hasCurrentThread: function() { return !!__goauld.cloakHasCurrentThread(); },
  hasThread: function(id) { return !!__goauld.cloakHasThread(+id); },
  addRange: function(range) {
    var b = (typeof range.base === 'object') ? range.base.address : +range.base;
    __goauld.cloakAddRange(+b, +range.size);
  },
  removeRange: function(range) {
    var b = (typeof range.base === 'object') ? range.base.address : +range.base;
    __goauld.cloakRemoveRange(+b, +range.size);
  },
  hasRangeContaining: function(address) {
    var a = (typeof address === 'object') ? address.address : +address;
    return !!__goauld.cloakHasRangeContaining(+a);
  },
  clipRange: function(range) {
    var b = (typeof range.base === 'object') ? range.base.address : +range.base;
    var j = __goauld.cloakClipRangeJson(+b, +range.size);
    if (j === 'null') return null;
    return JSON.parse(j).map(function(r) {
      return { base: ptr(r.base), size: r.size };
    });
  },
  addFileDescriptor: function(fd) { __goauld.cloakAddFd(+fd); },
  removeFileDescriptor: function(fd) { __goauld.cloakRemoveFd(+fd); },
  hasFileDescriptor: function(fd) { return !!__goauld.cloakHasFd(+fd); }
};

function WallClockSampler() {}
WallClockSampler.prototype.sample = function() {
  return __goauldBigInt(__goauld.wallClockSample());
};
function CycleSampler() {}
CycleSampler.prototype.sample = function() {
  return __goauldBigInt(__goauld.cycleSample());
};
function BusyCycleSampler() {}
BusyCycleSampler.prototype.sample = function() {
  return __goauldBigInt(__goauld.cycleSample());
};
function UserTimeSampler(threadId) {
  this._tid = (threadId != null) ? +threadId : -1;
}
UserTimeSampler.prototype.sample = function() {
  return __goauldBigInt(__goauld.userTimeSample(this._tid));
};
function MallocCountSampler() { this._n = 0; }
MallocCountSampler.prototype.sample = function() { return this._n; };
function CallCountSampler(functions) {
  this._n = 0;
  this._fns = functions || [];
}
CallCountSampler.prototype.sample = function() { return this._n; };

function Profiler() {
  this._entries = [];
  this._listeners = [];
}
Profiler.prototype.instrument = function(functionAddress, sampler, callbacks) {
  var self = this;
  var addr = (typeof functionAddress === 'object') ? functionAddress : ptr(functionAddress);
  var entry = {
    address: addr,
    worst: null,
    count: 0,
    describeText: null,
    describe: callbacks && callbacks.describe
  };
  self._entries.push(entry);
  var listener = Interceptor.attach(addr, {
    onEnter: function(args) {
      this._t0 = sampler.sample();
      this._args = args;
    },
    onLeave: function(_retval) {
      var t1 = sampler.sample();
      var delta = t1 - this._t0;
      entry.count++;
      if (entry.worst === null || delta > entry.worst) {
        entry.worst = delta;
        if (typeof entry.describe === 'function') {
          try { entry.describeText = String(entry.describe.call(this, this._args)); }
          catch (_) { entry.describeText = null; }
        }
      }
    }
  });
  self._listeners.push(listener);
};
Profiler.prototype.generateReport = function() {
  var parts = ['<report>'];
  for (var i = 0; i < this._entries.length; i++) {
    var e = this._entries[i];
    parts.push('<worst-case>');
    parts.push('<address>' + String(e.address) + '</address>');
    parts.push('<count>' + e.count + '</count>');
    parts.push('<value>' + String(e.worst != null ? e.worst : 0) + '</value>');
    if (e.describeText) parts.push('<description>' + e.describeText + '</description>');
    parts.push('</worst-case>');
  }
  parts.push('</report>');
  return parts.join('');
};


function __goauld_try_define_getter(obj, name, getter, setter) {
  if (typeof Object.defineProperty !== 'function') return false;
  try {
    var desc = { configurable: true, enumerable: true, get: getter };
    if (setter) desc.set = setter;
    Object.defineProperty(obj, name, desc);
    var probe = {};
    Object.defineProperty(probe, '__g', { get: function() { return 1; } });
    return probe.__g === 1;
  } catch (_) {
    return false;
  }
}

function __arm64_check(res) {
  var j = (typeof res === 'string') ? JSON.parse(res) : res;
  if (!j || !j.ok) {
    var em = j && j.error;
    if (em != null && typeof em !== 'string') {
      try { em = JSON.stringify(em); } catch (_) { em = '' + em; }
    }
    throw new Error(em || 'Arm64 op failed');
  }
  return j;
}
function __arm64_addr(v) {
  if (v == null) return 0;
  if (typeof v === 'object' && typeof v.address === 'number') return +v.address;
  return +v;
}
/** Pack writer ops as one JSON array string — avoids Symbiote multi-arg leaf glitches. */
function __arm64_op(id, op, args) {
  var argsStr = JSON.stringify(args || {});
  if (typeof __g_hostOp === 'function') {
    var bundle = '[' + (+id) + ',' + JSON.stringify(String(op)) + ',' + JSON.stringify(argsStr) + ']';
    var raw = __g_hostOp('arm64WriterOp', bundle);
    var outer = (typeof raw === 'string') ? JSON.parse(raw) : raw;
    if (!outer || !outer.ok) {
      var em = outer && outer.error;
      throw new Error((typeof em === 'string') ? em : 'arm64WriterOp host failed');
    }
    return __arm64_check(outer.v);
  }
  return __arm64_check(__goauld.arm64WriterOp(+id, op, argsStr));
}

function Arm64Writer(codeAddress, options) {
  var addr = __arm64_addr(codeAddress);
  var pc = (options && options.pc != null) ? __arm64_addr(options.pc) : -1;
  this._id = __goauld.arm64WriterNew(addr, pc);
  this._refresh();
}
// Symbiote has no working Object.defineProperty getters — keep Frida fields as data props.
Arm64Writer.prototype._refresh = function() {
  this.base = ptr(__arm64_op(this._id, 'base', {}).v);
  this.code = ptr(__arm64_op(this._id, 'code', {}).v);
  this.pc = ptr(__arm64_op(this._id, 'pc', {}).v);
  this.offset = +__arm64_op(this._id, 'offset', {}).v;
};
Arm64Writer.prototype._op = function(op, args) {
  var r = __arm64_op(this._id, op, args || {});
  if (op !== 'dispose') this._refresh();
  return r;
};
Arm64Writer.prototype.reset = function(codeAddress, options) {
  var addr = __arm64_addr(codeAddress);
  var args = { codeAddress: addr };
  if (options && options.pc != null) args.pc = __arm64_addr(options.pc);
  this._op('reset', args);
};
Arm64Writer.prototype.dispose = function() { this._op('dispose', {}); };
Arm64Writer.prototype.flush = function() { this._op('flush', {}); };
Arm64Writer.prototype.skip = function(n) { this._op('skip', { n: +n }); };
Arm64Writer.prototype.putLabel = function(id) { this._op('putLabel', { id: String(id) }); };
Arm64Writer.prototype.putNop = function() { this._op('putNop', {}); };
Arm64Writer.prototype.putRet = function() { this._op('putRet', {}); };
Arm64Writer.prototype.putRetReg = function(reg) { this._op('putRetReg', { reg: String(reg) }); };
Arm64Writer.prototype.putBrkImm = function(imm) { this._op('putBrkImm', { imm: +imm }); };
Arm64Writer.prototype.putInstruction = function(insn) { this._op('putInstruction', { insn: +insn >>> 0 }); };
Arm64Writer.prototype.putBytes = function(data) {
  var arr = [];
  if (data && typeof data.length === 'number') {
    for (var i = 0; i < data.length; i++) arr.push(data[i] & 0xff);
  }
  this._op('putBytes', { data: arr });
};
Arm64Writer.prototype.putBranchAddress = function(address) {
  this._op('putBranchAddress', { address: __arm64_addr(address) });
};
Arm64Writer.prototype.canBranchDirectlyBetween = function(from, to) {
  return !!this._op('canBranchDirectlyBetween', {
    from: __arm64_addr(from), to: __arm64_addr(to)
  }).v;
};
Arm64Writer.prototype.putBImm = function(address) {
  this._op('putBImm', { address: __arm64_addr(address) });
};
Arm64Writer.prototype.putBlImm = function(address) {
  this._op('putBlImm', { address: __arm64_addr(address) });
};
Arm64Writer.prototype.putBLabel = function(labelId) {
  this._op('putBLabel', { labelId: String(labelId) });
};
Arm64Writer.prototype.putBlLabel = function(labelId) {
  this._op('putBlLabel', { labelId: String(labelId) });
};
Arm64Writer.prototype.putBCondLabel = function(cc, labelId) {
  this._op('putBCondLabel', { cc: String(cc), labelId: String(labelId) });
};
Arm64Writer.prototype.putBrReg = function(reg) { this._op('putBrReg', { reg: String(reg) }); };
Arm64Writer.prototype.putBrRegNoAuth = function(reg) { this.putBrReg(reg); };
Arm64Writer.prototype.putBlrReg = function(reg) { this._op('putBlrReg', { reg: String(reg) }); };
Arm64Writer.prototype.putBlrRegNoAuth = function(reg) { this.putBlrReg(reg); };
Arm64Writer.prototype.putCbzRegImm = function(reg, target) {
  this._op('putCbzRegImm', { reg: String(reg), target: __arm64_addr(target) });
};
Arm64Writer.prototype.putCbnzRegImm = function(reg, target) {
  this._op('putCbnzRegImm', { reg: String(reg), target: __arm64_addr(target) });
};
Arm64Writer.prototype.putCbzRegLabel = function(reg, labelId) {
  this._op('putCbzRegLabel', { reg: String(reg), labelId: String(labelId) });
};
Arm64Writer.prototype.putCbnzRegLabel = function(reg, labelId) {
  this._op('putCbnzRegLabel', { reg: String(reg), labelId: String(labelId) });
};
Arm64Writer.prototype.putTbzRegImmImm = function(reg, bit, target) {
  this._op('putTbzRegImmImm', { reg: String(reg), bit: +bit, target: __arm64_addr(target) });
};
Arm64Writer.prototype.putTbnzRegImmImm = function(reg, bit, target) {
  this._op('putTbnzRegImmImm', { reg: String(reg), bit: +bit, target: __arm64_addr(target) });
};
Arm64Writer.prototype.putTbzRegImmLabel = function(reg, bit, labelId) {
  this._op('putTbzRegImmLabel', { reg: String(reg), bit: +bit, labelId: String(labelId) });
};
Arm64Writer.prototype.putTbnzRegImmLabel = function(reg, bit, labelId) {
  this._op('putTbnzRegImmLabel', { reg: String(reg), bit: +bit, labelId: String(labelId) });
};
Arm64Writer.prototype.putPushRegReg = function(regA, regB) {
  this._op('putPushRegReg', { regA: String(regA), regB: String(regB) });
};
Arm64Writer.prototype.putPopRegReg = function(regA, regB) {
  this._op('putPopRegReg', { regA: String(regA), regB: String(regB) });
};
Arm64Writer.prototype.putLdrRegAddress = function(reg, address) {
  this._op('putLdrRegAddress', { reg: String(reg), address: __arm64_addr(address) });
};
Arm64Writer.prototype.putLdrRegU32 = function(reg, val) {
  this._op('putLdrRegU32', { reg: String(reg), val: +val >>> 0 });
};
Arm64Writer.prototype.putLdrRegU64 = function(reg, val) {
  this._op('putLdrRegU64', { reg: String(reg), val: __arm64_addr(val) });
};
Arm64Writer.prototype.putLdrRegReg = function(dstReg, srcReg) {
  this._op('putLdrRegReg', { dstReg: String(dstReg), srcReg: String(srcReg) });
};
Arm64Writer.prototype.putLdrRegRegOffset = function(dstReg, srcReg, srcOffset) {
  this._op('putLdrRegRegOffset', {
    dstReg: String(dstReg), srcReg: String(srcReg), srcOffset: +srcOffset
  });
};
Arm64Writer.prototype.putLdrRegRegOffsetMode = function(dstReg, srcReg, srcOffset, mode) {
  this._op('putLdrRegRegOffsetMode', {
    dstReg: String(dstReg), srcReg: String(srcReg), srcOffset: +srcOffset, mode: String(mode)
  });
};
Arm64Writer.prototype.putStrRegReg = function(srcReg, dstReg) {
  this._op('putStrRegReg', { srcReg: String(srcReg), dstReg: String(dstReg) });
};
Arm64Writer.prototype.putStrRegRegOffset = function(srcReg, dstReg, dstOffset) {
  this._op('putStrRegRegOffset', {
    srcReg: String(srcReg), dstReg: String(dstReg), dstOffset: +dstOffset
  });
};
Arm64Writer.prototype.putStrRegRegOffsetMode = function(srcReg, dstReg, dstOffset, mode) {
  this._op('putStrRegRegOffsetMode', {
    srcReg: String(srcReg), dstReg: String(dstReg), dstOffset: +dstOffset, mode: String(mode)
  });
};
Arm64Writer.prototype.putStpRegRegRegOffset = function(regA, regB, regDst, dstOffset, mode) {
  this._op('putStpRegRegRegOffset', {
    regA: String(regA), regB: String(regB), regDst: String(regDst),
    dstOffset: +dstOffset, mode: String(mode)
  });
};
Arm64Writer.prototype.putMovRegReg = function(dstReg, srcReg) {
  this._op('putMovRegReg', { dstReg: String(dstReg), srcReg: String(srcReg) });
};
Arm64Writer.prototype.putMovkRegImm = function(reg, imm, shift) {
  this._op('putMovkRegImm', { reg: String(reg), imm: +imm, shift: +(shift || 0) });
};
Arm64Writer.prototype.putAddRegRegImm = function(dstReg, leftReg, rightValue) {
  this._op('putAddRegRegImm', {
    dstReg: String(dstReg), leftReg: String(leftReg), rightValue: +rightValue
  });
};
Arm64Writer.prototype.putAddRegRegReg = function(dstReg, leftReg, rightReg) {
  this._op('putAddRegRegReg', {
    dstReg: String(dstReg), leftReg: String(leftReg), rightReg: String(rightReg)
  });
};
Arm64Writer.prototype.putSubRegRegImm = function(dstReg, leftReg, rightValue) {
  this._op('putSubRegRegImm', {
    dstReg: String(dstReg), leftReg: String(leftReg), rightValue: +rightValue
  });
};
Arm64Writer.prototype.putSubRegRegReg = function(dstReg, leftReg, rightReg) {
  this._op('putSubRegRegReg', {
    dstReg: String(dstReg), leftReg: String(leftReg), rightReg: String(rightReg)
  });
};
Arm64Writer.prototype.putAndRegRegImm = function(dstReg, leftReg, rightValue) {
  this._op('putAndRegRegImm', {
    dstReg: String(dstReg), leftReg: String(leftReg), rightValue: +rightValue
  });
};
Arm64Writer.prototype.putEorRegRegReg = function(dstReg, leftReg, rightReg) {
  this._op('putEorRegRegReg', {
    dstReg: String(dstReg), leftReg: String(leftReg), rightReg: String(rightReg)
  });
};
Arm64Writer.prototype.putLslRegImm = function(dstReg, srcReg, shift) {
  this._op('putLslRegImm', {
    dstReg: String(dstReg), srcReg: String(srcReg), shift: +shift
  });
};
Arm64Writer.prototype.putCmpRegReg = function(regA, regB) {
  this._op('putCmpRegReg', { regA: String(regA), regB: String(regB) });
};
Arm64Writer.prototype.putAdrpRegAddress = function(reg, address) {
  this._op('putAdrpRegAddress', { reg: String(reg), address: __arm64_addr(address) });
};
Arm64Writer.prototype.putPushAllXRegisters = function() {
  this._op('putPushAllXRegisters', {});
};
Arm64Writer.prototype.putPopAllXRegisters = function() {
  this._op('putPopAllXRegisters', {});
};
Arm64Writer.prototype.putPushAllQRegisters = function() {
  this._op('putPushAllQRegisters', {});
};
Arm64Writer.prototype.putPopAllQRegisters = function() {
  this._op('putPopAllQRegisters', {});
};
Arm64Writer.prototype.putLdrRegU32Ptr = function(reg, srcAddress) {
  this._op('putLdrRegU32Ptr', { reg: String(reg), srcAddress: __arm64_addr(srcAddress) });
};
Arm64Writer.prototype.putLdrRegU64Ptr = function(reg, srcAddress) {
  this._op('putLdrRegU64Ptr', { reg: String(reg), srcAddress: __arm64_addr(srcAddress) });
};
Arm64Writer.prototype.putLdrRegRef = function(reg) {
  return this._op('putLdrRegRef', { reg: String(reg) }).v;
};
Arm64Writer.prototype.putLdrRegValue = function(ref, value) {
  this._op('putLdrRegValue', { ref: +ref, value: __arm64_addr(value) });
};
Arm64Writer.prototype.putLdrswRegRegOffset = function(dstReg, srcReg, srcOffset) {
  this._op('putLdrswRegRegOffset', {
    dstReg: String(dstReg), srcReg: String(srcReg), srcOffset: +srcOffset
  });
};
Arm64Writer.prototype.putLdpRegRegRegOffset = function(regA, regB, regSrc, srcOffset, mode) {
  this._op('putLdpRegRegRegOffset', {
    regA: String(regA), regB: String(regB), regSrc: String(regSrc),
    srcOffset: +srcOffset, mode: String(mode)
  });
};
Arm64Writer.prototype.putMovRegNzcv = function(reg) {
  this._op('putMovRegNzcv', { reg: String(reg) });
};
Arm64Writer.prototype.putMovNzcvReg = function(reg) {
  this._op('putMovNzcvReg', { reg: String(reg) });
};
Arm64Writer.prototype.putUxtwRegReg = function(dstReg, srcReg) {
  this._op('putUxtwRegReg', { dstReg: String(dstReg), srcReg: String(srcReg) });
};
Arm64Writer.prototype.putUbfm = function(dstReg, srcReg, imms, immr) {
  this._op('putUbfm', {
    dstReg: String(dstReg), srcReg: String(srcReg), imms: +imms, immr: +immr
  });
};
Arm64Writer.prototype.putLsrRegImm = function(dstReg, srcReg, shift) {
  this._op('putLsrRegImm', {
    dstReg: String(dstReg), srcReg: String(srcReg), shift: +shift
  });
};
Arm64Writer.prototype.putTstRegImm = function(reg, immValue) {
  this._op('putTstRegImm', { reg: String(reg), immValue: +immValue });
};
Arm64Writer.prototype.putXpaciReg = function(reg) {
  this._op('putXpaciReg', { reg: String(reg) });
};
Arm64Writer.prototype.putPaciaRegReg = function(dstReg, modReg) {
  this._op('putPaciaRegReg', { dstReg: String(dstReg), modReg: String(modReg) });
};
Arm64Writer.prototype.putMrs = function(dstReg, systemReg) {
  this._op('putMrs', { dstReg: String(dstReg), systemReg: +systemReg });
};
Arm64Writer.prototype.putCallAddressWithArguments = function(func, args) {
  var mapped = [];
  for (var i = 0; i < (args || []).length; i++) {
    var a = args[i];
    if (typeof a === 'string') mapped.push(a);
    else mapped.push(__arm64_addr(a));
  }
  this._op('putCallAddressWithArguments', {
    func: __arm64_addr(func), args: mapped
  });
};
Arm64Writer.prototype.putCallRegWithArguments = function(reg, args) {
  var mapped = [];
  for (var i = 0; i < (args || []).length; i++) {
    var a = args[i];
    if (typeof a === 'string') mapped.push(a);
    else mapped.push(__arm64_addr(a));
  }
  this._op('putCallRegWithArguments', {
    reg: String(reg), args: mapped
  });
};
Arm64Writer.prototype.sign = function(value) {
  return ptr(this._op('sign', { value: __arm64_addr(value) }).v);
};

function __reloc_op(self, op, args) {
  var argsStr = JSON.stringify(args || {});
  if (typeof __g_hostOp === 'function') {
    var bundle = '[' + (+self._id) + ',' + (+self._writerId) + ',' + JSON.stringify(String(op)) + ',' + JSON.stringify(argsStr) + ']';
    var raw = __g_hostOp('arm64RelocatorOp', bundle);
    var outer = (typeof raw === 'string') ? JSON.parse(raw) : raw;
    if (!outer || !outer.ok) {
      var em = outer && outer.error;
      throw new Error((typeof em === 'string') ? em : 'arm64RelocatorOp host failed');
    }
    return __arm64_check(outer.v);
  }
  return __arm64_check(__goauld.arm64RelocatorOp(+self._id, +self._writerId, op, argsStr));
}
function Arm64Relocator(inputCode, output) {
  this._writerId = output._id;
  this._id = __goauld.arm64RelocatorNew(__arm64_addr(inputCode), this._writerId);
  if (!this._id) throw new Error('Arm64Relocator: bad writer');
  this._refresh();
}
Arm64Relocator.prototype._refresh = function() {
  this.eob = !!__reloc_op(this, 'eob', {}).v;
  this.eoi = !!__reloc_op(this, 'eoi', {}).v;
  var v = __reloc_op(this, 'input', {}).v;
  this.input = (v == null) ? null : ptr(v);
};
Arm64Relocator.prototype._op = function(op, args) {
  var r = __reloc_op(this, op, args || {});
  if (op !== 'dispose') this._refresh();
  return r;
};
Arm64Relocator.prototype.reset = function(inputCode, output) {
  if (output) this._writerId = output._id;
  this._op('reset', { inputCode: __arm64_addr(inputCode) });
};
Arm64Relocator.prototype.dispose = function() { this._op('dispose', {}); };
Arm64Relocator.prototype.readOne = function() { return this._op('readOne', {}).v; };
Arm64Relocator.prototype.skipOne = function() { return !!this._op('skipOne', {}).v; };
Arm64Relocator.prototype.writeOne = function() { return !!this._op('writeOne', {}).v; };
Arm64Relocator.prototype.writeAll = function() { this._op('writeAll', {}); };
Arm64Relocator.prototype.peekNextWriteSource = function() {
  var v = this._op('peekNextWriteSource', {}).v;
  return (v == null) ? null : ptr(v);
};
Arm64Relocator.prototype.peekNextWriteInsn = function() {
  return this._op('peekNextWriteInsn', {}).v;
};
Arm64Relocator.prototype.setSource = function(base, bytes) {
  var arr = [];
  if (bytes && typeof bytes.length === 'number') {
    for (var i = 0; i < bytes.length; i++) arr.push(bytes[i] & 0xff);
  }
  if (!__goauld.arm64RelocatorSetSource(+this._id, __arm64_addr(base), arr)) {
    throw new Error('Arm64Relocator.setSource failed');
  }
};

// AArch64 enum string constants (Frida-compatible values).
var Register = {
  x0:'x0',x1:'x1',x2:'x2',x3:'x3',x4:'x4',x5:'x5',x6:'x6',x7:'x7',
  x8:'x8',x9:'x9',x10:'x10',x11:'x11',x12:'x12',x13:'x13',x14:'x14',x15:'x15',
  x16:'x16',x17:'x17',x18:'x18',x19:'x19',x20:'x20',x21:'x21',x22:'x22',x23:'x23',
  x24:'x24',x25:'x25',x26:'x26',x27:'x27',x28:'x28',x29:'x29',x30:'x30',
  w0:'w0',w1:'w1',w2:'w2',w3:'w3',w4:'w4',w5:'w5',w6:'w6',w7:'w7',
  w8:'w8',w9:'w9',w10:'w10',w11:'w11',w12:'w12',w13:'w13',w14:'w14',w15:'w15',
  w16:'w16',w17:'w17',w18:'w18',w19:'w19',w20:'w20',w21:'w21',w22:'w22',w23:'w23',
  w24:'w24',w25:'w25',w26:'w26',w27:'w27',w28:'w28',w29:'w29',w30:'w30',
  sp:'sp',lr:'lr',fp:'fp',wsp:'wsp',wzr:'wzr',xzr:'xzr',ip0:'ip0',ip1:'ip1',
  q0:'q0',q1:'q1',q2:'q2',q3:'q3',q4:'q4',q5:'q5',q6:'q6',q7:'q7',
  q8:'q8',q9:'q9',q10:'q10',q11:'q11',q12:'q12',q13:'q13',q14:'q14',q15:'q15',
  q16:'q16',q17:'q17',q18:'q18',q19:'q19',q20:'q20',q21:'q21',q22:'q22',q23:'q23',
  q24:'q24',q25:'q25',q26:'q26',q27:'q27',q28:'q28',q29:'q29',q30:'q30',q31:'q31'
};
var ConditionCode = {
  eq:'eq',ne:'ne',hs:'hs',lo:'lo',mi:'mi',pl:'pl',vs:'vs',vc:'vc',
  hi:'hi',ls:'ls',ge:'ge',lt:'lt',gt:'gt',le:'le',al:'al',nv:'nv'
};
var IndexMode = {
  'post-adjust':'post-adjust',
  'signed-offset':'signed-offset',
  'pre-adjust':'pre-adjust'
};

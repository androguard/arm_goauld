// Example: Module.enumerateExports / Imports / Symbols / Sections / Dependencies.
// Expect: module-enum-ok

var libc = Process.findModuleByName('libc.so');
if (!libc) {
  send({ type: 'module-enum-err', err: 'libc.so not found' });
  send('module-enum-ok');
} else {
  var exports = libc.enumerateExports();
  var imports = libc.enumerateImports();
  var symbols = libc.enumerateSymbols();
  var sections = libc.enumerateSections();
  var deps = libc.enumerateDependencies();

  var hasStrlen = exports.some(function (e) { return e.name === 'strlen'; });
  var hasDlopenImport = imports.some(function (e) {
    return e.name === 'dlopen' || (e.name && e.name.indexOf('dlopen') >= 0);
  });
  var hasText = sections.some(function (s) {
    return s.name === '.text' || s.name.indexOf('text') >= 0;
  });
  var hasDynstr = sections.some(function (s) { return s.name === '.dynstr'; });
  var strlenSym = symbols.filter(function (s) { return s.name === 'strlen'; });

  var results = {
    module: libc.name,
    path: libc.path,
    exportCount: exports.length,
    importCount: imports.length,
    symbolCount: symbols.length,
    sectionCount: sections.length,
    depCount: deps.length,
    hasStrlenExport: hasStrlen,
    hasDlopenImport: hasDlopenImport,
    hasTextSection: hasText,
    hasDynstrSection: hasDynstr,
    strlenSymbol: strlenSym.length
      ? {
          type: strlenSym[0].type,
          isGlobal: strlenSym[0].isGlobal,
          address: String(strlenSym[0].address)
        }
      : null,
    sampleDeps: deps.slice(0, 5),
    sampleSections: sections.slice(0, 8).map(function (s) {
      return { id: s.id, name: s.name, size: s.size };
    }),
    sampleExports: exports.slice(0, 5).map(function (e) {
      return { type: e.type, name: e.name };
    }),
    sampleImports: imports.slice(0, 5).map(function (e) {
      return { type: e.type, name: e.name, hasSlot: !!e.slot };
    })
  };

  var ok =
    results.exportCount > 0 &&
    results.hasStrlenExport &&
    results.sectionCount > 0 &&
    (results.hasTextSection || results.hasDynstrSection) &&
    results.symbolCount > 0;

  send({ type: 'module-enum', results: results, ok: ok });
  send('module-enum-ok');
}

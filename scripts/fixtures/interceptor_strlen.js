var strlen = Module.findExportByName("libc.so", "strlen");
if (!strlen) {
  strlen = Module.findExportByName(null, "strlen");
}
send("strlen@" + strlen);
if (strlen) {
  Interceptor.attach(strlen, {
    onEnter: function (args) {
      try {
        send(args[0].readUtf8String());
      } catch (e) {
        send("onEnter-err:" + e);
      }
    }
  });
  send("interceptor-installed");
} else {
  send("strlen-not-found");
}

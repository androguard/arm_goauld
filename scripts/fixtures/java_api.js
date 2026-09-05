// Frida Java API surface smoke (https://frida.re/docs/javascript-api/#java)
Java.perform(function () {
  var info = {
    type: "java-api",
    available: Java.available,
    androidVersion: Java.androidVersion,
    isMain: Java.isMainThread(),
  };

  var classes = Java.enumerateLoadedClassesSync();
  info.classCount = classes.length;
  info.hasTarget = classes.indexOf("com.example.javatarget.Target") >= 0;

  var loaders = Java.enumerateClassLoadersSync();
  info.loaderCount = loaders.length;

  var groups = Java.enumerateMethods("com.example.javatarget.Target!hookMe");
  info.hookMeGroups = groups.length;
  if (groups.length && groups[0].classes.length) {
    info.hookMeMethods = groups[0].classes[0].methods;
  }

  var T = Java.use("com.example.javatarget.Target");
  T.hookMe.overload("int").implementation = function (x) {
    send({ type: "java-api-hook", x: x });
    return this.hookMe(x);
  };

  Java.scheduleOnMainThread(function () {
    send({ type: "java-api-main", isMain: Java.isMainThread() });
  });

  send(info);
  send({ type: "java-api-ok" });
});

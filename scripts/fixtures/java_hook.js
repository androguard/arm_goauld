Java.perform(function () {
  var T = Java.use("com.example.javatarget.Target");
  T.hookMe.implementation = function (x) {
    send("called with " + x);
    // callOriginal via backup ArtMethod (this.hookMe → javaCallOriginal).
    return this.hookMe(x) + 1000;
  };
});
send("java-hook-installed");

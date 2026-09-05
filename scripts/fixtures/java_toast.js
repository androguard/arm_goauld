// Frida-shaped toast using framework android.widget.Toast
// (not an API defined by the target APK).
//
// Mirrors https://codeshare.frida.re/@yodiaditya/simple-android-toast/
// and https://www.yodiw.com/frida-android-make-toast-non-rooted-device/

Java.perform(function () {
  var context = Java.use("android.app.ActivityThread")
    .currentApplication()
    .getApplicationContext();

  Java.scheduleOnMainThread(function () {
    var toast = Java.use("android.widget.Toast");
    toast
      .makeText(
        context,
        Java.use("java.lang.String").$new("Hello from goauld (android.widget.Toast)"),
        toast.LENGTH_LONG.value
      )
      .show();
  });
});

send("toast-shown");

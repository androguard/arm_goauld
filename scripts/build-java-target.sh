#!/usr/bin/env bash
# Minimal APK build for testapps/java-target (no Gradle).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/testapps/java-target"
OUT="$APP/build"
ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
BT="$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)"
PLATFORM="$(ls -d "$ANDROID_HOME"/platforms/android-* | sort -V | tail -1)"
ANDROID_JAR="$PLATFORM/android.jar"
JAVA_HOME="${JAVA_HOME:-/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
export PATH="$JAVA_HOME/bin:$BT:$PATH"

echo "build-tools=$BT"
echo "platform=$PLATFORM"
rm -rf "$OUT"
mkdir -p "$OUT"/{gen,obj,dex,apk}

"$BT/aapt2" compile --dir "$APP/res" -o "$OUT/compiled.zip" 2>/dev/null || {
  mkdir -p "$APP/res/values"
  cat > "$APP/res/values/strings.xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<resources><string name="app_name">java-target</string></resources>
EOF
  "$BT/aapt2" compile --dir "$APP/res" -o "$OUT/compiled.zip"
}

"$BT/aapt2" link -o "$OUT/apk/unsigned.apk" \
  -I "$ANDROID_JAR" \
  --manifest "$APP/AndroidManifest.xml" \
  --java "$OUT/gen" \
  "$OUT/compiled.zip"

mkdir -p "$OUT/obj"
javac --release 17 -classpath "$ANDROID_JAR" \
  -d "$OUT/obj" \
  "$APP/src/com/example/javatarget/Target.java"

"$BT/d8" --min-api 26 --output "$OUT/dex" "$OUT/obj"/com/example/javatarget/*.class
# Inject classes.dex into apk
(
  cd "$OUT/dex"
  zip -q "$OUT/apk/unsigned.apk" classes.dex
)

# Debug keystore
KS="$OUT/debug.keystore"
if [[ ! -f "$KS" ]]; then
  keytool -genkeypair -v -keystore "$KS" -storepass android -keypass android \
    -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=Android Debug,O=Android,C=US" >/dev/null
fi
"$BT/zipalign" -f 4 "$OUT/apk/unsigned.apk" "$OUT/apk/aligned.apk"
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
  --out "$OUT/java-target.apk" "$OUT/apk/aligned.apk"
echo "OK $OUT/java-target.apk"
ls -la "$OUT/java-target.apk"

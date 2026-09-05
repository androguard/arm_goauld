package goauld;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.widget.Toast;

/** Tiny helper loaded from the agent (InMemoryDexClassLoader), not the target APK. */
public final class ToastBridge {
    private ToastBridge() {}

    public static void show(final Context ctx, final String msg) {
        if (ctx == null || msg == null) {
            return;
        }
        final Runnable r =
                new Runnable() {
                    @Override
                    public void run() {
                        Toast.makeText(ctx, msg, Toast.LENGTH_LONG).show();
                    }
                };
        if (Looper.myLooper() == Looper.getMainLooper()) {
            r.run();
        } else {
            new Handler(Looper.getMainLooper()).post(r);
        }
    }
}

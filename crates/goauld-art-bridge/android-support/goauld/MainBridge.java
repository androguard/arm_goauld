package goauld;

import android.os.Handler;
import android.os.Looper;

/** Post work onto the app main looper; calls native {@link #onMain(long)}. */
public final class MainBridge {
    private MainBridge() {}

    public static native void onMain(long token);

    public static void post(final long token) {
        final Runnable r =
                new Runnable() {
                    @Override
                    public void run() {
                        onMain(token);
                    }
                };
        if (Looper.myLooper() == Looper.getMainLooper()) {
            r.run();
        } else {
            new Handler(Looper.getMainLooper()).post(r);
        }
    }
}

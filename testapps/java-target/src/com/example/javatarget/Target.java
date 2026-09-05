package com.example.javatarget;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/**
 * Minimal demo Activity for goauld Java hooks / toast / comm stress.
 *
 * Intentionally does <b>not</b> reference {@code android.widget.Toast}.
 *
 * <ul>
 *   <li>{@link #hookMe(int)} — Technique-A hook target (2s loop)
 *   <li>{@code apk-tick} thread — 50ms heartbeat used by {@code goauld stress}
 *       to measure whether agent↔host flooding starves the app
 * </ul>
 */
public class Target extends Activity {
    private static final String TAG = "java-target";

    /** Fixed signature for Java.use(...).hookMe.implementation tests. */
    public int hookMe(int x) {
        Log.i(TAG, "hookMe(" + x + ") native");
        return x * 2;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView status = new TextView(this);
        status.setText("java-target — hooks / toast / stress");
        status.setTextSize(18f);
        status.setTextColor(Color.WHITE);
        status.setBackgroundColor(Color.rgb(0x12, 0x12, 0x18));
        status.setPadding(48, 96, 48, 48);
        setContentView(status);
        Log.i(TAG, "onCreate");

        new Thread(
                        new Runnable() {
                            @Override
                            public void run() {
                                int n = 0;
                                while (true) {
                                    int r = hookMe(n++);
                                    Log.i(TAG, "hookMe returned " + r);
                                    try {
                                        Thread.sleep(2000);
                                    } catch (InterruptedException ignored) {
                                    }
                                }
                            }
                        },
                        "hook-loop")
                .start();

        // High-frequency heartbeat for communication stress impact measurement.
        new Thread(
                        new Runnable() {
                            @Override
                            public void run() {
                                long n = 0;
                                while (true) {
                                    long t = System.nanoTime();
                                    Log.i(TAG, "apk-tick n=" + n + " t=" + t);
                                    n++;
                                    try {
                                        Thread.sleep(50);
                                    } catch (InterruptedException ignored) {
                                    }
                                }
                            }
                        },
                        "apk-tick")
                .start();
    }
}

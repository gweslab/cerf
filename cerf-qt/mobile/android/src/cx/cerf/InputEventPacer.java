package cx.cerf;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.ActionMode;
import android.view.KeyEvent;
import android.view.KeyboardShortcutGroup;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.SearchEvent;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.view.accessibility.AccessibilityEvent;

import java.util.ArrayDeque;
import java.util.List;

final class InputEventPacer implements Window.Callback {
    private static final class Pending {
        final MotionEvent event;
        final long dueUptime;

        Pending(MotionEvent event, long dueUptime) {
            this.event = event;
            this.dueUptime = dueUptime;
        }
    }

    private static final class Installer implements Application.ActivityLifecycleCallbacks {
        @Override public void onActivityCreated(Activity activity, Bundle savedInstanceState) { wrap(activity); }
        @Override public void onActivityStarted(Activity activity) {}
        @Override public void onActivityResumed(Activity activity) {}
        @Override public void onActivityPaused(Activity activity) {}
        @Override public void onActivityStopped(Activity activity) {}
        @Override public void onActivitySaveInstanceState(Activity activity, Bundle outState) {}
        @Override public void onActivityDestroyed(Activity activity) {}
    }

    private static native long nativeCreate();
    private static native void nativeDestroy(long pacing);
    private static native void nativePush(long pacing, int code, boolean down, boolean up, boolean paced);
    private static native boolean nativePopReady(long pacing, long nowUptime);
    private static native long nativeHeadDue(long pacing);

    private final Window.Callback target;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final ArrayDeque<Pending> pending = new ArrayDeque<>();
    private final Runnable drain = this::drain;
    private final ArrayDeque<KeyEvent> pendingKeys = new ArrayDeque<>();
    private final Runnable drainKeys = this::drainKeys;
    private long keyPacing;
    private long anchorUptime;
    private long anchorEventTime;

    private InputEventPacer(Window.Callback target) {
        this.target = target;
    }

    static void install(Activity activity) {
        activity.getApplication().registerActivityLifecycleCallbacks(new Installer());
        wrap(activity);
    }

    private static void wrap(Activity activity) {
        Window window = activity.getWindow();
        window.setCallback(new InputEventPacer(window.getCallback()));
    }

    @Override
    public boolean dispatchTouchEvent(MotionEvent event) {
        final long now = SystemClock.uptimeMillis();
        if (pending.isEmpty() && event.getActionMasked() == MotionEvent.ACTION_DOWN) {
            anchorUptime    = now;
            anchorEventTime = event.getEventTime();
        }
        final long due = anchorUptime + (event.getEventTime() - anchorEventTime);
        if (pending.isEmpty() && due <= now) return target.dispatchTouchEvent(event);
        pending.addLast(new Pending(MotionEvent.obtain(event), due));
        if (pending.size() == 1) handler.postAtTime(drain, due);
        return true;
    }

    private void drain() {
        final long now = SystemClock.uptimeMillis();
        while (!pending.isEmpty() && pending.peekFirst().dueUptime <= now) {
            final MotionEvent event = pending.pollFirst().event;
            target.dispatchTouchEvent(event);
            event.recycle();
        }
        if (!pending.isEmpty()) handler.postAtTime(drain, pending.peekFirst().dueUptime);
    }

    @Override
    public boolean dispatchKeyEvent(KeyEvent event) {
        final int action = event.getAction();
        if (keyPacing == 0) keyPacing = nativeCreate();
        nativePush(keyPacing, event.getKeyCode(), action == KeyEvent.ACTION_DOWN, action == KeyEvent.ACTION_UP,
                   (event.getFlags() & KeyEvent.FLAG_SOFT_KEYBOARD) != 0);
        if (pendingKeys.isEmpty() && nativePopReady(keyPacing, SystemClock.uptimeMillis()))
            return target.dispatchKeyEvent(event);
        pendingKeys.addLast(new KeyEvent(event));
        if (pendingKeys.size() == 1) handler.postAtTime(drainKeys, nativeHeadDue(keyPacing));
        return true;
    }

    private void drainKeys() {
        while (!pendingKeys.isEmpty() && nativePopReady(keyPacing, SystemClock.uptimeMillis()))
            target.dispatchKeyEvent(pendingKeys.pollFirst());
        if (!pendingKeys.isEmpty()) handler.postAtTime(drainKeys, nativeHeadDue(keyPacing));
    }

    private void dropPending() {
        handler.removeCallbacks(drain);
        while (!pending.isEmpty()) pending.pollFirst().event.recycle();
        handler.removeCallbacks(drainKeys);
        pendingKeys.clear();
        if (keyPacing != 0) nativeDestroy(keyPacing);
        keyPacing = 0;
    }

    @Override public boolean dispatchKeyShortcutEvent(KeyEvent event) { return target.dispatchKeyShortcutEvent(event); }
    @Override public boolean dispatchTrackballEvent(MotionEvent event) { return target.dispatchTrackballEvent(event); }
    @Override public boolean dispatchGenericMotionEvent(MotionEvent event) { return target.dispatchGenericMotionEvent(event); }

    @Override
    public boolean dispatchPopulateAccessibilityEvent(AccessibilityEvent event) {
        return target.dispatchPopulateAccessibilityEvent(event);
    }

    @Override public View onCreatePanelView(int featureId) { return target.onCreatePanelView(featureId); }
    @Override public boolean onCreatePanelMenu(int featureId, Menu menu) { return target.onCreatePanelMenu(featureId, menu); }

    @Override
    public boolean onPreparePanel(int featureId, View view, Menu menu) {
        return target.onPreparePanel(featureId, view, menu);
    }

    @Override public boolean onMenuOpened(int featureId, Menu menu) { return target.onMenuOpened(featureId, menu); }

    @Override
    public boolean onMenuItemSelected(int featureId, MenuItem item) {
        return target.onMenuItemSelected(featureId, item);
    }

    @Override
    public void onWindowAttributesChanged(WindowManager.LayoutParams attrs) {
        target.onWindowAttributesChanged(attrs);
    }

    @Override public void onContentChanged() { target.onContentChanged(); }
    @Override public void onWindowFocusChanged(boolean hasFocus) { target.onWindowFocusChanged(hasFocus); }
    @Override public void onAttachedToWindow() { target.onAttachedToWindow(); }

    @Override
    public void onDetachedFromWindow() {
        dropPending();
        target.onDetachedFromWindow();
    }

    @Override public void onPanelClosed(int featureId, Menu menu) { target.onPanelClosed(featureId, menu); }
    @Override public boolean onSearchRequested() { return target.onSearchRequested(); }
    @Override public boolean onSearchRequested(SearchEvent searchEvent) { return target.onSearchRequested(searchEvent); }

    @Override
    public ActionMode onWindowStartingActionMode(ActionMode.Callback callback) {
        return target.onWindowStartingActionMode(callback);
    }

    @Override
    public ActionMode onWindowStartingActionMode(ActionMode.Callback callback, int type) {
        return target.onWindowStartingActionMode(callback, type);
    }

    @Override public void onActionModeStarted(ActionMode mode) { target.onActionModeStarted(mode); }
    @Override public void onActionModeFinished(ActionMode mode) { target.onActionModeFinished(mode); }

    @Override
    public void onProvideKeyboardShortcuts(List<KeyboardShortcutGroup> data, Menu menu, int deviceId) {
        target.onProvideKeyboardShortcuts(data, menu, deviceId);
    }

    @Override public void onPointerCaptureChanged(boolean hasCapture) { target.onPointerCaptureChanged(hasCapture); }
}

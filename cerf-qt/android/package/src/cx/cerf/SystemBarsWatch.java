package cx.cerf;

import android.app.Activity;
import android.os.Build;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowInsetsController;

final class SystemBarsWatch {
    @SuppressWarnings("deprecation")
    private static final int HIDDEN_FLAGS = View.SYSTEM_UI_FLAG_FULLSCREEN | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION;

    @SuppressWarnings("deprecation")
    private static final int FULL_SCREEN_FLAGS = View.SYSTEM_UI_FLAG_LAYOUT_STABLE
            | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN | HIDDEN_FLAGS
            | View.SYSTEM_UI_FLAG_IMMERSIVE;

    private static native void nativeShown(long link);

    private SystemBarsWatch() {}

    @SuppressWarnings("deprecation")
    static void install(Activity activity, long link) {
        final View decor = activity.getWindow().getDecorView();
        decor.setOnApplyWindowInsetsListener((view, insets) -> {
            revealBySwipe(activity);
            return view.onApplyWindowInsets(insets);
        });
        decor.setOnSystemUiVisibilityChangeListener(visibility -> {
            if ((visibility & HIDDEN_FLAGS) != HIDDEN_FLAGS) nativeShown(link);
        });
    }

    @SuppressWarnings("deprecation")
    static void hide(Activity activity) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            final WindowInsetsController controller = activity.getWindow().getInsetsController();
            if (controller == null) return;
            controller.setSystemBarsBehavior(WindowInsetsController.BEHAVIOR_DEFAULT);
            controller.hide(WindowInsets.Type.systemBars());
            return;
        }
        activity.getWindow().getDecorView().setSystemUiVisibility(FULL_SCREEN_FLAGS);
    }

    @SuppressWarnings("deprecation")
    static void useLightIcons(Activity activity, boolean light) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            final WindowInsetsController controller = activity.getWindow().getInsetsController();
            if (controller == null) return;
            final int lightBars = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                    | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;
            controller.setSystemBarsAppearance(light ? 0 : lightBars, lightBars);
            return;
        }
        final View decor = activity.getWindow().getDecorView();
        final int lightBars = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
        final int flags = decor.getSystemUiVisibility();
        decor.setSystemUiVisibility(light ? flags & ~lightBars : flags | lightBars);
    }

    @SuppressWarnings("deprecation")
    private static void revealBySwipe(Activity activity) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            final WindowInsetsController controller = activity.getWindow().getInsetsController();
            if (controller == null) return;
            if (controller.getSystemBarsBehavior() == WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE)
                controller.setSystemBarsBehavior(WindowInsetsController.BEHAVIOR_DEFAULT);
            return;
        }
        final View decor = activity.getWindow().getDecorView();
        final int flags = decor.getSystemUiVisibility();
        if ((flags & View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY) != 0)
            decor.setSystemUiVisibility((flags & ~View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY) | View.SYSTEM_UI_FLAG_IMMERSIVE);
    }
}

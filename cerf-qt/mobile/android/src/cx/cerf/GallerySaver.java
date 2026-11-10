package cx.cerf;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.os.Environment;
import android.provider.MediaStore;

import java.io.OutputStream;

public final class GallerySaver {
    private GallerySaver() {}

    public static String savePng(Context context, String fileName, byte[] png) {
        ContentResolver resolver = context.getContentResolver();
        ContentValues   values   = new ContentValues();
        values.put(MediaStore.MediaColumns.DISPLAY_NAME, fileName);
        values.put(MediaStore.MediaColumns.MIME_TYPE, "image/png");
        values.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_PICTURES + "/CERF");
        values.put(MediaStore.MediaColumns.IS_PENDING, 1);
        Uri item = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values);
        if (item == null) return "the media store refused " + fileName;
        try (OutputStream out = resolver.openOutputStream(item)) {
            if (out == null) throw new java.io.IOException("no output stream for " + item);
            out.write(png);
        } catch (Exception e) {
            resolver.delete(item, null, null);
            return e.toString();
        }
        values.clear();
        values.put(MediaStore.MediaColumns.IS_PENDING, 0);
        if (resolver.update(item, values, null, null) != 1) {
            resolver.delete(item, null, null);
            return "the media store did not publish " + fileName;
        }
        return null;
    }
}

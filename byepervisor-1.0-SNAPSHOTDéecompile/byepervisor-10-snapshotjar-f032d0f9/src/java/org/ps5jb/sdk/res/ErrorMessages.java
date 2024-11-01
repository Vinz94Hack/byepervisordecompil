package org.ps5jb.sdk.res;

import org.ps5jb.loader.Status;
import java.util.MissingResourceException;
import java.text.MessageFormat;
import java.util.StringTokenizer;
import java.util.Locale;
import java.util.ResourceBundle;

public final class ErrorMessages
{
    private static ResourceBundle resourceBundle;
    private static final String packagePrefix;
    private static final String rootPackage;
    
    private static Locale getLocale() {
        final String localeVal = System.getProperty(ErrorMessages.packagePrefix + ".Locale");
        Locale locale;
        if (localeVal == null) {
            locale = Locale.getDefault();
        }
        else {
            final String[] localeComponents = { null, null, null };
            int localeCompIndx = 0;
            final StringTokenizer localeTok = new StringTokenizer(localeVal, "_");
            while (localeTok.hasMoreTokens()) {
                localeComponents[localeCompIndx++] = localeTok.nextToken();
            }
            locale = new Locale(localeComponents[0], localeComponents[1], localeComponents[2]);
        }
        return locale;
    }
    
    private ErrorMessages() {
    }
    
    public static String getErrorMessage(final String key, final Object... formatArgs) {
        if (ErrorMessages.resourceBundle != null) {
            try {
                final String val = ErrorMessages.resourceBundle.getString(key);
                return MessageFormat.format(val, formatArgs);
            }
            catch (final MissingResourceException ex) {}
        }
        return key;
    }
    
    public static String getClassErrorMessage(final Class clazz, final String keySuffix, final Object... formatArgs) {
        String keyPrefix = clazz.getName();
        if (keyPrefix.startsWith(ErrorMessages.rootPackage)) {
            keyPrefix = keyPrefix.substring(ErrorMessages.rootPackage.length() + 1);
        }
        return getErrorMessage(keyPrefix + "." + keySuffix, formatArgs);
    }
    
    static {
        packagePrefix = ErrorMessages.class.getPackage().getName();
        rootPackage = ErrorMessages.packagePrefix.substring(0, ErrorMessages.packagePrefix.lastIndexOf("."));
        try {
            ErrorMessages.resourceBundle = ResourceBundle.getBundle(ErrorMessages.packagePrefix + ".error_messages", getLocale());
        }
        catch (final MissingResourceException e) {
            Status.printStackTrace(e.getMessage(), (Throwable)e);
        }
    }
}

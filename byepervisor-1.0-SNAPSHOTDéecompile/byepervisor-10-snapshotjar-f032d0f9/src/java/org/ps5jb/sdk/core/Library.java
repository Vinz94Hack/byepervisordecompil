package org.ps5jb.sdk.core;

import org.ps5jb.sdk.res.ErrorMessages;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Constructor;

public class Library
{
    private static Constructor NativeLibrary_new;
    private static Method NativeLibrary_findEntry;
    private static Method NativeLibrary_load;
    private static Field NativeLibrary_handle;
    private final Object nativeLibraryInstance;
    private CallContext callContext;
    
    private static void initNativeLibrary() {
        try {
            final Class nativeLibraryClass = Class.forName("java.lang.ClassLoader$NativeLibrary");
            (Library.NativeLibrary_new = nativeLibraryClass.getDeclaredConstructors()[0]).setAccessible(true);
            (Library.NativeLibrary_findEntry = nativeLibraryClass.getDeclaredMethod("findEntry", String.class)).setAccessible(true);
            (Library.NativeLibrary_load = nativeLibraryClass.getDeclaredMethod("load", (Class[])new Class[0])).setAccessible(true);
            (Library.NativeLibrary_handle = nativeLibraryClass.getDeclaredField("handle")).setAccessible(true);
        }
        catch (final NoSuchFieldException | NoSuchMethodException | ClassNotFoundException | RuntimeException | Error e) {
            throw new SdkRuntimeException(e);
        }
    }
    
    public Library(final long handle) {
        final Long h = new Long(handle);
        try {
            this.nativeLibraryInstance = Library.NativeLibrary_new.newInstance(new Object[] { this.getClass(), h.toString(), Boolean.TRUE });
            Library.NativeLibrary_handle.set(this.nativeLibraryInstance, (Object)h);
        }
        catch (final InvocationTargetException e) {
            throw new SdkRuntimeException(e.getTargetException().getMessage(), e.getTargetException());
        }
        catch (final IllegalAccessException | InstantiationException | RuntimeException | Error e2) {
            throw new SdkRuntimeException(e2.getMessage(), e2);
        }
    }
    
    public Library(final String path) {
        try {
            this.nativeLibraryInstance = Library.NativeLibrary_new.newInstance(new Object[] { this.getClass(), path, Boolean.FALSE });
            Library.NativeLibrary_load.invoke(this.nativeLibraryInstance, new Object[0]);
        }
        catch (final InvocationTargetException e) {
            throw new SdkRuntimeException(e.getTargetException().getMessage(), e.getTargetException());
        }
        catch (final IllegalAccessException | InstantiationException | RuntimeException | Error e2) {
            throw new SdkRuntimeException(e2.getMessage(), e2);
        }
    }
    
    static int getLibJavaHandle() {
        return CallContext.libjava_handle;
    }
    
    @Override
    protected void finalize() throws Throwable {
        try {
            this.closeLibrary();
        }
        finally {
            super.finalize();
        }
    }
    
    public void closeLibrary() {
        if (this.callContext != null) {
            this.callContext.close();
            this.callContext = null;
        }
    }
    
    protected long call(final Pointer function, final long... args) {
        if (this.callContext == null) {
            this.callContext = new CallContext();
        }
        return this.callContext.execute(function, args);
    }
    
    public long getHandle() {
        try {
            return (long)Library.NativeLibrary_handle.get(this.nativeLibraryInstance);
        }
        catch (final IllegalAccessException | RuntimeException | Error e) {
            throw new SdkRuntimeException(e.getMessage(), e);
        }
    }
    
    public Pointer addrOf(final String symbolName) {
        try {
            final Long symbolAddr = (Long)Library.NativeLibrary_findEntry.invoke(this.nativeLibraryInstance, new Object[] { symbolName });
            if (symbolAddr == null || symbolAddr == 0L) {
                throw new SdkSymbolNotFoundException(ErrorMessages.getClassErrorMessage(Library.class, "symbolNotFound", symbolName, "0x" + Long.toHexString(this.getHandle())));
            }
            return Pointer.valueOf(symbolAddr);
        }
        catch (final SdkRuntimeException e) {
            throw e;
        }
        catch (final InvocationTargetException e2) {
            throw new SdkRuntimeException(e2.getTargetException().getMessage(), e2.getTargetException());
        }
        catch (final IllegalAccessException | RuntimeException | Error e3) {
            throw new SdkRuntimeException(e3.getMessage(), e3);
        }
    }
    
    static {
        initNativeLibrary();
    }
}

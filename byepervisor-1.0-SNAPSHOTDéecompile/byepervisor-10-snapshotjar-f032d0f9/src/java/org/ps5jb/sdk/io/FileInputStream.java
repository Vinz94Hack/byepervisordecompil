package org.ps5jb.sdk.io;

import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import org.ps5jb.sdk.include.sys.fcntl.OpenFlag;
import org.ps5jb.sdk.lib.LibKernel;
import java.lang.reflect.Field;
import org.ps5jb.sdk.core.SdkRuntimeException;
import java.io.FileNotFoundException;
import java.io.File;
import java.io.FileDescriptor;

public class FileInputStream extends java.io.FileInputStream
{
    public FileInputStream(final String name) throws FileNotFoundException {
        super(new FileDescriptor());
        this.disableProxies();
        this.openFile(new File(name));
    }
    
    public FileInputStream(final File file) throws FileNotFoundException {
        super(new FileDescriptor());
        this.disableProxies();
        this.openFile(file);
    }
    
    public FileInputStream(final FileDescriptor fileDescriptor) {
        super(fileDescriptor);
        this.disableProxies();
    }
    
    private void disableProxies() {
        try {
            Field proxyField = java.io.FileInputStream.class.getDeclaredField("proxy");
            proxyField.setAccessible(true);
            proxyField.set((Object)this, (Object)null);
            final FileDescriptor fd = this.getFd();
            proxyField = FileDescriptor.class.getDeclaredField("proxy");
            proxyField.setAccessible(true);
            proxyField.set((Object)fd, (Object)null);
        }
        catch (final NoSuchFieldException ex) {}
        catch (final IllegalAccessException e) {
            throw new SdkRuntimeException((Throwable)e);
        }
    }
    
    private FileDescriptor getFd() {
        try {
            final Field fdField = java.io.FileInputStream.class.getDeclaredField("fd");
            fdField.setAccessible(true);
            return (FileDescriptor)fdField.get((Object)this);
        }
        catch (final NoSuchFieldException | IllegalAccessException e) {
            throw new SdkRuntimeException((Throwable)e);
        }
    }
    
    private void openFile(final File file) throws FileNotFoundException {
        final LibKernel libKernel = new LibKernel();
        final int fd = libKernel.open(file.getAbsolutePath(), OpenFlag.or(OpenFlag.O_RDONLY));
        if (fd == -1) {
            throw new FileNotFoundException();
        }
        try {
            final Method setMethod = FileDescriptor.class.getDeclaredMethod("set", Integer.TYPE);
            setMethod.setAccessible(true);
            setMethod.invoke((Object)this.getFd(), new Object[] { new Integer(fd) });
        }
        catch (final NoSuchMethodException | IllegalAccessException e) {
            throw new SdkRuntimeException((Throwable)e);
        }
        catch (final InvocationTargetException e2) {
            throw new SdkRuntimeException(e2.getTargetException());
        }
    }
}

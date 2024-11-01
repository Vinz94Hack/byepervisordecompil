package org.ps5jb.sdk.io;

import java.io.FileFilter;
import java.io.FilenameFilter;
import java.util.List;
import org.ps5jb.sdk.include.sys.dirent.DirEnt;
import java.util.ArrayList;
import org.ps5jb.sdk.include.sys.fcntl.OpenFlag;
import org.ps5jb.sdk.core.Pointer;
import java.io.IOException;
import org.ps5jb.sdk.include.sys.stat.FileStatusMode;
import org.ps5jb.sdk.include.sys.stat.StatType;
import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.loader.Status;
import java.util.Collection;
import java.util.HashSet;
import java.util.Arrays;
import org.ps5jb.sdk.include.sys.Stat;
import org.ps5jb.sdk.lib.LibKernel;
import java.lang.reflect.Field;
import org.ps5jb.sdk.core.SdkRuntimeException;
import java.util.Set;

public class File extends java.io.File
{
    private boolean reacheable;
    private long size;
    private Set modes;
    private long modificationTime;
    private int uid;
    private int gid;
    
    public File(final java.io.File parent, final String child) {
        super(parent, child);
        this.disableProxy();
        this.refresh();
    }
    
    public File(final String parent, final String child) {
        super(parent, child);
        this.disableProxy();
        this.refresh();
    }
    
    public File(final String pathname) {
        super(pathname);
        this.disableProxy();
        this.refresh();
    }
    
    private void disableProxy() {
        try {
            final Field proxyField = java.io.File.class.getDeclaredField("proxy");
            proxyField.setAccessible(true);
            proxyField.set((Object)this, (Object)null);
        }
        catch (final NoSuchFieldException ex) {}
        catch (final IllegalAccessException e) {
            throw new SdkRuntimeException((Throwable)e);
        }
    }
    
    public void refresh() {
        final LibKernel libKernel = new LibKernel();
        try {
            if (libKernel.sceKernelCheckReachability(this.getAbsolutePath()) == 0) {
                this.reacheable = true;
                final Stat stat = new Stat(libKernel);
                try {
                    final StatType statType = stat.getStatus(this.getAbsolutePath());
                    try {
                        this.size = statType.getSize();
                        this.modes = (Set)new HashSet((Collection)Arrays.asList((Object[])statType.getMode()));
                        this.modificationTime = statType.getMtim().getSec() * 1000L + statType.getMtim().getNsec() / 1000000L;
                        this.uid = statType.getUid();
                        this.gid = statType.getGid();
                    }
                    finally {
                        statType.free();
                    }
                }
                catch (final SdkException e) {
                    Status.printStackTrace("", (Throwable)e);
                    this.reacheable = false;
                }
            }
        }
        finally {
            libKernel.closeLibrary();
        }
    }
    
    public int getOwner() {
        return this.uid;
    }
    
    public int getGroup() {
        return this.gid;
    }
    
    public Set getModes() {
        return (Set)new HashSet((Collection)this.modes);
    }
    
    public long lastModified() {
        return this.modificationTime;
    }
    
    public boolean exists() {
        return this.reacheable;
    }
    
    public long length() {
        return this.size;
    }
    
    public boolean isDirectory() {
        if (this.modes != null) {
            return this.modes.contains((Object)FileStatusMode.S_IFDIR);
        }
        return super.isDirectory();
    }
    
    public boolean isFile() {
        if (this.modes != null) {
            return this.modes.contains((Object)FileStatusMode.S_IFREG);
        }
        return super.isFile();
    }
    
    public File getParentFile() {
        final String parent = this.getParent();
        return (parent == null) ? null : new File(parent);
    }
    
    public File getAbsoluteFile() {
        final String absolutePath = this.getAbsolutePath();
        return new File(absolutePath);
    }
    
    public File getCanonicalFile() throws IOException {
        final String canonicalPath = this.getCanonicalPath();
        return new File(canonicalPath);
    }
    
    public String[] list() {
        String[] result = null;
        final int BUF_SIZE = 16384;
        final Pointer db = Pointer.malloc(BUF_SIZE);
        try {
            final LibKernel libKernel = new LibKernel();
            try {
                final int fd = libKernel.open(this.getAbsolutePath(), OpenFlag.or(OpenFlag.O_RDONLY, OpenFlag.O_DIRECTORY));
                if (fd != -1) {
                    final List dirEnts = (List)new ArrayList();
                    try {
                        DirEnt dirEnt = null;
                        int remainingSize = libKernel.getdents(fd, db, BUF_SIZE);
                        while (remainingSize > 0 && remainingSize <= BUF_SIZE) {
                            if (dirEnt == null) {
                                dirEnt = new DirEnt(db);
                            }
                            if (!dirEnt.getName().equals((Object)".") && !dirEnt.getName().equals((Object)"..")) {
                                dirEnts.add((Object)dirEnt.getName());
                            }
                            final long oldAddr = dirEnt.getPointer().addr();
                            dirEnt = dirEnt.next(remainingSize);
                            if (dirEnt == null) {
                                remainingSize = libKernel.getdents(fd, db, BUF_SIZE);
                            }
                            else {
                                remainingSize -= (int)(dirEnt.getPointer().addr() - oldAddr);
                            }
                        }
                    }
                    finally {
                        libKernel.close(fd);
                    }
                    result = (String[])dirEnts.toArray((Object[])new String[0]);
                }
            }
            finally {
                libKernel.closeLibrary();
            }
        }
        finally {
            db.free();
        }
        return result;
    }
    
    public java.io.File[] listFiles() {
        final String[] fileList = this.list();
        if (fileList == null) {
            return null;
        }
        final File[] result = new File[fileList.length];
        for (int i = 0; i < fileList.length; ++i) {
            result[i] = new File(this, fileList[i]);
        }
        return result;
    }
    
    public java.io.File[] listFiles(final FilenameFilter filter) {
        final String[] fileList = this.list(filter);
        if (fileList == null) {
            return null;
        }
        final File[] result = new File[fileList.length];
        for (int i = 0; i < fileList.length; ++i) {
            result[i] = new File(this, fileList[i]);
        }
        return result;
    }
    
    public java.io.File[] listFiles(final FileFilter filter) {
        final String[] fileList = this.list();
        if (fileList == null) {
            return null;
        }
        final List result = (List)new ArrayList();
        for (int i = 0; i < fileList.length; ++i) {
            final File file = new File(this, fileList[i]);
            if (filter == null || filter.accept((java.io.File)file)) {
                result.add((Object)file);
            }
        }
        return (java.io.File[])result.toArray((Object[])new File[0]);
    }
}

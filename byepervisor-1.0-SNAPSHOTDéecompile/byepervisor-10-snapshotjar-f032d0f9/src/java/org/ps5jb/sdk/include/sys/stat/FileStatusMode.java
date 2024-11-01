package org.ps5jb.sdk.include.sys.stat;

import java.util.List;
import java.util.ArrayList;

public final class FileStatusMode implements Comparable
{
    public static final FileStatusMode S_IXOTH;
    public static final FileStatusMode S_IWOTH;
    public static final FileStatusMode S_IROTH;
    public static final FileStatusMode S_IXGRP;
    public static final FileStatusMode S_IWGRP;
    public static final FileStatusMode S_IRGRP;
    public static final FileStatusMode S_IXUSR;
    public static final FileStatusMode S_IWUSR;
    public static final FileStatusMode S_IRUSR;
    public static final FileStatusMode S_ISVTX;
    public static final FileStatusMode S_ISTXT;
    public static final FileStatusMode S_ISGID;
    public static final FileStatusMode S_ISUID;
    public static final FileStatusMode S_IFWHT;
    public static final FileStatusMode S_IFSOCK;
    public static final FileStatusMode S_IFLNK;
    public static final FileStatusMode S_IFREG;
    public static final FileStatusMode S_IFBLK;
    public static final FileStatusMode S_IFDIR;
    public static final FileStatusMode S_IFCHR;
    public static final FileStatusMode S_IFIFO;
    public static final FileStatusMode S_IRWXU;
    public static final FileStatusMode S_IRWXG;
    public static final FileStatusMode S_IRWXO;
    public static final FileStatusMode S_IFMT;
    private static final FileStatusMode[] values;
    private final short value;
    private final String name;
    
    private FileStatusMode(final short value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static FileStatusMode[] values() {
        return FileStatusMode.values;
    }
    
    public static FileStatusMode[] valueOf(final short value) {
        final List result = (List)new ArrayList();
        for (final FileStatusMode mode : FileStatusMode.values) {
            if ((value & mode.value) == mode.value) {
                result.add((Object)mode);
            }
        }
        return (FileStatusMode[])result.toArray((Object[])new FileStatusMode[result.size()]);
    }
    
    public short value() {
        return this.value;
    }
    
    public static short or(final FileStatusMode... modes) {
        short result = 0;
        for (final FileStatusMode mode : modes) {
            result |= mode.value;
        }
        return result;
    }
    
    public int compareTo(final Object o) {
        return this.value - ((FileStatusMode)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof FileStatusMode && this.value == ((FileStatusMode)o).value;
        return result;
    }
    
    @Override
    public int hashCode() {
        return this.value;
    }
    
    @Override
    public String toString() {
        return this.name;
    }
    
    static {
        S_IXOTH = new FileStatusMode((short)1, "S_IXOTH");
        S_IWOTH = new FileStatusMode((short)2, "S_IWOTH");
        S_IROTH = new FileStatusMode((short)4, "S_IROTH");
        S_IXGRP = new FileStatusMode((short)8, "S_IXGRP");
        S_IWGRP = new FileStatusMode((short)16, "S_IWGRP");
        S_IRGRP = new FileStatusMode((short)32, "S_IRGRP");
        S_IXUSR = new FileStatusMode((short)64, "S_IXUSR");
        S_IWUSR = new FileStatusMode((short)128, "S_IWUSR");
        S_IRUSR = new FileStatusMode((short)256, "S_IRUSR");
        S_ISVTX = new FileStatusMode((short)512, "S_ISVTX");
        S_ISTXT = new FileStatusMode((short)512, "S_ISTXT");
        S_ISGID = new FileStatusMode((short)1024, "S_ISGID");
        S_ISUID = new FileStatusMode((short)2048, "S_ISUID");
        S_IFWHT = new FileStatusMode((short)(-8192), "S_IFWHT");
        S_IFSOCK = new FileStatusMode((short)(-16384), "S_IFSOCK");
        S_IFLNK = new FileStatusMode((short)(-24576), "S_IFLNK");
        S_IFREG = new FileStatusMode((short)(-32768), "S_IFREG");
        S_IFBLK = new FileStatusMode((short)24576, "S_IFBLK");
        S_IFDIR = new FileStatusMode((short)16384, "S_IFDIR");
        S_IFCHR = new FileStatusMode((short)8192, "S_IFCHR");
        S_IFIFO = new FileStatusMode((short)4096, "S_IFIFO");
        S_IRWXU = new FileStatusMode((short)448, "S_IRWXU");
        S_IRWXG = new FileStatusMode((short)56, "S_IRWXG");
        S_IRWXO = new FileStatusMode((short)7, "S_IRWXO");
        S_IFMT = new FileStatusMode((short)(-4096), "S_IFMT");
        values = new FileStatusMode[] { FileStatusMode.S_IXOTH, FileStatusMode.S_IWOTH, FileStatusMode.S_IROTH, FileStatusMode.S_IXGRP, FileStatusMode.S_IWGRP, FileStatusMode.S_IRGRP, FileStatusMode.S_IXUSR, FileStatusMode.S_IWUSR, FileStatusMode.S_IRUSR, FileStatusMode.S_ISVTX, FileStatusMode.S_ISTXT, FileStatusMode.S_ISGID, FileStatusMode.S_ISUID, FileStatusMode.S_IFWHT, FileStatusMode.S_IFSOCK, FileStatusMode.S_IFLNK, FileStatusMode.S_IFREG, FileStatusMode.S_IFBLK, FileStatusMode.S_IFDIR, FileStatusMode.S_IFCHR, FileStatusMode.S_IFIFO };
    }
}

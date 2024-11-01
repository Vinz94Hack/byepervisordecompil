package org.ps5jb.sdk.include.sys.fcntl;

import org.ps5jb.sdk.res.ErrorMessages;

public final class OpenFlag implements Comparable
{
    public static final OpenFlag O_RDONLY;
    public static final OpenFlag O_WRONLY;
    public static final OpenFlag O_RDWR;
    public static final OpenFlag O_NONBLOCK;
    public static final OpenFlag O_APPEND;
    public static final OpenFlag O_SHLOCK;
    public static final OpenFlag O_EXLOCK;
    public static final OpenFlag O_FSYNC;
    public static final OpenFlag O_SYNC;
    public static final OpenFlag O_NOFOLLOW;
    public static final OpenFlag O_CREAT;
    public static final OpenFlag O_TRUNC;
    public static final OpenFlag O_EXCL;
    public static final OpenFlag O_DIRECT;
    public static final OpenFlag O_DIRECTORY;
    public static final OpenFlag O_EXEC;
    public static final OpenFlag O_CLOEXEC;
    private static final OpenFlag[] values;
    private int value;
    private String name;
    
    private OpenFlag(final int value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static OpenFlag[] values() {
        return OpenFlag.values;
    }
    
    public static OpenFlag valueOf(final int value) {
        for (final OpenFlag openFlag : OpenFlag.values) {
            if (value == openFlag.value()) {
                return openFlag;
            }
        }
        throw new IllegalArgumentException(ErrorMessages.getClassErrorMessage(OpenFlag.class, "invalidValue", Integer.toString(value)));
    }
    
    public int value() {
        return this.value;
    }
    
    public static int or(final OpenFlag... flags) {
        int result = 0;
        for (final OpenFlag flag : flags) {
            result |= flag.value;
        }
        return result;
    }
    
    public int compareTo(final Object o) {
        return this.value - ((OpenFlag)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof OpenFlag && this.value == ((OpenFlag)o).value;
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
        O_RDONLY = new OpenFlag(0, "O_RDONLY");
        O_WRONLY = new OpenFlag(1, "O_WRONLY");
        O_RDWR = new OpenFlag(2, "O_RDWR");
        O_NONBLOCK = new OpenFlag(4, "O_NONBLOCK");
        O_APPEND = new OpenFlag(8, "O_APPEND");
        O_SHLOCK = new OpenFlag(16, "O_SHLOCK");
        O_EXLOCK = new OpenFlag(32, "O_EXLOCK");
        O_FSYNC = new OpenFlag(128, "O_FSYNC");
        O_SYNC = new OpenFlag(OpenFlag.O_FSYNC.value(), "O_SYNC");
        O_NOFOLLOW = new OpenFlag(256, "O_NOFOLLOW");
        O_CREAT = new OpenFlag(512, "O_CREAT");
        O_TRUNC = new OpenFlag(1024, "O_TRUNC");
        O_EXCL = new OpenFlag(2048, "O_EXCL");
        O_DIRECT = new OpenFlag(65536, "O_DIRECT");
        O_DIRECTORY = new OpenFlag(131072, "O_DIRECTORY");
        O_EXEC = new OpenFlag(262144, "O_EXEC");
        O_CLOEXEC = new OpenFlag(1048576, "O_CLOEXEC");
        values = new OpenFlag[] { OpenFlag.O_RDONLY, OpenFlag.O_WRONLY, OpenFlag.O_RDWR, OpenFlag.O_NONBLOCK, OpenFlag.O_APPEND, OpenFlag.O_SHLOCK, OpenFlag.O_EXLOCK, OpenFlag.O_FSYNC, OpenFlag.O_SYNC, OpenFlag.O_NOFOLLOW, OpenFlag.O_CREAT, OpenFlag.O_TRUNC, OpenFlag.O_EXCL, OpenFlag.O_DIRECT, OpenFlag.O_DIRECTORY, OpenFlag.O_EXEC, OpenFlag.O_CLOEXEC };
    }
}

package org.ps5jb.sdk.include.sys.mman;

import org.ps5jb.sdk.res.ErrorMessages;

public final class MappingFlag implements Comparable
{
    public static final MappingFlag MAP_FILE;
    public static final MappingFlag MAP_SHARED;
    public static final MappingFlag MAP_PRIVATE;
    @Deprecated
    public static final MappingFlag MAP_COPY;
    public static final MappingFlag MAP_FIXED;
    public static final MappingFlag MAP_HASSEMAPHORE;
    public static final MappingFlag MAP_STACK;
    public static final MappingFlag MAP_NOSYNC;
    public static final MappingFlag MAP_ANON;
    public static final MappingFlag MAP_ANONYMOUS;
    public static final MappingFlag MAP_EXCL;
    public static final MappingFlag MAP_NOCORE;
    public static final MappingFlag MAP_PREFAULT_READ;
    public static final MappingFlag MAP_32BIT;
    private static final MappingFlag[] values;
    private int value;
    private String name;
    
    private MappingFlag(final int value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public static MappingFlag[] values() {
        return MappingFlag.values;
    }
    
    public static MappingFlag valueOf(final int value) {
        for (final MappingFlag mappingFlag : MappingFlag.values) {
            if (value == mappingFlag.value()) {
                return mappingFlag;
            }
        }
        throw new IllegalArgumentException(ErrorMessages.getClassErrorMessage(MappingFlag.class, "invalidValue", Integer.toString(value)));
    }
    
    public int value() {
        return this.value;
    }
    
    public static int or(final MappingFlag... flags) {
        int result = 0;
        for (final MappingFlag flag : flags) {
            result |= flag.value;
        }
        return result;
    }
    
    public int compareTo(final Object o) {
        return this.value - ((MappingFlag)o).value;
    }
    
    @Override
    public boolean equals(final Object o) {
        final boolean result = o instanceof MappingFlag && this.value == ((MappingFlag)o).value;
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
        MAP_FILE = new MappingFlag(0, "MAP_FILE");
        MAP_SHARED = new MappingFlag(1, "MAP_SHARED");
        MAP_PRIVATE = new MappingFlag(2, "MAP_PRIVATE");
        MAP_COPY = new MappingFlag(MappingFlag.MAP_PRIVATE.value(), "MAP_COPY");
        MAP_FIXED = new MappingFlag(16, "MAP_FIXED");
        MAP_HASSEMAPHORE = new MappingFlag(512, "MAP_HASSEMAPHORE");
        MAP_STACK = new MappingFlag(1024, "MAP_STACK");
        MAP_NOSYNC = new MappingFlag(2048, "MAP_NOSYNC");
        MAP_ANON = new MappingFlag(4096, "MAP_ANON");
        MAP_ANONYMOUS = new MappingFlag(MappingFlag.MAP_ANON.value(), "MAP_ANONYMOUS");
        MAP_EXCL = new MappingFlag(16384, "MAP_EXCL");
        MAP_NOCORE = new MappingFlag(131072, "MAP_NOCORE");
        MAP_PREFAULT_READ = new MappingFlag(262144, "MAP_PREFAULT_READ");
        MAP_32BIT = new MappingFlag(524288, "MAP_32BIT");
        values = new MappingFlag[] { MappingFlag.MAP_FILE, MappingFlag.MAP_SHARED, MappingFlag.MAP_PRIVATE, MappingFlag.MAP_COPY, MappingFlag.MAP_FIXED, MappingFlag.MAP_HASSEMAPHORE, MappingFlag.MAP_STACK, MappingFlag.MAP_NOSYNC, MappingFlag.MAP_ANON, MappingFlag.MAP_ANONYMOUS, MappingFlag.MAP_EXCL, MappingFlag.MAP_NOCORE, MappingFlag.MAP_PREFAULT_READ, MappingFlag.MAP_32BIT };
    }
}

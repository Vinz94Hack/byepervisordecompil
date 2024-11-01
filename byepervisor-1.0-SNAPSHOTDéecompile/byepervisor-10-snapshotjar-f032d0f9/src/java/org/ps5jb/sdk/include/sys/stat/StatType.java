package org.ps5jb.sdk.include.sys.stat;

import org.ps5jb.sdk.include.sys.timespec.TimespecType;
import org.ps5jb.sdk.core.Pointer;

public class StatType
{
    public static final long OFFSET_ST_DEV = 0L;
    public static final long OFFSET_ST_INO = 4L;
    public static final long OFFSET_ST_MODE = 8L;
    public static final long OFFSET_ST_NLINK = 10L;
    public static final long OFFSET_ST_UID = 12L;
    public static final long OFFSET_ST_GID = 16L;
    public static final long OFFSET_ST_RDEV = 20L;
    public static final long OFFSET_ST_ATIM = 24L;
    public static final long OFFSET_ST_MTIM = 40L;
    public static final long OFFSET_ST_CTIM = 56L;
    public static final long OFFSET_ST_SIZE = 72L;
    public static final long OFFSET_ST_BLOCKS = 80L;
    public static final long OFFSET_ST_BLKSIZE = 88L;
    public static final long OFFSET_ST_FLAGS = 92L;
    public static final long OFFSET_ST_GEN = 96L;
    public static final long OFFSET_ST_LSPARE = 100L;
    public static final long OFFSET_ST_BIRTHTIM = 104L;
    public static final long SIZE = 120L;
    private final Pointer ptr;
    private final boolean ownPtr;
    private TimespecType atim;
    private TimespecType mtim;
    private TimespecType ctim;
    private TimespecType birthtim;
    
    public StatType() {
        this.ptr = Pointer.calloc(120L);
        this.ownPtr = true;
        this.createTimespecs();
    }
    
    public StatType(final Pointer ptr) {
        this.ptr = ptr;
        this.ownPtr = false;
        this.createTimespecs();
    }
    
    private void createTimespecs() {
        this.atim = new TimespecType(this.ptr.inc(24L));
        this.mtim = new TimespecType(this.ptr.inc(40L));
        this.ctim = new TimespecType(this.ptr.inc(56L));
        this.birthtim = new TimespecType(this.ptr.inc(104L));
    }
    
    public int getDev() {
        return this.ptr.read4(0L);
    }
    
    public int getIno() {
        return this.ptr.read4(4L);
    }
    
    public FileStatusMode[] getMode() {
        return FileStatusMode.valueOf(this.ptr.read2(8L));
    }
    
    public short getNlink() {
        return this.ptr.read2(10L);
    }
    
    public int getUid() {
        return this.ptr.read4(12L);
    }
    
    public int getGid() {
        return this.ptr.read4(16L);
    }
    
    public int getRdev() {
        return this.ptr.read4(20L);
    }
    
    public TimespecType getAtim() {
        return this.atim;
    }
    
    public TimespecType getMtim() {
        return this.mtim;
    }
    
    public TimespecType getCtim() {
        return this.ctim;
    }
    
    public long getSize() {
        return this.ptr.read8(72L);
    }
    
    public long getBlocks() {
        return this.ptr.read8(80L);
    }
    
    public int getBlkSize() {
        return this.ptr.read4(88L);
    }
    
    public int getFlags() {
        return this.ptr.read4(92L);
    }
    
    public int getGen() {
        return this.ptr.read4(96L);
    }
    
    public int getLSpare() {
        return this.ptr.read4(100L);
    }
    
    public TimespecType getBirthtim() {
        return this.birthtim;
    }
    
    @Override
    protected void finalize() throws Throwable {
        try {
            this.free();
        }
        finally {
            super.finalize();
        }
    }
    
    public void free() {
        if (this.ownPtr && this.ptr != null && this.ptr.addr() != 0L) {
            this.ptr.free();
        }
    }
    
    public Pointer getPointer() {
        return this.ptr;
    }
}

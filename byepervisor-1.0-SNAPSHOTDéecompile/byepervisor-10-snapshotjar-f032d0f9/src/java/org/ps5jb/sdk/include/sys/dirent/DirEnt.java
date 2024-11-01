package org.ps5jb.sdk.include.sys.dirent;

import java.nio.charset.Charset;
import org.ps5jb.sdk.core.Pointer;

public class DirEnt
{
    private final Pointer ptr;
    private String name;
    
    public DirEnt(final Pointer pointer) {
        this.name = null;
        this.ptr = pointer;
    }
    
    public Pointer getPointer() {
        return this.ptr;
    }
    
    public DirEnt next(final int remainingSize) {
        final short reclen = this.ptr.read2(4L);
        DirEnt result;
        if (reclen >= 8 && reclen <= remainingSize) {
            result = new DirEnt(this.ptr.inc(reclen));
        }
        else {
            result = null;
        }
        return result;
    }
    
    public int getFileNo() {
        return this.ptr.read4();
    }
    
    public DirType getDirType() {
        return DirType.valueOf(this.ptr.read1(6L));
    }
    
    public String getName() {
        if (this.name == null) {
            this.name = this.ptr.readString(8L, new Integer((int)this.ptr.read1(7L)), Charset.defaultCharset().name());
        }
        return this.name;
    }
}

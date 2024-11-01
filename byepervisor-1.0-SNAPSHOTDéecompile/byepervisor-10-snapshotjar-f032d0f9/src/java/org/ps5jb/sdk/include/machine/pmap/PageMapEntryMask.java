package org.ps5jb.sdk.include.machine.pmap;

public class PageMapEntryMask
{
    public static final PageMapEntryMask X86_PG_V;
    public static final PageMapEntryMask X86_PG_RW;
    public static final PageMapEntryMask X86_PG_U;
    public static final PageMapEntryMask X86_PG_PS;
    public static final PageMapEntryMask SCE_PG_XO;
    public static final PageMapEntryMask EPT_PG_READ;
    public static final PageMapEntryMask EPT_PG_WRITE;
    public static final PageMapEntryMask EPT_PG_EXECUTE;
    public static final PageMapEntryMask EPT_PG_EMUL_V;
    public static final PageMapEntryMask EPT_PG_EMUL_RW;
    public static final PageMapEntryMask PG_PHYS_FRAME;
    public static final PageMapEntryMask PG_FRAME;
    public static final PageMapEntryMask PG_PS_FRAME;
    private long value;
    private String name;
    
    private PageMapEntryMask(final long value, final String name) {
        this.value = value;
        this.name = name;
    }
    
    public long value() {
        return this.value;
    }
    
    @Override
    public String toString() {
        return this.name;
    }
    
    static {
        X86_PG_V = new PageMapEntryMask(1L, "X86_PG_V");
        X86_PG_RW = new PageMapEntryMask(2L, "X86_PG_RW");
        X86_PG_U = new PageMapEntryMask(4L, "X86_PG_U");
        X86_PG_PS = new PageMapEntryMask(128L, "X86_PG_PS");
        SCE_PG_XO = new PageMapEntryMask(288230376151711744L, "SCE_PG_XO");
        EPT_PG_READ = new PageMapEntryMask(1L, "EPT_PG_READ");
        EPT_PG_WRITE = new PageMapEntryMask(2L, "EPT_PG_WRITE");
        EPT_PG_EXECUTE = new PageMapEntryMask(4L, "EPT_PG_EXECUTE");
        EPT_PG_EMUL_V = new PageMapEntryMask(4503599627370496L, "EPT_PG_EMUL_V");
        EPT_PG_EMUL_RW = new PageMapEntryMask(9007199254740992L, "EPT_PG_EMUL_RW");
        PG_PHYS_FRAME = new PageMapEntryMask(4503599627366400L, "PG_PHYS_FRAME");
        PG_FRAME = new PageMapEntryMask(4503599627354112L, "PG_FRAME");
        PG_PS_FRAME = new PageMapEntryMask(4503599625273344L, "PG_PS_FRAME");
    }
}

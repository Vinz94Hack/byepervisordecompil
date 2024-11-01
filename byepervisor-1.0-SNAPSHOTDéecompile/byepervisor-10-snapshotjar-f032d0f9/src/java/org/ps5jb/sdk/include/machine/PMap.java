package org.ps5jb.sdk.include.machine;

import org.ps5jb.sdk.include.sys.Param;
import org.ps5jb.sdk.core.SdkRuntimeException;
import org.ps5jb.sdk.res.ErrorMessages;
import org.ps5jb.sdk.include.machine.pmap.PageMapType;
import org.ps5jb.sdk.include.machine.pmap.PageMapEntryMask;
import java.util.Set;
import org.ps5jb.sdk.include.machine.pmap.PageMapFlag;
import java.util.Collection;
import java.util.HashSet;
import java.util.Arrays;
import org.ps5jb.sdk.include.machine.pmap.PageMap;
import org.ps5jb.sdk.core.kernel.KernelPointer;

public class PMap
{
    public static final long NDMPML4E = 1L;
    public static final long NKPML4E = 1L;
    public static long PML4PML4I;
    public static final long KPML4BASE = 511L;
    public static long DMPML4I;
    public static long DMPDPI;
    public static final long KPML4I = 511L;
    public static final long KPDPI = 510L;
    public static long addr_PDmap;
    
    public static void refresh(final KernelPointer dmpmk4iAddress, final KernelPointer dmpdpiAddress, final KernelPointer pml4pl4iAddress) {
        PMap.DMPML4I = dmpmk4iAddress.read4();
        PMap.DMPDPI = dmpdpiAddress.read4();
        PMap.PML4PML4I = pml4pl4iAddress.read4();
        PMap.addr_PDmap = KVADDR(PMap.PML4PML4I, PMap.PML4PML4I, 0L, 0L);
        VmParam.DMAP_MIN_ADDRESS = KVADDR(PMap.DMPML4I, PMap.DMPDPI, 0L, 0L);
        VmParam.DMAP_MAX_ADDRESS = KVADDR(PMap.DMPML4I + 1L, 0L, 0L, 0L);
    }
    
    public static long KVADDR(final long p14, final long p13, final long p12, final long p11) {
        return 0xFFFF800000000000L | p14 << 39 | p13 << 30 | p12 << 21 | p11 << 12;
    }
    
    private static boolean pmap_emulate_ad_bits(final PageMap pmap) {
        final Set flags = (Set)new HashSet((Collection)Arrays.asList((Object[])pmap.getFlags()));
        return flags.contains((Object)PageMapFlag.PMAP_EMULATE_AD_BITS);
    }
    
    private static PageMapEntryMask pmap_valid_bit(final PageMap pmap) {
        PageMapEntryMask mask;
        if (pmap.getType().equals(PageMapType.PT_X86) || pmap.getType().equals(PageMapType.PT_RVI)) {
            mask = PageMapEntryMask.X86_PG_V;
        }
        else {
            if (!pmap.getType().equals(PageMapType.PT_RVI)) {
                throw new SdkRuntimeException(ErrorMessages.getClassErrorMessage(PMap.class, "pmapBitValid", pmap.getType()));
            }
            if (pmap_emulate_ad_bits(pmap)) {
                mask = PageMapEntryMask.EPT_PG_EMUL_V;
            }
            else {
                mask = PageMapEntryMask.EPT_PG_READ;
            }
        }
        return mask;
    }
    
    private static long pmap_pte_index(final long va) {
        return va >> 12 & 0x1FFL;
    }
    
    private static long pmap_pde_index(final long va) {
        return va >> 21 & 0x1FFL;
    }
    
    private static long pmap_pdpe_index(final long va) {
        return va >> 30 & 0x1FFL;
    }
    
    private static long pmap_pml4e_index(final long va) {
        return va >> 39 & 0x1FFL;
    }
    
    private static KernelPointer pmap_pml4e(final PageMap pmap, final long va) {
        return new KernelPointer(pmap.getPml4() + pmap_pml4e_index(va) * 8L, new Long(8L));
    }
    
    private static KernelPointer pmap_pml4e_to_pdpe(final KernelPointer pml4e, final long va) {
        final long pml4eFrame = pml4e.read8() & PageMapEntryMask.PG_PHYS_FRAME.value();
        final long pdpe = VmParam.PHYS_TO_DMAP(pml4eFrame);
        return new KernelPointer(pdpe + pmap_pdpe_index(va) * 8L, new Long(8L));
    }
    
    private static KernelPointer pmap_pdpe(final PageMap pmap, final long va) {
        final PageMapEntryMask PG_V = pmap_valid_bit(pmap);
        final KernelPointer pml4e = pmap_pml4e(pmap, va);
        if ((pml4e.read8() & PG_V.value()) == 0x0L) {
            return KernelPointer.NULL;
        }
        return pmap_pml4e_to_pdpe(pml4e, va);
    }
    
    private static KernelPointer pmap_pdpe_to_pde(final KernelPointer pdpe, final long va) {
        final long pdpeFrame = pdpe.read8() & PageMapEntryMask.PG_PHYS_FRAME.value();
        final long pde = VmParam.PHYS_TO_DMAP(pdpeFrame);
        return new KernelPointer(pde + pmap_pde_index(va) * 8L, new Long(8L));
    }
    
    public static KernelPointer pmap_pde(final PageMap pmap, final long va) {
        final PageMapEntryMask PG_V = pmap_valid_bit(pmap);
        final KernelPointer pdpe = pmap_pdpe(pmap, va);
        if (KernelPointer.NULL.equals(pdpe) || (pdpe.read8() & PG_V.value()) == 0x0L) {
            return KernelPointer.NULL;
        }
        return pmap_pdpe_to_pde(pdpe, va);
    }
    
    private static KernelPointer pmap_pde_to_pte(final KernelPointer pde, final long va) {
        final long pdeFrame = pde.read8() & PageMapEntryMask.PG_PHYS_FRAME.value();
        final long pte = VmParam.PHYS_TO_DMAP(pdeFrame);
        return new KernelPointer(pte + pmap_pte_index(va) * 8L, new Long(8L));
    }
    
    public static KernelPointer pmap_pte(final PageMap pmap, final long va) {
        final PageMapEntryMask PG_V = pmap_valid_bit(pmap);
        final KernelPointer pde = pmap_pde(pmap, va);
        if (KernelPointer.NULL.equals(pde) || (pde.read8() & PG_V.value()) == 0x0L) {
            return KernelPointer.NULL;
        }
        return pmap_pde_to_pte(pde, va);
    }
    
    private KernelPointer vtopde(final long va) {
        final long mask = Long.MIN_VALUE;
        return new KernelPointer(PMap.addr_PDmap + (va + 21L & mask) * 8L, new Long(8L));
    }
    
    public long pmap_kextract(final long va) {
        long pa;
        if (va >= VmParam.DMAP_MIN_ADDRESS && va <= VmParam.DMAP_MAX_ADDRESS) {
            pa = VmParam.DMAP_TO_PHYS(va);
        }
        else {
            final KernelPointer pde = this.vtopde(va);
            if ((pde.addr() & PageMapEntryMask.X86_PG_PS.value()) != 0x0L) {
                pa = ((pde.addr() & PageMapEntryMask.PG_PS_FRAME.value()) | (va & 0x1FFFFFL));
            }
            else {
                pa = pmap_pde_to_pte(pde, va).read8();
                pa = ((pa & PageMapEntryMask.PG_PHYS_FRAME.value()) | (va & 0x3FFFL));
            }
        }
        return pa;
    }
    
    static {
        PMap.PML4PML4I = 256L;
        PMap.DMPML4I = Param.rounddown(510L, 1L);
        PMap.DMPDPI = 0L;
        PMap.addr_PDmap = KVADDR(PMap.PML4PML4I, PMap.PML4PML4I, 0L, 0L);
    }
}

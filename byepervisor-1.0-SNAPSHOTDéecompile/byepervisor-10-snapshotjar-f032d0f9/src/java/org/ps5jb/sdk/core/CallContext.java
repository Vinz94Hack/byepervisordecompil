package org.ps5jb.sdk.core;

import org.ps5jb.loader.Status;
import org.ps5jb.sdk.res.ErrorMessages;
import java.util.Arrays;

class CallContext
{
    private static Pointer rtld_JVM_NativePath;
    private static Pointer libc_setjmp;
    private static Pointer libkernel___Ux86_64_setcontext;
    static int libjava_handle;
    private Pointer callBuffer;
    private int[] dimensions;
    private boolean executing;
    
    private native long multiNewArray(final long p0, final int[] p1);
    
    private static void initSymbols() {
        final Library rtld = new Library(-2L);
        CallContext.rtld_JVM_NativePath = rtld.addrOf("JVM_NativePath");
        final Library libc = new Library(2L);
        CallContext.libc_setjmp = libc.addrOf("setjmp");
        final Library libkernel = new Library(8193L);
        CallContext.libkernel___Ux86_64_setcontext = libkernel.addrOf("__Ux86_64_setcontext");
    }
    
    private static Pointer findMultiNewArrayAddress() {
        Pointer result = null;
        SdkSymbolNotFoundException lastException = null;
        final int[] knownHandles = { 74, 75 };
        int handleLibJava = 0;
        final int[] array = knownHandles;
        final int length = array.length;
        int i = 0;
        while (i < length) {
            final int handle = array[i];
            final Library libjava = new Library(handle);
            try {
                result = libjava.addrOf("Java_java_lang_reflect_Array_multiNewArray");
                handleLibJava = handle;
            }
            catch (final SdkSymbolNotFoundException e) {
                lastException = e;
                ++i;
                continue;
            }
            break;
        }
        for (int handle2 = 48; handle2 < 128; ++handle2) {
            if (Arrays.binarySearch(knownHandles, handle2) < 0) {
                try {
                    final Library libjava2 = new Library(handle2);
                    result = libjava2.addrOf("Java_java_lang_reflect_Array_multiNewArray");
                    handleLibJava = handle2;
                    break;
                }
                catch (final SdkSymbolNotFoundException ex) {}
                catch (final SdkRuntimeException ex2) {}
            }
        }
        if (result == null) {
            throw lastException;
        }
        CallContext.libjava_handle = handleLibJava;
        return result;
    }
    
    private static void installMultiNewArrayHook() {
        boolean installed = false;
        final Pointer instance = Pointer.addrOf(new CallContext());
        final Pointer klass = Pointer.valueOf(instance.read8(8L));
        final Pointer methods = Pointer.valueOf(klass.read8(368L));
        final int numMethods = methods.read4();
        for (long i = 0L; i < numMethods; ++i) {
            final Pointer method = Pointer.valueOf(methods.read8(8L + i * 8L));
            final Pointer constMethod = Pointer.valueOf(method.read8(8L));
            final Pointer constants = Pointer.valueOf(constMethod.read8(8L));
            final short nameIndex = constMethod.read2(42L);
            final Pointer nameSymbol = Pointer.valueOf(constants.read8(64 + nameIndex * 8) & 0xFFFFFFFFFFFFFFFEL);
            final short nameLength = nameSymbol.read2();
            final String name = nameSymbol.inc(6L).readString(new Integer((int)nameLength));
            if (name.equals((Object)"multiNewArray")) {
                method.write8(80L, findMultiNewArrayAddress().addr());
                installed = true;
                break;
            }
        }
        if (!installed) {
            throw new SdkRuntimeException(ErrorMessages.getClassErrorMessage(CallContext.class, "installMultiNewArrayHook", new Object[0]));
        }
    }
    
    @Override
    protected void finalize() throws Throwable {
        try {
            this.close();
        }
        finally {
            super.finalize();
        }
    }
    
    void close() {
        if (this.callBuffer != null) {
            this.callBuffer.free();
            this.callBuffer = null;
        }
    }
    
    private void buildCallContext(final Pointer contextBuf, final Pointer jmpBuf, final long rip, final long rdi, final long rsi, final long rdx, final long rcx, final long r8, final long r9) {
        final long rbx = jmpBuf.read8(8L);
        final long rsp = jmpBuf.read8(16L);
        final long rbp = jmpBuf.read8(24L);
        final long r10 = jmpBuf.read8(32L);
        final long r11 = jmpBuf.read8(40L);
        final long r12 = jmpBuf.read8(48L);
        final long r13 = jmpBuf.read8(56L);
        contextBuf.write8(72L, rdi);
        contextBuf.write8(80L, rsi);
        contextBuf.write8(88L, rdx);
        contextBuf.write8(96L, rcx);
        contextBuf.write8(104L, r8);
        contextBuf.write8(112L, r9);
        contextBuf.write8(128L, rbx);
        contextBuf.write8(136L, rbp);
        contextBuf.write8(160L, r10);
        contextBuf.write8(168L, r11);
        contextBuf.write8(176L, r12);
        contextBuf.write8(184L, r13);
        contextBuf.write8(224L, rip);
        contextBuf.write8(248L, rsp);
        contextBuf.write8(272L, 0L);
        contextBuf.write8(280L, 0L);
    }
    
    long execute(final Pointer function, final long... args) {
        if (args.length > 6) {
            throw new IllegalArgumentException(ErrorMessages.getClassErrorMessage(CallContext.class, "maxCallArguments", new Integer(6), new Integer(args.length)));
        }
        if (this.callBuffer == null) {
            this.callBuffer = Pointer.malloc(2048L);
            this.dimensions = new int[] { 1 };
        }
        if (this.executing) {
            throw new SdkRuntimeException(ErrorMessages.getClassErrorMessage(CallContext.class, "nestedCall", new Object[0]));
        }
        this.executing = true;
        try {
            final Pointer fakeClass = this.callBuffer.inc(0L);
            final Pointer fakeKlass = fakeClass.inc(256L);
            final Pointer fakeKlassVTable = fakeKlass.inc(512L);
            final Pointer fakeClassOop = fakeKlassVTable.inc(1024L);
            fakeClassOop.write8(fakeClass.addr());
            fakeClass.write8(152L, fakeKlass.addr());
            fakeKlass.write4(196L, 0);
            fakeKlassVTable.write8(216L, CallContext.rtld_JVM_NativePath.addr());
            fakeKlass.write8(fakeKlassVTable.addr());
            fakeKlassVTable.write8(344L, CallContext.libc_setjmp.addr());
            this.multiNewArray(fakeClassOop.addr(), this.dimensions);
            this.buildCallContext(fakeKlass, fakeKlass, function.addr(), (args.length > 0) ? args[0] : 0L, (args.length > 1) ? args[1] : 0L, (args.length > 2) ? args[2] : 0L, (args.length > 3) ? args[3] : 0L, (args.length > 4) ? args[4] : 0L, (args.length > 5) ? args[5] : 0L);
            fakeKlass.write8(fakeKlassVTable.addr());
            fakeKlassVTable.write8(344L, CallContext.libkernel___Ux86_64_setcontext.addr());
            long ret = this.multiNewArray(fakeClassOop.addr(), this.dimensions);
            if (ret != 0L) {
                ret = Pointer.valueOf(ret).read8();
            }
            return ret;
        }
        catch (final SdkRuntimeException e) {
            throw e;
        }
        catch (final Throwable e2) {
            throw new SdkRuntimeException(e2.getMessage(), e2);
        }
        finally {
            this.executing = false;
        }
    }
    
    static {
        try {
            initSymbols();
            installMultiNewArrayHook();
        }
        catch (final Throwable e) {
            Status.printStackTrace(e.getMessage(), e);
            throw e;
        }
    }
}

package org.ps5jb.client.payloads;

import java.net.SocketException;
import org.dvb.event.UserEvent;
import org.ps5jb.sdk.include.machine.VmParam;
import org.ps5jb.sdk.include.machine.Param;
import java.io.OutputStream;
import org.ps5jb.sdk.core.SdkRuntimeException;
import org.ps5jb.sdk.core.AbstractPointer;
import org.ps5jb.sdk.include.sys.errno.MemoryFaultException;
import java.util.Arrays;
import java.net.Socket;
import org.dvb.event.UserEventRepository;
import org.dvb.event.OverallRepository;
import org.dvb.event.EventManager;
import org.ps5jb.sdk.core.SdkSoftwareVersionUnsupportedException;
import org.ps5jb.loader.Status;
import org.ps5jb.loader.KernelReadWrite;
import java.io.IOException;
import org.ps5jb.sdk.core.kernel.KernelOffsets;
import org.ps5jb.sdk.core.kernel.KernelPointer;
import org.ps5jb.sdk.lib.LibKernel;
import org.dvb.event.UserEventListener;
import org.ps5jb.loader.SocketListener;

public class KernelDump extends SocketListener implements UserEventListener
{
    public static final String SYSTEM_PROPERTY_KERNEL_DATA_POINTER = "org.ps5jb.client.KERNEL_DATA_POINTER";
    private LibKernel libKernel;
    private KernelPointer kbaseAddress;
    private KernelPointer kdataAddress;
    private KernelOffsets offsets;
    
    public KernelDump() throws IOException {
        super("Kernel Data Dumper", 5656);
        this.kbaseAddress = KernelPointer.NULL;
        this.kdataAddress = KernelPointer.NULL;
    }
    
    public void run() {
        if (KernelReadWrite.getAccessor() == null) {
            Status.println("Unable to dump without kernel read/write capabilities");
            return;
        }
        this.kbaseAddress = KernelPointer.valueOf(KernelReadWrite.getAccessor().getKernelBase());
        this.libKernel = new LibKernel();
        try {
            final int softwareVersion = this.libKernel.getSystemSoftwareVersion();
            try {
                this.offsets = new KernelOffsets(softwareVersion);
            }
            catch (final SdkSoftwareVersionUnsupportedException ex) {}
            this.kdataAddress = this.getKnownKDataAddress();
            if (KernelPointer.NULL.equals(this.kdataAddress)) {
                final KernelPointer kdataPtr = this.getKdataPtr();
                if (KernelPointer.NULL.equals(kdataPtr)) {
                    Status.println("No kernel addresses have been exposed. Aborting.");
                    return;
                }
                this.kdataAddress = this.scanKdataStartFromPtr(kdataPtr);
                if (!KernelPointer.NULL.equals(this.kdataAddress)) {
                    Status.println("Known pointer offset from data start: " + KernelPointer.valueOf(kdataPtr.addr() - this.kdataAddress.addr()));
                }
            }
            if (KernelPointer.NULL.equals(this.kdataAddress)) {
                Status.println("Kernel data address could not be determined. Aborting.");
                return;
            }
            Status.println("Kernel data address: " + this.kdataAddress);
            if (!KernelPointer.NULL.equals(this.kbaseAddress)) {
                Status.println("Kernel text address: " + this.kbaseAddress);
            }
            EventManager.getInstance().addUserEventListener((UserEventListener)this, (UserEventRepository)new OverallRepository());
            Status.println("Press Red square to abort");
            super.run();
        }
        finally {
            this.libKernel.closeLibrary();
            EventManager.getInstance().removeUserEventListener((UserEventListener)this);
        }
    }
    
    protected void acceptClient(final Socket clientSocket) throws Exception {
        final boolean isKtextReadable = this.offsets != null && this.kdataAddress.read4(this.offsets.OFFSET_KERNEL_DATA_BASE_DATA_CAVE) == 4919;
        final OutputStream out = clientSocket.getOutputStream();
        try {
            final byte[] buffer = new byte[4096];
            final long pageRatio = 16384L / buffer.length;
            final long printInterval = pageRatio * 256L;
            final String clientAddress = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
            KernelPointer kernelSpace;
            if (isKtextReadable) {
                kernelSpace = new KernelPointer(this.kbaseAddress.addr(), new Long(this.offsets.OFFSET_KERNEL_DATA + this.offsets.SIZE_KERNEL_DATA));
                Status.println("Dumping kernel text and data to " + clientAddress + ". Start: " + kernelSpace + "; size: 0x" + Long.toHexString((long)kernelSpace.size()));
            }
            else if (this.kdataAddress.size() != null) {
                kernelSpace = this.kdataAddress;
                Status.println("Dumping kernel data to " + clientAddress + ". Start: " + kernelSpace + "; size: 0x" + Long.toHexString((long)kernelSpace.size()));
            }
            else {
                kernelSpace = new KernelPointer(this.kdataAddress.addr(), new Long(28672L));
                Status.println("Dumping kernel data until crash to " + clientAddress + ". Start: " + kernelSpace);
            }
            long pageCount = 0L;
            while (pageCount * buffer.length < kernelSpace.size()) {
                Arrays.fill(buffer, (byte)0);
                final int readSize = (int)Math.min((long)buffer.length, kernelSpace.size() - pageCount * buffer.length);
                try {
                    kernelSpace.read(pageCount * buffer.length, buffer, 0, readSize);
                }
                catch (final SdkRuntimeException e) {
                    if (!(e.getCause() instanceof MemoryFaultException)) {
                        throw e;
                    }
                    if (pageCount == 0L) {
                        Status.println("Kernel is not readable. Aborting.");
                        break;
                    }
                    Status.println("Address " + AbstractPointer.toString(kernelSpace.addr() + pageCount * buffer.length) + " not accessible. Skipped.");
                }
                out.write(buffer, 0, readSize);
                ++pageCount;
                if (pageCount % printInterval == 0L) {
                    Status.println("Dumped 0x" + Long.toHexString(pageCount / pageRatio) + " pages");
                }
            }
        }
        finally {
            out.close();
        }
        this.terminate();
    }
    
    private KernelPointer getKnownKDataAddress() {
        KernelPointer kdataAddress = KernelPointer.NULL;
        if (!KernelPointer.NULL.equals(this.kbaseAddress) && this.offsets != null) {
            kdataAddress = new KernelPointer(this.kbaseAddress.addr() + this.offsets.OFFSET_KERNEL_DATA, new Long(this.offsets.SIZE_KERNEL_DATA));
        }
        return kdataAddress;
    }
    
    private KernelPointer getKdataPtr() {
        KernelPointer result = KernelPointer.NULL;
        final String resultStr = System.getProperty("org.ps5jb.client.KERNEL_DATA_POINTER");
        if (resultStr != null) {
            try {
                result = KernelPointer.valueOf(Long.parseLong(resultStr));
            }
            catch (final NumberFormatException ex) {}
        }
        return result;
    }
    
    private KernelPointer scanKdataStartFromPtr(final KernelPointer kdataPtr) {
        KernelPointer kdataPage = KernelPointer.valueOf(Param.ptoa(Param.atop(kdataPtr.addr())));
        Status.println("Kernel data address is not known for the current firmware. Scanning starting at " + kdataPage + ". This may crash if unsuccessful...");
        KernelPointer kdataAddress = KernelPointer.NULL;
        while (!KernelPointer.NULL.equals(kdataPage)) {
            final long val1 = kdataPage.read8();
            if (val1 == 4294967297L) {
                final long val2 = kdataPage.read8(8L);
                if (val2 == 0L) {
                    boolean check = true;
                    for (long i = 0L; i < 4L; ++i) {
                        final long valCheck = kdataPage.read8(16L + i * 8L);
                        if ((valCheck & VmParam.VM_MIN_KERNEL_ADDRESS) != VmParam.VM_MIN_KERNEL_ADDRESS && valCheck != 8L) {
                            check = false;
                            break;
                        }
                    }
                    if (check) {
                        kdataAddress = kdataPage;
                        break;
                    }
                }
            }
            kdataPage = kdataPage.inc(-16384L);
        }
        return kdataAddress;
    }
    
    public void userEventReceived(final UserEvent userEvent) {
        if (userEvent.getType() == 402) {
            switch (userEvent.getCode()) {
                case 403: {
                    try {
                        this.terminate();
                    }
                    catch (final IOException e) {
                        Status.printStackTrace("Failed to terminate the listener due to I/O exception", (Throwable)e);
                    }
                    break;
                }
            }
        }
    }
    
    protected void handleException(final Throwable ex) {
        if (ex instanceof SocketException) {
            Status.println(ex.getMessage());
        }
        else {
            super.handleException(ex);
        }
    }
}

package org.ps5jb.client.payloads;

import java.util.Iterator;
import java.util.ArrayList;
import org.ps5jb.sdk.include.sys.dirent.DirType;
import org.ps5jb.sdk.include.sys.dirent.DirEnt;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.io.File;
import org.ps5jb.sdk.include.sys.fcntl.OpenFlag;
import java.util.List;
import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.loader.Status;
import org.ps5jb.sdk.include.sys.FCntl;
import org.ps5jb.sdk.lib.LibKernel;

public class ListDirEnts implements Runnable
{
    public void run() {
        try {
            final LibKernel libKernel = new LibKernel();
            final FCntl fcntl = new FCntl(libKernel);
            try {
                this.printDirEnts("/", "", libKernel, fcntl);
            }
            finally {
                libKernel.closeLibrary();
            }
        }
        catch (final SdkException e) {
            Status.printStackTrace(e.getMessage(), (Throwable)e);
        }
    }
    
    public void getDirEnts(final List dirEnts, final String path, final LibKernel libKernel, final FCntl fcntl, final boolean recurse) throws SdkException {
        if (libKernel.sceKernelCheckReachability(path) == 0) {
            final int fd = fcntl.open(path, OpenFlag.O_RDONLY, OpenFlag.O_DIRECTORY);
            try {
                final File root = new File(path);
                final int BUF_SIZE = 16384;
                final Pointer db = Pointer.malloc(BUF_SIZE);
                try {
                    DirEnt dirEnt = null;
                    int remainingSize = libKernel.getdents(fd, db, BUF_SIZE);
                    while (remainingSize > 0 && remainingSize <= BUF_SIZE) {
                        if (dirEnt == null) {
                            dirEnt = new DirEnt(db);
                        }
                        if (!dirEnt.getName().equals((Object)".") && !dirEnt.getName().equals((Object)"..")) {
                            dirEnts.add((Object)new File(root, dirEnt.getName()));
                            if (recurse && DirType.DT_DIR.equals(dirEnt.getDirType())) {
                                final String childPath = path + ((path == "/") ? "" : "/") + dirEnt.getName();
                                try {
                                    this.getDirEnts(dirEnts, childPath, libKernel, fcntl, recurse);
                                }
                                catch (final SdkException e) {
                                    Status.println("[ERROR] " + e.getMessage());
                                }
                            }
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
                    db.free();
                }
            }
            finally {
                fcntl.close(fd);
            }
        }
    }
    
    private void printDirEnts(final String path, final String indent, final LibKernel libKernel, final FCntl fcntl) throws SdkException {
        final List dirEnts = (List)new ArrayList();
        try {
            this.getDirEnts(dirEnts, path, libKernel, fcntl, false);
        }
        catch (final SdkException e) {
            Status.println(indent + "  [ERROR] " + e.getMessage());
        }
        for (File file : dirEnts) {
            final String childPath = file.getAbsolutePath();
            Status.println(indent + file.getName() + (file.isDirectory() ? " [DIR]" : ""));
            if (file.isDirectory()) {
                this.printDirEnts(childPath, indent + "  ", libKernel, fcntl);
            }
        }
    }
}

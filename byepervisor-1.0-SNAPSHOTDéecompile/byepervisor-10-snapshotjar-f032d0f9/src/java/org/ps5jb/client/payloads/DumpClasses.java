package org.ps5jb.client.payloads;

import java.io.FileInputStream;
import java.net.Socket;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.jar.JarEntry;
import java.lang.module.ModuleReader;
import java.util.Iterator;
import java.io.InputStream;
import java.lang.module.ModuleReference;
import java.util.Map;
import java.lang.reflect.Method;
import java.lang.reflect.Field;
import java.security.PrivilegedActionException;
import jdk.internal.loader.URLClassPath;
import org.ps5jb.sdk.core.OpenModuleAction;
import java.util.Set;
import java.util.jar.JarFile;
import java.util.HashSet;
import java.io.OutputStream;
import java.util.zip.ZipOutputStream;
import java.io.FileOutputStream;
import org.ps5jb.loader.Status;
import java.io.File;
import java.io.IOException;
import org.ps5jb.loader.SocketListener;

public class DumpClasses extends SocketListener
{
    public DumpClasses() throws IOException {
        this(9125);
    }
    
    public DumpClasses(final int port) throws IOException {
        super("Classpath Dumper", port);
    }
    
    public File dumpClasspath() throws Exception {
        final File dumpZip = File.createTempFile("classpath", ".zip");
        dumpZip.deleteOnExit();
        Status.println("Dumping class path to: " + dumpZip.getAbsolutePath());
        final ZipOutputStream zip = new ZipOutputStream((OutputStream)new FileOutputStream(dumpZip));
        try {
            final Set dumpedEntries = (Set)new HashSet();
            for (ClassLoader cl = Thread.currentThread().getContextClassLoader(), prevCl = null; cl != null && !cl.equals(prevCl); cl = cl.getParent()) {
                prevCl = cl;
                Status.println("Dumping " + cl);
                this.dumpClassLoader(cl, zip, dumpedEntries);
            }
            final File pbpJar = new File("/app0/cdc/lib/pbp.jar");
            if (pbpJar.exists()) {
                Status.println("Dumping " + pbpJar);
                this.dumpJarFile(new JarFile(pbpJar), zip, (Set)new HashSet());
            }
            final File bdjstackJar = new File("/app0/cdc/bdjstack.jar");
            if (bdjstackJar.exists()) {
                Status.println("Dumping " + bdjstackJar);
                this.dumpJarFile(new JarFile(bdjstackJar), zip, (Set)new HashSet());
            }
            zip.finish();
        }
        finally {
            zip.close();
        }
        return dumpZip;
    }
    
    protected void dumpClassLoader(final ClassLoader cl, final ZipOutputStream zip, final Set dumpedEntries) throws Exception {
        Class prevClass = null;
        Class c = cl.getClass();
        String indent = "";
        while (c != null && !c.equals(prevClass)) {
            prevClass = c;
            if (!this.tryDumpBuiltinClassLoader(cl, c, zip, dumpedEntries)) {
                if (!this.tryDumpJdkUcpClassLoader(cl, c, zip, dumpedEntries)) {
                    Status.println(indent + "    Unrecognized class loader " + c.getName() + ". Skipping to parent");
                    c = c.getSuperclass();
                    indent += "  ";
                }
                else {
                    Status.println(indent + "  Dumped class loader " + c.getName());
                }
            }
            else {
                Status.println(indent + "  Dumped class loader " + c.getName());
            }
        }
    }
    
    protected boolean tryDumpJdkUcpClassLoader(final ClassLoader cl, final Class clClass, final ZipOutputStream zip, final Set dumpedEntries) throws Exception {
        try {
            OpenModuleAction.execute("jdk.internal.loader.URLClassPath");
            final Field ucpField = clClass.getDeclaredField("ucp");
            ucpField.setAccessible(true);
            final Object ucpObject = ucpField.get((Object)cl);
            if (ucpObject != null && ucpObject instanceof URLClassPath) {
                final URLClassPath ucp = (URLClassPath)ucpObject;
                final Method getLoaderMethod = ucp.getClass().getDeclaredMethod("getLoader", Integer.TYPE);
                getLoaderMethod.setAccessible(true);
                Object loader = null;
                for (int i = 0; (loader = getLoaderMethod.invoke((Object)ucp, new Object[] { new Integer(i) })) != null; ++i) {
                    final Field jarfileField = loader.getClass().getDeclaredField("jarfile");
                    jarfileField.setAccessible(true);
                    final JarFile jarFile = (JarFile)jarfileField.get(loader);
                    if (jarFile != null) {
                        Status.println("    Dumping " + jarFile.getName());
                        try {
                            this.dumpJarFile(jarFile, zip, dumpedEntries);
                        }
                        catch (final IOException e) {
                            Status.printStackTrace("Skipping due to error", (Throwable)e);
                        }
                    }
                    else {
                        Status.println("    Skipping loader " + loader + " since it does not have a JAR file");
                    }
                }
                return true;
            }
        }
        catch (final NoSuchFieldException | PrivilegedActionException ex) {}
        return false;
    }
    
    protected boolean tryDumpBuiltinClassLoader(final ClassLoader cl, final Class clClass, final ZipOutputStream zip, final Set dumpedEntries) throws Exception {
        try {
            OpenModuleAction.execute("java.lang.module.ModuleReference");
            OpenModuleAction.execute("jdk.internal.module.SystemModuleFinders");
            try {
                OpenModuleAction.execute("jdk.internal.util.Optional");
                OpenModuleAction.execute("jdk.internal.util.stream.Stream");
            }
            catch (final PrivilegedActionException e) {
                Status.println("Error while opening PS5-specific jdk.internal.util package. Assuming this package does not exist in the current execution environment. Error: " + e.getException().getClass() + "; Message: " + e.getException().getMessage());
            }
            final Field ptmField = clClass.getDeclaredField("packageToModule");
            ptmField.setAccessible(true);
            final Map ptm = (Map)ptmField.get((Object)cl);
            final Set processed = (Set)new HashSet();
            for (Object loadedModule : ptm.values()) {
                if (!processed.contains(loadedModule)) {
                    final Field mrefField = loadedModule.getClass().getDeclaredField("mref");
                    mrefField.setAccessible(true);
                    final ModuleReference mref = (ModuleReference)mrefField.get(loadedModule);
                    Status.println("    Dumping " + mref.descriptor().name());
                    final ModuleReader mr = mref.open();
                    try {
                        final Method listMethod = this.getMethod(mr.getClass(), "list", new Class[0]);
                        final Method openMethod = this.getMethod(mr.getClass(), "open", new Class[] { String.class });
                        final Object resourceStream = listMethod.invoke((Object)mr, new Object[0]);
                        final Method toArrayMethod = this.getMethod(resourceStream.getClass(), "toArray", new Class[0]);
                        final Object[] resources = (Object[])toArrayMethod.invoke(resourceStream, new Object[0]);
                        Status.println("      Processing " + resources.length + " resources");
                        final Object[] array = resources;
                        for (int length = array.length, i = 0; i < length; ++i) {
                            final Object res = array[i];
                            final String resName = mref.descriptor().name() + "/" + res;
                            if (!dumpedEntries.contains((Object)resName)) {
                                final Object isOptional = openMethod.invoke((Object)mr, new Object[] { res });
                                final Method Optional_isPresentMethod = this.getMethod(isOptional.getClass(), "isPresent", new Class[0]);
                                final Method Optional_getMethod = this.getMethod(isOptional.getClass(), "get", new Class[0]);
                                if (Optional_isPresentMethod.invoke(isOptional, new Object[0])) {
                                    final InputStream is = (InputStream)Optional_getMethod.invoke(isOptional, new Object[0]);
                                    try {
                                        this.createZipEntry(is, resName, zip);
                                        dumpedEntries.add((Object)resName);
                                    }
                                    finally {
                                        is.close();
                                    }
                                }
                                else {
                                    Status.println("    Failed to open classpath resource: " + res);
                                }
                            }
                        }
                    }
                    finally {
                        mr.close();
                    }
                    processed.add(loadedModule);
                }
            }
            return true;
        }
        catch (final NoSuchFieldException ex) {
            return false;
        }
    }
    
    protected Method getMethod(final Class cl, final String methodName, final Class[] parameterTypes) throws NoSuchMethodException {
        try {
            final Method result = cl.getMethod(methodName, (Class[])parameterTypes);
            result.setAccessible(true);
            return result;
        }
        catch (final NoSuchMethodException e) {
            this.printClassMethods(cl, "");
            throw e;
        }
    }
    
    protected void printClassMethods(final Class cl, final String indent) {
        final Method[] methods = cl.getDeclaredMethods();
        final String nextIndent = indent + "  ";
        if (methods.length > 0) {
            Status.println(indent + cl.getName());
            final Method[] array = methods;
            for (int length = array.length, i = 0; i < length; ++i) {
                final Method method = array[i];
                Status.println(nextIndent + method.toString());
            }
        }
        if (cl.getSuperclass() != null) {
            this.printClassMethods(cl.getSuperclass(), nextIndent);
        }
    }
    
    protected void dumpJarFile(final JarFile jarFile, final ZipOutputStream zip, final Set dumpedEntries) throws IOException {
        final Enumeration jarEntries = jarFile.entries();
        while (jarEntries.hasMoreElements()) {
            final JarEntry jarEntry = (JarEntry)jarEntries.nextElement();
            if (!jarEntry.isDirectory()) {
                final File urlPath = new File(jarFile.getName());
                final String resName = urlPath.getName() + "/" + jarEntry.getName();
                if (dumpedEntries.contains((Object)resName)) {
                    continue;
                }
                final InputStream is = jarFile.getInputStream((ZipEntry)jarEntry);
                try {
                    this.createZipEntry(is, resName, zip);
                    dumpedEntries.add((Object)resName);
                }
                finally {
                    is.close();
                }
            }
        }
    }
    
    protected void createZipEntry(final InputStream is, final String entryName, final ZipOutputStream zip) throws IOException {
        final ZipEntry zipEntry = new ZipEntry(entryName);
        zip.putNextEntry(zipEntry);
        try {
            this.writeResource(is, (OutputStream)zip);
        }
        finally {
            zip.closeEntry();
        }
    }
    
    protected void writeResource(final InputStream is, final OutputStream out) throws IOException {
        if (is != null) {
            try {
                final byte[] buf = new byte[8192];
                int r;
                while ((r = is.read(buf)) > 0) {
                    out.write(buf, 0, r);
                }
            }
            finally {
                is.close();
            }
        }
    }
    
    public void acceptClient(final Socket clientSocket) throws Exception {
        final File dumpZip = this.dumpClasspath();
        Status.println("Sending the dump to: " + clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort());
        try {
            final OutputStream out = clientSocket.getOutputStream();
            try {
                final InputStream is = (InputStream)new FileInputStream(dumpZip);
                try {
                    this.writeResource(is, out);
                }
                finally {
                    is.close();
                }
            }
            finally {
                out.close();
            }
            Status.println("Classpath dump sent successfully");
            this.terminate();
        }
        finally {
            if (!dumpZip.delete()) {
                Status.println("Failed to delete the temporary classpath dump");
            }
        }
    }
    
    public void handleException(final Throwable ex) {
        super.handleException(ex);
        try {
            this.terminate();
        }
        catch (final IOException ex2) {}
    }
}

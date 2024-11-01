package org.ps5jb.client;

import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Field;
import java.nio.file.Path;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.URLConnection;
import java.util.Enumeration;
import org.ps5jb.client.payloads.umtx.common.DebugStatus;
import org.ps5jb.loader.Config;
import org.ps5jb.loader.KernelReadWrite;
import java.util.jar.Manifest;
import java.io.IOException;
import org.ps5jb.loader.Status;
import java.net.URL;

public class JarMain
{
    private static final String MANIFEST_PAYLOAD_KEY = "PS5JB-Client-Payload";
    private static final String MANIFEST_LOGGER_HOST = "PS5JB-Client-Logger-Host";
    private static final String MANIFEST_LOGGER_PORT = "PS5JB-Client-Logger-Port";
    
    public static void main(final String[] args) throws Exception {
        final JarMain main = new JarMain();
        if (args == null || args.length == 0) {
            main.execute();
        }
        else if (args.length > 0 && args[0].equals((Object)"--help")) {
            System.out.println("Usage: java -jar xploit.jar <address> [<port>]");
        }
        else {
            main.sendJar(args);
        }
    }
    
    protected void execute() throws Exception {
        boolean foundManifest = false;
        boolean foundPayload = false;
        final Enumeration manifests = this.getClass().getClassLoader().getResources("META-INF/MANIFEST.MF");
        while (manifests.hasMoreElements() && !foundManifest) {
            final URL manifestUrl = (URL)manifests.nextElement();
            Status.println("Searching manifest for payload: " + manifestUrl);
            final URLConnection con = manifestUrl.openConnection();
            InputStream manifestStream;
            try {
                manifestStream = con.getInputStream();
            }
            catch (final IOException e) {
                Status.printStackTrace("Unable to open the manifest. Skipping.", (Throwable)e);
                continue;
            }
            try {
                final Manifest mf = new Manifest(manifestStream);
                String payloadName = mf.getMainAttributes().getValue("PS5JB-Client-Payload");
                if (payloadName == null) {
                    continue;
                }
                foundManifest = true;
                if (payloadName.length() <= 0) {
                    continue;
                }
                foundPayload = true;
                if (payloadName.indexOf(".") == -1) {
                    payloadName = this.getClass().getPackage().getName() + ".payloads." + payloadName;
                }
                boolean restoreLogger = false;
                try {
                    final Class payloadClass = Class.forName(payloadName);
                    Status.println("Executing payload: " + payloadName);
                    if (!KernelReadWrite.restoreAccessor(this.getClass().getClassLoader())) {
                        Status.println("Kernel R/W not available");
                    }
                    else {
                        Status.println("Kernel R/W restored");
                    }
                    try {
                        String overrideLoggerHost = mf.getMainAttributes().getValue("PS5JB-Client-Logger-Host");
                        if (overrideLoggerHost.equals((Object)"")) {
                            overrideLoggerHost = null;
                        }
                        if (overrideLoggerHost != null) {
                            final String overrideLoggerPortStr = mf.getMainAttributes().getValue("PS5JB-Client-Logger-Port");
                            if (overrideLoggerPortStr != null && !"".equals((Object)overrideLoggerPortStr)) {
                                final int overrideLoggerPort = Integer.parseInt(overrideLoggerPortStr);
                                Status.resetLogger(overrideLoggerHost, overrideLoggerPort, Config.getLoggerTimeout());
                                restoreLogger = true;
                                DebugStatus.info("Remote logging server set to " + overrideLoggerHost + ":" + overrideLoggerPort);
                            }
                        }
                    }
                    catch (final NumberFormatException e2) {
                        Status.println("Logger port configuration is invalid:  Skipping");
                    }
                    final Runnable payload = payloadClass.newInstance();
                    payload.run();
                }
                catch (final ClassNotFoundException e3) {
                    Status.println("Unable to determine the payload to execute because the value of the attribute 'PS5JB-Client-Payload' is not recognized: " + payloadName);
                }
                catch (final ClassCastException e4) {
                    Status.printStackTrace("Unable to execute the payload. Make sure it implements the " + Runnable.class.getName() + " interface", (Throwable)e4);
                }
                finally {
                    if (KernelReadWrite.getAccessor() != null && KernelReadWrite.saveAccessor()) {
                        Status.println("Kernel R/W is active and is saved for future payloads");
                    }
                    if (restoreLogger) {
                        DebugStatus.info("Restoring default remote logging configuration");
                        Status.resetLogger(Config.getLoggerHost(), Config.getLoggerPort(), Config.getLoggerTimeout());
                    }
                }
            }
            finally {
                manifestStream.close();
            }
        }
        if (!foundManifest) {
            Status.println("Unable to determine payload to execute because the JAR manifest could not be opened.");
        }
        else if (!foundPayload) {
            Status.println("Unable to determine the payload to execute because the value of the attribute 'PS5JB-Client-Payload' is empty");
        }
    }
    
    protected void sendJar(final String[] args) throws Exception {
        final String host = args[0];
        final String port = (args.length > 1) ? args[1] : "9025";
        final Path jarPath = JarUtils.discoverJar(null);
        if (jarPath == null) {
            throw new FileNotFoundException("Jar file path could not be determined from the classloader");
        }
        JarUtils.sendJar(host, port, jarPath);
    }
    
    private static void disableIllegalAccessWarnings() {
        try {
            final Class unsafeClass = Class.forName("sun.misc.Unsafe");
            final Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            final Object unsafe = unsafeField.get((Object)null);
            final Method putObjectVolatileMethod = unsafeClass.getDeclaredMethod("putObjectVolatile", Object.class, Long.TYPE, Object.class);
            final Method staticFieldOffsetMethod = unsafeClass.getDeclaredMethod("staticFieldOffset", Field.class);
            final Class loggerClass = Class.forName("jdk.internal.module.IllegalAccessLogger");
            final Field loggerField = loggerClass.getDeclaredField("logger");
            final Long offset = (Long)staticFieldOffsetMethod.invoke(unsafe, new Object[] { loggerField });
            putObjectVolatileMethod.invoke(unsafe, new Object[] { loggerClass, offset, null });
        }
        catch (final ClassNotFoundException | IllegalAccessException | NoSuchFieldException | NoSuchMethodException | InvocationTargetException ex) {}
    }
    
    static {
        disableIllegalAccessWarnings();
    }
}

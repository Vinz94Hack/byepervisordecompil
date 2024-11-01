package org.ps5jb.client;

import java.security.PrivilegedActionException;
import java.util.jar.JarEntry;
import java.net.URL;
import java.lang.reflect.Field;
import java.util.jar.JarFile;
import java.net.URISyntaxException;
import java.net.URI;
import jdk.internal.loader.URLClassPath;
import org.ps5jb.sdk.core.OpenModuleAction;
import java.io.IOException;
import java.io.OutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.net.Socket;
import java.net.InetAddress;
import java.nio.file.Path;

public class JarUtils
{
    public static void sendJar(final String hostArg, final String portArg, final Path jarPath) throws IOException {
        final InetAddress addr = InetAddress.getByName(hostArg);
        final int port = Integer.parseInt(portArg);
        final Socket socket = new Socket(addr, port);
        socket.setSoTimeout(5000);
        final InputStream jarStream = Files.newInputStream(jarPath, new OpenOption[0]);
        try {
            final OutputStream out = socket.getOutputStream();
            try {
                final byte[] buf = new byte[8192];
                int readCount;
                while ((readCount = jarStream.read(buf)) != -1) {
                    out.write(buf, 0, readCount);
                }
                System.out.println("JAR successfully sent");
            }
            finally {
                out.close();
            }
        }
        finally {
            jarStream.close();
        }
    }
    
    public static Path discoverJar(ClassLoader classLoader) throws NoSuchFieldException, IllegalAccessException, IOException, PrivilegedActionException {
        Path jarPath = null;
        OpenModuleAction.execute("jdk.internal.loader.URLClassPath");
        if (classLoader == null) {
            classLoader = JarUtils.class.getClassLoader();
        }
        final Field field = classLoader.getClass().getDeclaredField("ucp");
        field.setAccessible(true);
        final URLClassPath ucp = (URLClassPath)field.get((Object)classLoader);
        final URL[] urLs = ucp.getURLs();
        for (int length = urLs.length, i = 0; i < length; ++i) {
            final URL url = urLs[i];
            if (url.getProtocol().equals((Object)"file")) {
                Path path;
                try {
                    path = Path.of(new URI(url.toString()));
                }
                catch (final URISyntaxException e) {
                    throw new RuntimeException(e.getClass().getName() + ": " + e.getMessage());
                }
                final JarFile jar = new JarFile(path.toFile());
                final String classEntryName = JarMain.class.getName().replace('.', '/') + ".class";
                final JarEntry jarEntry = jar.getJarEntry(classEntryName);
                if (jarEntry != null) {
                    jarPath = path;
                    break;
                }
            }
        }
        return jarPath;
    }
}

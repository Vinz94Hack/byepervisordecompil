package org.ps5jb.client.payloads.ftp;

import java.net.SocketException;
import org.dvb.event.UserEvent;
import java.util.Iterator;
import java.lang.reflect.Field;
import java.security.PrivilegedActionException;
import org.ps5jb.sdk.core.OpenModuleAction;
import java.net.Socket;
import java.io.IOException;
import org.ps5jb.loader.Status;
import org.dvb.event.UserEventRepository;
import org.dvb.event.OverallRepository;
import org.dvb.event.EventManager;
import java.util.ArrayList;
import java.util.List;
import org.dvb.event.UserEventListener;
import org.ps5jb.loader.SocketListener;

public class FtpServer extends SocketListener implements UserEventListener
{
    private List workers;
    private boolean isKeyConfirming;
    
    public FtpServer() throws IOException {
        super("FTP Server", 9225);
        this.workers = (List)new ArrayList();
        final EventManager eventManager = EventManager.getInstance();
        if (eventManager != null) {
            eventManager.addUserEventListener((UserEventListener)this, (UserEventRepository)new OverallRepository());
        }
        Status.println("Welcome to " + this.listenerName + ". You can login anonymously using the username 'ps5jb' and " + ("".equals((Object)"") ? "no password." : "password ''.") + " Exit the " + this.listenerName + " by issuing a custom 'TERM' command or by pressing the RED button.");
    }
    
    public void acceptClient(final Socket clientSocket) throws Exception {
        clientSocket.setSoTimeout(0);
        final int dataPort = this.serverSocket.getLocalPort() + this.workers.size() + 1;
        final FtpWorker w = new FtpWorker(this, clientSocket, dataPort, "FTPWorker " + (this.workers.size() + 1));
        Status.println("New connection received from " + clientSocket.getInetAddress().getHostAddress());
        this.workers.add((Object)w);
        w.start();
    }
    
    protected void disableIOProxyFactory() {
        final String BDJ_FACTORY_CLASS_NAME = "com.oracle.orbis.io.BDJFactory";
        try {
            OpenModuleAction.execute("com.oracle.orbis.io.BDJFactory");
        }
        catch (final PrivilegedActionException e) {
            Status.println("Error while opening PS5-specific com.oracle.orbis.io package. Assuming this package does not exist in the current execution environment. Error: " + e.getException().getClass() + "; Message: " + e.getException().getMessage());
            return;
        }
        try {
            final Class bdjFactoryClass = Class.forName("com.oracle.orbis.io.BDJFactory");
            final Field bdjFactoryInstance = bdjFactoryClass.getDeclaredField("instance");
            bdjFactoryInstance.setAccessible(true);
            bdjFactoryInstance.set((Object)null, (Object)null);
        }
        catch (final Throwable e2) {
            this.handleException(e2);
        }
    }
    
    public void run() {
        this.disableIOProxyFactory();
        super.run();
        final EventManager eventManager = EventManager.getInstance();
        if (eventManager != null) {
            eventManager.removeUserEventListener((UserEventListener)this);
        }
        for (final FtpWorker worker : this.workers) {
            worker.terminate();
        }
        for (final FtpWorker worker : this.workers) {
            try {
                worker.join(5000L);
            }
            catch (final InterruptedException e) {
                Status.printStackTrace(e.getMessage(), (Throwable)e);
            }
        }
    }
    
    protected void disposeClient(final Socket clientSocket) {
    }
    
    public void userEventReceived(final UserEvent userEvent) {
        if (userEvent.getFamily() == 1 && userEvent.getType() == 402) {
            switch (userEvent.getCode()) {
                case 403: {
                    if (!this.isKeyConfirming) {
                        Status.println("Are you sure you want to terminate the " + this.listenerName + "? Press the same key again to confirm or any other key to cancel.");
                        this.isKeyConfirming = true;
                        break;
                    }
                    try {
                        this.terminate();
                    }
                    catch (final IOException e) {
                        Status.printStackTrace(e.getMessage(), (Throwable)e);
                        this.isKeyConfirming = false;
                    }
                    break;
                }
                default: {
                    if (this.isKeyConfirming) {
                        Status.println("Termination request cancelled.");
                        this.isKeyConfirming = false;
                        break;
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

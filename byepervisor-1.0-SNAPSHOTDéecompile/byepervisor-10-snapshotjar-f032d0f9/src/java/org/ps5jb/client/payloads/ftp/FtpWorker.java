package org.ps5jb.client.payloads.ftp;

import java.util.Locale;
import java.io.OutputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.BufferedOutputStream;
import java.io.InputStream;
import java.io.BufferedInputStream;
import java.util.StringTokenizer;
import java.util.Set;
import org.ps5jb.sdk.include.sys.stat.FileStatusMode;
import java.util.Date;
import java.util.List;
import java.util.ArrayList;
import java.net.SocketException;
import java.io.Reader;
import java.io.InputStreamReader;
import org.ps5jb.loader.Status;
import java.io.FileNotFoundException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.File;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import org.ps5jb.sdk.core.Library;
import org.ps5jb.sdk.include.sys.FCntl;
import org.ps5jb.sdk.lib.LibKernel;
import java.net.ServerSocket;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;

public class FtpWorker extends Thread
{
    static final String DEFAULT_USERNAME = "ps5jb";
    static final String DEFAULT_PASSWORD = "";
    private boolean debugMode;
    private static SimpleDateFormat fileMonthFormat;
    private static SimpleDateFormat fileDayHourFormat;
    private static SimpleDateFormat fileDayYearFormat;
    private static MessageFormat lsDirFormat;
    private String root;
    private String currDirectory;
    private String fileSeparator;
    private Socket controlSocket;
    private PrintWriter controlOutWriter;
    private BufferedReader controlIn;
    private ServerSocket dataSocket;
    private Socket dataConnection;
    private PrintWriter dataOutWriter;
    private int dataPort;
    private String transferMode;
    private String currentUserStatus;
    private String validUser;
    private String validPassword;
    private FtpServer server;
    private LibKernel libKernel;
    private FCntl fcntl;
    private boolean useNativeCalls;
    private boolean quitCommandLoop;
    
    public FtpWorker(final FtpServer server, final Socket client, final int dataPort, final String name) throws IOException {
        super(name);
        this.debugMode = true;
        this.fileSeparator = "/";
        this.transferMode = "ASCII";
        this.currentUserStatus = "NOTLOGGEDIN";
        this.validUser = "ps5jb";
        this.validPassword = "";
        this.quitCommandLoop = false;
        this.server = server;
        this.controlSocket = client;
        this.dataPort = dataPort;
        try {
            final Method getLibJavaHandleMethod = Library.class.getDeclaredMethod("getLibJavaHandle", (Class<?>[])new Class[0]);
            getLibJavaHandleMethod.setAccessible(true);
            final int libJavaHandle = (int)getLibJavaHandleMethod.invoke((Object)null, new Object[0]);
            this.libKernel = new LibKernel();
            this.fcntl = new FCntl(this.libKernel);
            this.useNativeCalls = true;
            this.debugOutput("Using native calls from libjava @ 0x" + Integer.toHexString(libJavaHandle));
        }
        catch (final NoSuchMethodException | IllegalAccessException | InvocationTargetException | NoClassDefFoundError e) {
            this.useNativeCalls = false;
            this.debugOutput("Using Java file I/O");
        }
        File rootFile;
        for (rootFile = this.createFile(System.getProperty("user.dir")), rootFile = rootFile.getCanonicalFile(); rootFile.getParentFile() != null; rootFile = rootFile.getParentFile()) {}
        this.root = rootFile.getAbsolutePath();
        final File curDir = this.createFile("/app0");
        if (!this.isFileExists(curDir)) {
            this.currDirectory = this.root;
        }
        else {
            this.currDirectory = curDir.getAbsolutePath();
        }
    }
    
    protected File createFile(final String path) {
        File result;
        if (this.useNativeCalls) {
            result = new org.ps5jb.sdk.io.File(path);
        }
        else {
            result = new File(path);
        }
        return result;
    }
    
    protected File createFile(final File parent, final String path) {
        File result;
        if (this.useNativeCalls) {
            result = new org.ps5jb.sdk.io.File(parent, path);
        }
        else {
            result = new File(parent, path);
        }
        return result;
    }
    
    protected FileInputStream createFileInputStream(final File file) throws FileNotFoundException {
        FileInputStream result;
        if (this.useNativeCalls) {
            result = new org.ps5jb.sdk.io.FileInputStream(file);
        }
        else {
            result = new FileInputStream(file);
        }
        return result;
    }
    
    public void terminate() {
        this.quitCommandLoop = true;
        try {
            this.controlSocket.close();
        }
        catch (final IOException e) {
            Status.println("Warning, the socket could not be closed. This can usually be safely ignored. Cause: " + e.getMessage());
        }
    }
    
    public void run() {
        this.debugOutput("Current working directory " + this.currDirectory);
        try {
            this.controlIn = new BufferedReader((Reader)new InputStreamReader(this.controlSocket.getInputStream()));
            try {
                this.controlOutWriter = new PrintWriter(this.controlSocket.getOutputStream(), true);
                try {
                    this.sendMsgToClient("220 Welcome to the PS5JB FTP-Server");
                    while (!this.quitCommandLoop) {
                        try {
                            final String command = this.controlIn.readLine();
                            if (command != null) {
                                this.executeCommand(command);
                            }
                            else {
                                this.quitCommandLoop = true;
                            }
                        }
                        catch (final SocketException e) {
                            Status.println(e.getMessage());
                            this.quitCommandLoop = true;
                        }
                    }
                }
                finally {
                    this.controlOutWriter.close();
                }
            }
            finally {
                this.controlIn.close();
            }
        }
        catch (final Throwable e2) {
            Status.printStackTrace(e2.getMessage(), e2);
        }
        finally {
            try {
                this.controlSocket.close();
            }
            catch (final IOException e3) {
                Status.printStackTrace("Could not close the socket", (Throwable)e3);
            }
            this.closeDataConnection();
            if (this.libKernel != null) {
                this.libKernel.closeLibrary();
            }
            this.debugOutput("Worker stopped");
        }
    }
    
    private File toAbsoluteFile(final String path) {
        File pathFile = this.createFile((path == null) ? this.currDirectory : path);
        if (!pathFile.isAbsolute() && path != null) {
            pathFile = this.createFile(this.createFile(this.currDirectory), path);
        }
        return pathFile.getAbsoluteFile();
    }
    
    private boolean isFileValid(File file, final boolean checkExists) {
        boolean valid;
        if (checkExists) {
            try {
                file = file.getCanonicalFile();
                valid = (this.isFileExists(file) && file.getAbsolutePath().startsWith(this.root));
            }
            catch (final IOException e) {
                valid = false;
            }
        }
        else {
            valid = file.getAbsolutePath().startsWith(this.root);
        }
        return valid;
    }
    
    private boolean isFileExists(final File file) {
        return file.getParentFile() == null || file.exists();
    }
    
    private boolean isDirectory(final File file) {
        return file.getParentFile() == null || file.isDirectory();
    }
    
    private void executeCommand(final String c) throws IOException {
        final int index = c.indexOf(32);
        final String command = (index == -1) ? c.toUpperCase() : c.substring(0, index).toUpperCase();
        final String args = (index == -1) ? null : c.substring(index + 1);
        this.debugOutput("Command: " + command + " Args: " + args);
        final String s = command;
        int n = -1;
        switch (s.hashCode()) {
            case 2614219: {
                if (s.equals((Object)"USER")) {
                    n = 0;
                    break;
                }
                break;
            }
            case 2448401: {
                if (s.equals((Object)"PASS")) {
                    n = 1;
                    break;
                }
                break;
            }
            case 67152: {
                if (s.equals((Object)"CWD")) {
                    n = 2;
                    break;
                }
                break;
            }
            case 2336926: {
                if (s.equals((Object)"LIST")) {
                    n = 3;
                    break;
                }
                break;
            }
            case 2399391: {
                if (s.equals((Object)"NLST")) {
                    n = 4;
                    break;
                }
                break;
            }
            case 79645: {
                if (s.equals((Object)"PWD")) {
                    n = 5;
                    break;
                }
                break;
            }
            case 2701253: {
                if (s.equals((Object)"XPWD")) {
                    n = 6;
                    break;
                }
                break;
            }
            case 2497103: {
                if (s.equals((Object)"QUIT")) {
                    n = 7;
                    break;
                }
                break;
            }
            case 2448404: {
                if (s.equals((Object)"PASV")) {
                    n = 8;
                    break;
                }
                break;
            }
            case 2135118: {
                if (s.equals((Object)"EPSV")) {
                    n = 9;
                    break;
                }
                break;
            }
            case 2560839: {
                if (s.equals((Object)"SYST")) {
                    n = 10;
                    break;
                }
                break;
            }
            case 2153778: {
                if (s.equals((Object)"FEAT")) {
                    n = 11;
                    break;
                }
                break;
            }
            case 2461825: {
                if (s.equals((Object)"PORT")) {
                    n = 12;
                    break;
                }
                break;
            }
            case 2135085: {
                if (s.equals((Object)"EPRT")) {
                    n = 13;
                    break;
                }
                break;
            }
            case 2511857: {
                if (s.equals((Object)"RETR")) {
                    n = 14;
                    break;
                }
                break;
            }
            case 76390: {
                if (s.equals((Object)"MKD")) {
                    n = 15;
                    break;
                }
                break;
            }
            case 2697998: {
                if (s.equals((Object)"XMKD")) {
                    n = 16;
                    break;
                }
                break;
            }
            case 81257: {
                if (s.equals((Object)"RMD")) {
                    n = 17;
                    break;
                }
                break;
            }
            case 2702865: {
                if (s.equals((Object)"XRMD")) {
                    n = 18;
                    break;
                }
                break;
            }
            case 2590522: {
                if (s.equals((Object)"TYPE")) {
                    n = 19;
                    break;
                }
                break;
            }
            case 2555908: {
                if (s.equals((Object)"STOR")) {
                    n = 20;
                    break;
                }
                break;
            }
            case 2571372: {
                if (s.equals((Object)"TERM")) {
                    n = 21;
                    break;
                }
                break;
            }
        }
        switch (n) {
            case 0: {
                this.handleUser(args);
                break;
            }
            case 1: {
                this.handlePass(args);
                break;
            }
            case 2: {
                this.handleCwd(args);
                break;
            }
            case 3: {
                this.handleNlst(args);
                break;
            }
            case 4: {
                this.handleNlst(args);
                break;
            }
            case 5:
            case 6: {
                this.handlePwd();
                break;
            }
            case 7: {
                this.handleQuit();
                break;
            }
            case 8: {
                this.handlePasv();
                break;
            }
            case 9: {
                this.handleEpsv();
                break;
            }
            case 10: {
                this.handleSyst();
                break;
            }
            case 11: {
                this.handleFeat();
                break;
            }
            case 12: {
                this.handlePort(args);
                break;
            }
            case 13: {
                this.handleEPort(args);
                break;
            }
            case 14: {
                this.handleRetr(args);
                break;
            }
            case 15:
            case 16: {
                this.handleMkd(args);
                break;
            }
            case 17:
            case 18: {
                this.handleRmd(args);
                break;
            }
            case 19: {
                this.handleType(args);
                break;
            }
            case 20: {
                this.handleStor(args);
                break;
            }
            case 21: {
                this.server.terminate();
                break;
            }
            default: {
                this.sendMsgToClient("501 Unknown command");
                break;
            }
        }
    }
    
    private void sendMsgToClient(final String msg) {
        this.controlOutWriter.println(msg);
    }
    
    private void sendDataMsgToClient(final String msg) {
        if (this.dataConnection == null) {
            this.sendMsgToClient("425 No data connection was established");
            this.debugOutput("Cannot send message, because no data connection is established");
        }
        else {
            this.dataOutWriter.print(msg + "\r\n");
        }
    }
    
    private void openDataConnectionPassive(final int port) {
        this.closeDataConnection();
        try {
            this.dataSocket = new ServerSocket(port);
            this.dataConnection = this.dataSocket.accept();
            this.dataOutWriter = new PrintWriter(this.dataConnection.getOutputStream(), true);
            this.debugOutput("Data connection - Passive Mode - established");
        }
        catch (final IOException e) {
            Status.printStackTrace("Could not create data connection.", (Throwable)e);
        }
    }
    
    private void openDataConnectionActive(final String ipAddress, final int port) {
        this.closeDataConnection();
        try {
            this.dataConnection = new Socket(ipAddress, port);
            this.dataOutWriter = new PrintWriter(this.dataConnection.getOutputStream(), true);
            this.debugOutput("Data connection - Active Mode - established");
        }
        catch (final IOException e) {
            Status.printStackTrace("Could not connect to client data socket", (Throwable)e);
        }
    }
    
    private void closeDataConnection() {
        try {
            if (this.dataOutWriter != null) {
                this.dataOutWriter.close();
                this.dataOutWriter = null;
            }
            if (this.dataConnection != null) {
                this.dataConnection.close();
                this.dataConnection = null;
            }
            if (this.dataSocket != null) {
                this.dataSocket.close();
                this.dataSocket = null;
            }
            this.debugOutput("Data connection was closed");
        }
        catch (final IOException e) {
            Status.printStackTrace("Could not close data connection", (Throwable)e);
        }
    }
    
    private void handleUser(final String username) {
        if (username.toLowerCase().equals((Object)this.validUser)) {
            this.sendMsgToClient("331 User name okay, need password");
            this.currentUserStatus = "ENTEREDUSERNAME";
        }
        else if (this.currentUserStatus == "LOGGEDIN") {
            this.sendMsgToClient("530 User already logged in");
        }
        else {
            this.sendMsgToClient("530 Not logged in");
        }
    }
    
    private void handlePass(final String password) {
        if (this.currentUserStatus == "ENTEREDUSERNAME" && password.equals((Object)this.validPassword)) {
            this.currentUserStatus = "LOGGEDIN";
            this.sendMsgToClient("230-Welcome to HKUST");
            this.sendMsgToClient("230 User logged in successfully");
        }
        else if (this.currentUserStatus == "LOGGEDIN") {
            this.sendMsgToClient("530 User already logged in");
        }
        else {
            this.sendMsgToClient("530 Not logged in");
        }
    }
    
    private void handleCwd(final String args) {
        File f;
        if ("..".equals((Object)args)) {
            f = this.toAbsoluteFile(null);
            if (f.getParentFile() != null) {
                f = f.getParentFile();
            }
        }
        else if (".".equals((Object)args)) {
            f = this.toAbsoluteFile(null);
        }
        else {
            f = this.toAbsoluteFile(args);
        }
        if (this.isFileValid(f, true) && this.isDirectory(f)) {
            this.currDirectory = f.getAbsolutePath();
            this.sendMsgToClient("250 The current directory has been changed to " + this.currDirectory);
        }
        else {
            this.sendMsgToClient("550 Requested action not taken. File unavailable: " + this.currDirectory);
        }
    }
    
    private void handleNlst(final String args) {
        if (this.dataConnection == null) {
            this.sendMsgToClient("425 No data connection was established");
        }
        else {
            final String[] dirContent = this.nlstHelper(args);
            if (dirContent == null) {
                this.sendMsgToClient("550 File does not exist.");
            }
            else {
                this.sendMsgToClient("125 Opening ASCII mode data connection for file list.");
                for (int i = 0; i < dirContent.length; ++i) {
                    this.sendDataMsgToClient(dirContent[i]);
                }
                this.sendMsgToClient("226 Transfer complete.");
                this.closeDataConnection();
            }
        }
    }
    
    private String[] nlstHelper(final String args) {
        String[] result = null;
        final File f = this.toAbsoluteFile(args);
        if (this.isFileValid(f, true)) {
            if (this.isDirectory(f)) {
                final List files = (List)new ArrayList();
                final String[] children = f.list();
                if (children != null) {
                    for (final String child : children) {
                        files.add((Object)this.createFile(f, child));
                    }
                }
                if (files.size() > 0) {
                    result = new String[files.size()];
                    for (int i = 0; i < files.size(); ++i) {
                        result[i] = this.ls((File)files.get(i));
                    }
                }
            }
            else if (f.isFile()) {
                result = new String[] { this.ls(f) };
            }
        }
        return result;
    }
    
    private String ls(final File f) {
        final String fileSize = Long.toString(f.length());
        final StringBuffer padding = new StringBuffer();
        for (int i = 0; i < Math.min(1, 14 - fileSize.length()); ++i) {
            padding.append(" ");
        }
        final Date lastModified = new Date(f.lastModified());
        final String month = FtpWorker.fileMonthFormat.format(lastModified).substring(0, 3);
        String restOfDate;
        if (System.currentTimeMillis() - lastModified.getTime() > 655200000L) {
            restOfDate = FtpWorker.fileDayYearFormat.format(lastModified);
        }
        else {
            restOfDate = FtpWorker.fileDayHourFormat.format(lastModified);
        }
        String owner = "owner";
        String group = "group";
        String mode = this.isDirectory(f) ? "rwxr-xr-x" : "rw-r--r--";
        final FileStatusMode[] modeIter = { FileStatusMode.S_IRUSR, FileStatusMode.S_IWUSR, FileStatusMode.S_IXUSR, FileStatusMode.S_IRGRP, FileStatusMode.S_IWGRP, FileStatusMode.S_IXGRP, FileStatusMode.S_IROTH, FileStatusMode.S_IWOTH, FileStatusMode.S_IXOTH };
        if (f instanceof org.ps5jb.sdk.io.File) {
            final org.ps5jb.sdk.io.File sdkFile = (org.ps5jb.sdk.io.File)f;
            owner = ((sdkFile.getOwner() == 0) ? "root " : Integer.toString(sdkFile.getOwner()));
            if (owner.length() > 5) {
                owner = owner.substring(0, 5);
            }
            else {
                while (owner.length() != 5) {
                    owner = "0" + owner;
                }
            }
            group = ((sdkFile.getGroup() == 0) ? "root " : Integer.toString(sdkFile.getGroup()));
            if (group.length() > 5) {
                group = group.substring(0, 5);
            }
            else {
                while (group.length() != 5) {
                    group = "0" + group;
                }
            }
            final StringBuffer modeBuffer = new StringBuffer();
            final Set sdkFileModes = sdkFile.getModes();
            for (int j = 0; j < modeIter.length; ++j) {
                if (sdkFileModes.contains((Object)modeIter[j])) {
                    if (j % 3 == 0) {
                        modeBuffer.append("r");
                    }
                    else if (j % 3 == 1) {
                        modeBuffer.append("w");
                    }
                    else {
                        modeBuffer.append("x");
                    }
                }
                else {
                    modeBuffer.append("-");
                }
            }
            mode = modeBuffer.toString();
        }
        return FtpWorker.lsDirFormat.format((Object)new Object[] { this.isDirectory(f) ? "d" : "-", mode + " 1 " + owner + " " + group, padding, fileSize, month, restOfDate, f.getName() });
    }
    
    private void handlePort(final String args) {
        final StringTokenizer tokenizer = new StringTokenizer(args, ",");
        final String[] stringSplit = this.splitString(args, ",");
        final String hostName = stringSplit[0] + "." + stringSplit[1] + "." + stringSplit[2] + "." + stringSplit[3];
        final int p = Integer.parseInt(stringSplit[4]) * 256 + Integer.parseInt(stringSplit[5]);
        this.openDataConnectionActive(hostName, p);
        this.sendMsgToClient("200 Command OK");
    }
    
    private void handleEPort(final String args) {
        final String IPV4 = "1";
        final String IPV5 = "2";
        final String[] splitArgs = this.splitString(args, "\\|");
        final String ipVersion = splitArgs[1];
        final String ipAddress = splitArgs[2];
        if (!"1".equals((Object)ipVersion) || !"2".equals((Object)ipVersion)) {
            throw new IllegalArgumentException("Unsupported IP version");
        }
        final int port = Integer.parseInt(splitArgs[3]);
        this.openDataConnectionActive(ipAddress, port);
        this.sendMsgToClient("200 Command OK");
    }
    
    private void handlePwd() {
        this.sendMsgToClient("257 \"" + this.currDirectory);
    }
    
    private void handlePasv() {
        final String myIp = this.server.getNetAddress();
        final String[] myIpSplit = this.splitString(myIp, "\\.");
        final int p1 = this.dataPort / 256;
        final int p2 = this.dataPort % 256;
        this.sendMsgToClient("227 Entering Passive Mode (" + myIpSplit[0] + "," + myIpSplit[1] + "," + myIpSplit[2] + "," + myIpSplit[3] + "," + p1 + "," + p2);
        this.openDataConnectionPassive(this.dataPort);
    }
    
    private void handleEpsv() {
        this.sendMsgToClient("229 Entering Extended Passive Mode (|||" + this.dataPort + "|)");
        this.openDataConnectionPassive(this.dataPort);
    }
    
    private void handleQuit() {
        this.sendMsgToClient("221 Closing connection");
        this.quitCommandLoop = true;
    }
    
    private void handleSyst() {
        this.sendMsgToClient("215 PS5JB FTP Server");
    }
    
    private void handleFeat() {
        this.sendMsgToClient("211-Extensions supported:");
        this.sendMsgToClient("211 END");
    }
    
    private void handleMkd(final String args) {
        if (args != null) {
            final File dir = this.toAbsoluteFile(args);
            if (!dir.mkdir()) {
                this.sendMsgToClient("550 Failed to create new directory");
                this.debugOutput("Failed to create new directory");
            }
            else {
                this.sendMsgToClient("250 Directory successfully created");
            }
        }
        else {
            this.sendMsgToClient("550 Invalid directory name");
        }
    }
    
    private void handleRmd(final String dir) {
        final File f = this.toAbsoluteFile(dir);
        if (this.isFileValid(f, true) && this.isDirectory(f) && f.getParentFile() != null) {
            if (f.delete()) {
                this.sendMsgToClient("250 Directory was successfully removed");
            }
            else {
                this.sendMsgToClient("550 Failed to delete the directory");
            }
        }
        else {
            this.sendMsgToClient("550 Invalid directory name");
        }
    }
    
    private void handleType(final String mode) {
        if (mode.toUpperCase().equals((Object)"A")) {
            this.transferMode = "ASCII";
            this.sendMsgToClient("200 OK");
        }
        else if (mode.toUpperCase().equals((Object)"I")) {
            this.transferMode = "BINARY";
            this.sendMsgToClient("200 OK");
        }
        else {
            this.sendMsgToClient("504 Not OK");
        }
    }
    
    private void handleRetr(final String file) {
        final File f = this.toAbsoluteFile(file);
        if (!this.isFileValid(f, true) || !f.isFile()) {
            this.sendMsgToClient("550 Invalid file name");
        }
        else if (this.transferMode == "BINARY") {
            this.sendMsgToClient("150 Opening binary mode data connection for requested file " + f.getName());
            BufferedInputStream fin = null;
            try {
                fin = new BufferedInputStream((InputStream)this.createFileInputStream(f));
            }
            catch (final Exception e) {
                Status.printStackTrace("Could not create input stream", (Throwable)e);
                this.sendMsgToClient("550 Could not open requested file");
                return;
            }
            BufferedOutputStream fout = null;
            try {
                fout = new BufferedOutputStream(this.dataConnection.getOutputStream());
            }
            catch (final Exception e2) {
                Status.printStackTrace("Could not create output stream", (Throwable)e2);
                this.sendMsgToClient("550 Error writing to data connection");
                return;
            }
            this.debugOutput("Starting file transmission of " + f.getName());
            final byte[] buf = new byte[1024];
            int l = 0;
            try {
                while ((l = fin.read(buf, 0, 1024)) != -1) {
                    fout.write(buf, 0, l);
                }
            }
            catch (final IOException e3) {
                Status.printStackTrace("Could not read from or write to file streams", (Throwable)e3);
            }
            try {
                fin.close();
                fout.close();
            }
            catch (final IOException e3) {
                Status.printStackTrace("Could not close file streams", (Throwable)e3);
            }
            this.debugOutput("Completed file transmission of " + f.getName());
            this.sendMsgToClient("226 File transfer successful. Closing data connection.");
        }
        else {
            this.sendMsgToClient("150 Opening ASCII mode data connection for requested file " + f.getName());
            BufferedReader rin = null;
            PrintWriter rout = null;
            try {
                rin = new BufferedReader((Reader)new FileReader(f));
                rout = new PrintWriter(this.dataConnection.getOutputStream(), true);
            }
            catch (final IOException e4) {
                this.debugOutput("Could not create file streams");
            }
            try {
                String s;
                while ((s = rin.readLine()) != null) {
                    rout.println(s);
                }
            }
            catch (final IOException e5) {
                Status.printStackTrace("Could not read from or write to file streams", (Throwable)e5);
            }
            try {
                rout.close();
                rin.close();
            }
            catch (final IOException e5) {
                Status.printStackTrace("Could not close file streams", (Throwable)e5);
            }
            this.sendMsgToClient("226 File transfer successful. Closing data connection.");
        }
        this.closeDataConnection();
    }
    
    private void handleStor(final String file) {
        if (file == null) {
            this.sendMsgToClient("501 No filename given");
        }
        else {
            final File f = this.toAbsoluteFile(file);
            if (this.isFileExists(f)) {
                this.sendMsgToClient("550 File already exists");
            }
            else if (!this.isFileValid(f, false)) {
                this.sendMsgToClient("550 Invalid file name");
            }
            else if (this.transferMode == "BINARY") {
                BufferedOutputStream fout = null;
                BufferedInputStream fin = null;
                this.sendMsgToClient("150 Opening binary mode data connection for requested file " + f.getName());
                try {
                    fout = new BufferedOutputStream((OutputStream)new FileOutputStream(f));
                    fin = new BufferedInputStream(this.dataConnection.getInputStream());
                }
                catch (final Exception e) {
                    this.debugOutput("Could not create file streams");
                }
                this.debugOutput("Start receiving file " + f.getName());
                final byte[] buf = new byte[1024];
                int l = 0;
                try {
                    while ((l = fin.read(buf, 0, 1024)) != -1) {
                        fout.write(buf, 0, l);
                    }
                }
                catch (final IOException e2) {
                    Status.printStackTrace("Could not read from or write to file streams", (Throwable)e2);
                }
                try {
                    fin.close();
                    fout.close();
                }
                catch (final IOException e2) {
                    Status.printStackTrace("Could not close file streams", (Throwable)e2);
                }
                this.debugOutput("Completed receiving file " + f.getName());
                this.sendMsgToClient("226 File transfer successful. Closing data connection.");
            }
            else {
                this.sendMsgToClient("150 Opening ASCII mode data connection for requested file " + f.getName());
                BufferedReader rin = null;
                PrintWriter rout = null;
                try {
                    rin = new BufferedReader((Reader)new InputStreamReader(this.dataConnection.getInputStream()));
                    rout = new PrintWriter((OutputStream)new FileOutputStream(f), true);
                }
                catch (final IOException e3) {
                    this.debugOutput("Could not create file streams");
                }
                try {
                    String s;
                    while ((s = rin.readLine()) != null) {
                        rout.println(s);
                    }
                }
                catch (final IOException e4) {
                    Status.printStackTrace("Could not read from or write to file streams", (Throwable)e4);
                }
                try {
                    rout.close();
                    rin.close();
                }
                catch (final IOException e4) {
                    Status.printStackTrace("Could not close file streams", (Throwable)e4);
                }
                this.sendMsgToClient("226 File transfer successful. Closing data connection.");
            }
            this.closeDataConnection();
        }
    }
    
    private void debugOutput(final String msg) {
        if (this.debugMode) {
            Status.println(msg);
        }
    }
    
    private String[] splitString(final String str, final String delim) {
        final StringTokenizer tokenizer = new StringTokenizer(str, delim);
        final List result = (List)new ArrayList();
        while (tokenizer.hasMoreTokens()) {
            final String nextArg = tokenizer.nextToken();
            result.add((Object)nextArg);
        }
        return (String[])result.toArray((Object[])new String[result.size()]);
    }
    
    static {
        FtpWorker.fileMonthFormat = new SimpleDateFormat("MMM", Locale.ENGLISH);
        FtpWorker.fileDayHourFormat = new SimpleDateFormat("dd HH:mm", Locale.ENGLISH);
        FtpWorker.fileDayYearFormat = new SimpleDateFormat("dd  yyyy", Locale.ENGLISH);
        FtpWorker.lsDirFormat = new MessageFormat("{0}{1}{2} {3} {4} {5} {6}");
    }
    
    private static final class transferType
    {
        private static final String ASCII = "ASCII";
        private static final String BINARY = "BINARY";
    }
    
    private static final class userStatus
    {
        private static final String NOTLOGGEDIN = "NOTLOGGEDIN";
        private static final String ENTEREDUSERNAME = "ENTEREDUSERNAME";
        private static final String LOGGEDIN = "LOGGEDIN";
    }
}

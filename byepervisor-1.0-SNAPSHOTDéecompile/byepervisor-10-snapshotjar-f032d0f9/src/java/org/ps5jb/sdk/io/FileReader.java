package org.ps5jb.sdk.io;

import java.io.FileDescriptor;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class FileReader extends InputStreamReader
{
    public FileReader(final String fileName) throws FileNotFoundException {
        super((InputStream)new FileInputStream(fileName));
    }
    
    public FileReader(final File file) throws FileNotFoundException {
        super((InputStream)new FileInputStream(file));
    }
    
    public FileReader(final FileDescriptor fd) {
        super((InputStream)new FileInputStream(fd));
    }
}

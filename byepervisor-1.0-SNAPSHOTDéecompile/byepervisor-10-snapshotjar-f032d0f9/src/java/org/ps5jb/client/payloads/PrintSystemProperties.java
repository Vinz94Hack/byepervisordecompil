package org.ps5jb.client.payloads;

import java.util.Iterator;
import java.util.Enumeration;
import java.util.Properties;
import java.util.TreeSet;
import org.ps5jb.loader.Config;
import org.ps5jb.loader.Status;

public class PrintSystemProperties implements Runnable
{
    public void run() {
        Status.resetLogger((String)null, 0, 0);
        Status.println("The following message will not show up on the remote logging server");
        Status.resetLogger(Config.getLoggerHost(), Config.getLoggerPort(), Config.getLoggerTimeout());
        Status.println("The following message will show up on the remote logging server");
        final Properties props = System.getProperties();
        final Enumeration propNames = props.propertyNames();
        final TreeSet sortedPropNames = new TreeSet();
        while (propNames.hasMoreElements()) {
            final String propName = (String)propNames.nextElement();
            sortedPropNames.add((Object)propName);
        }
        for (String sortedPropName : sortedPropNames) {
            final String value = props.getProperty(sortedPropName);
            Status.println(sortedPropName + " = " + value);
        }
    }
}

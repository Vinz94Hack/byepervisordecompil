package org.ps5jb.client.payloads.umtx.common;

import org.ps5jb.loader.Status;

public class DebugStatus
{
    public static Level level;
    
    public static boolean isTraceEnabled() {
        return DebugStatus.level.level <= Level.TRACE.level;
    }
    
    public static void trace(final String message) {
        if (isTraceEnabled()) {
            Status.println(message);
        }
    }
    
    public static boolean isDebugEnabled() {
        return DebugStatus.level.level <= Level.DEBUG.level;
    }
    
    public static void debug(final String message) {
        if (isDebugEnabled()) {
            Status.println(message);
        }
    }
    
    public static boolean isNoticeEnabled() {
        return DebugStatus.level.level <= Level.NOTICE.level;
    }
    
    public static void notice(final String message) {
        if (isNoticeEnabled()) {
            Status.println(message);
        }
    }
    
    public static boolean isInfoEnabled() {
        return DebugStatus.level.level <= Level.INFO.level;
    }
    
    public static void info(final String message) {
        if (isInfoEnabled()) {
            Status.println(message);
        }
    }
    
    public static boolean isErrorEnabled() {
        return DebugStatus.level.level <= Level.ERROR.level;
    }
    
    public static void error(final String message) {
        if (isErrorEnabled()) {
            Status.println(message);
        }
    }
    
    public static void error(final String message, final Throwable ex) {
        if (isErrorEnabled()) {
            Status.printStackTrace(message, ex);
        }
    }
    
    static {
        DebugStatus.level = Level.INFO;
    }
    
    public static class Level
    {
        public static final Level TRACE;
        public static final Level DEBUG;
        public static final Level NOTICE;
        public static final Level INFO;
        public static final Level ERROR;
        private String name;
        private int level;
        
        private Level(final int level, final String name) {
            this.level = level;
            this.name = name;
        }
        
        @Override
        public String toString() {
            return this.name;
        }
        
        static {
            TRACE = new Level(5, "TRACE");
            DEBUG = new Level(10, "DEBUG");
            NOTICE = new Level(20, "NOTICE");
            INFO = new Level(30, "INFO");
            ERROR = new Level(40, "ERROR");
        }
    }
}

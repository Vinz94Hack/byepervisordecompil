package org.ps5jb.sdk.core;

import java.security.PrivilegedActionException;
import java.security.AccessController;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.PrivilegedExceptionAction;

public class OpenModuleAction implements PrivilegedExceptionAction
{
    private String className;
    
    private OpenModuleAction(final String className) {
        this.className = className;
    }
    
    public Object run() throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        final Method Class_getModule = Class.class.getDeclaredMethod("getModule", (Class<?>[])new Class[0]);
        Class_getModule.setAccessible(true);
        final Class targetClass = Class.forName(this.className);
        final Object targetModule = Class_getModule.invoke((Object)targetClass, new Object[0]);
        final Class moduleClass = Class.forName("java.lang.Module");
        final Method Module_implAddOpensToAllUnnamed = moduleClass.getDeclaredMethod("implAddOpensToAllUnnamed", String.class);
        Module_implAddOpensToAllUnnamed.setAccessible(true);
        Module_implAddOpensToAllUnnamed.invoke(targetModule, new Object[] { targetClass.getPackage().getName() });
        return null;
    }
    
    public static void execute(final String className) throws PrivilegedActionException {
        AccessController.doPrivileged((PrivilegedExceptionAction)new OpenModuleAction(className));
    }
}

package org.ps5jb.client.payloads.umtx.common;

import org.havi.ui.HNavigable;
import java.awt.Color;
import org.ps5jb.loader.Status;
import org.havi.ui.HScene;
import org.havi.ui.HSceneFactory;
import org.dvb.event.UserEventRepository;
import org.dvb.event.OverallRepository;
import org.dvb.event.EventManager;
import java.awt.FontMetrics;
import java.awt.Font;
import org.havi.ui.HStaticText;
import org.havi.ui.HRangeValue;
import org.havi.ui.event.HAdjustmentEvent;
import org.havi.ui.event.HTextEvent;
import org.havi.ui.HSinglelineEntry;
import java.awt.event.KeyEvent;
import java.awt.Component;
import org.dvb.event.UserEvent;
import java.awt.Graphics;
import org.ps5jb.loader.Config;
import org.havi.ui.event.HKeyListener;
import org.havi.ui.event.HAdjustmentListener;
import org.havi.ui.event.HTextListener;
import org.dvb.event.UserEventListener;
import org.havi.ui.HContainer;

public class LoggingConfiguration extends HContainer implements UserEventListener, HTextListener, HAdjustmentListener, HKeyListener
{
    private static final String EMPTY_IP = "0.0.0.0";
    protected String loggerHost;
    protected int loggerPort;
    protected DebugStatus.Level debugLevel;
    protected boolean aborted;
    protected boolean canceled;
    protected boolean accepted;
    
    protected LoggingConfiguration() {
        this.loggerHost = Config.getLoggerHost();
        if ("".equals((Object)this.loggerHost) || this.loggerHost == null) {
            this.loggerHost = "0.0.0.0";
        }
        this.loggerPort = Config.getLoggerPort();
        this.debugLevel = DebugStatus.level;
        this.canceled = false;
        this.accepted = false;
        this.aborted = false;
    }
    
    public boolean isOpaque() {
        return true;
    }
    
    public boolean isFocusTraversable() {
        return true;
    }
    
    public void paint(final Graphics graphics) {
        if (this.isShowing()) {
            graphics.setColor(this.getBackground());
            graphics.fillRect(0, 0, this.getWidth(), this.getHeight());
        }
        super.paint(graphics);
    }
    
    public void userEventReceived(final UserEvent userEvent) {
        if (userEvent.getType() == 402) {
            switch (userEvent.getCode()) {
                case 403: {
                    this.aborted = true;
                    break;
                }
                case 404: {
                    this.accepted = true;
                    break;
                }
                case 406: {
                    this.canceled = true;
                    break;
                }
                case 48: {
                    this.debugLevel = DebugStatus.Level.ERROR;
                    this.setStaticText("level", this.debugLevel.toString());
                    break;
                }
                case 49: {
                    this.debugLevel = DebugStatus.Level.INFO;
                    this.setStaticText("level", this.debugLevel.toString());
                    break;
                }
                case 50: {
                    this.debugLevel = DebugStatus.Level.NOTICE;
                    this.setStaticText("level", this.debugLevel.toString());
                    break;
                }
                case 51: {
                    this.debugLevel = DebugStatus.Level.DEBUG;
                    this.setStaticText("level", this.debugLevel.toString());
                    break;
                }
                case 52: {
                    this.debugLevel = DebugStatus.Level.TRACE;
                    this.setStaticText("level", this.debugLevel.toString());
                    break;
                }
                case 40: {
                    if (!(userEvent.getSource() instanceof Component)) {
                        this.getComponent("host").requestFocus();
                        break;
                    }
                    break;
                }
            }
        }
    }
    
    public void keyTyped(final KeyEvent keyEvent) {
    }
    
    public void keyPressed(final KeyEvent keyEvent) {
        if (keyEvent.getSource() instanceof Component) {
            final Component source = (Component)keyEvent.getSource();
            if ("host".equals((Object)source.getName())) {
                final HSinglelineEntry textCtrl = (HSinglelineEntry)source;
                if (keyEvent.getKeyCode() == 38) {
                    this.incrementInt(textCtrl, 1, 0, 255);
                }
                else if (keyEvent.getKeyCode() == 40) {
                    this.incrementInt(textCtrl, -1, 0, 255);
                }
                else if (keyEvent.getKeyCode() == 461) {
                    final int caretPos = textCtrl.getCaretCharPosition();
                    final String ip = textCtrl.getTextContent(128);
                    if ((caretPos <= 0 || ip.charAt(caretPos - 1) != '.') && (caretPos <= 1 || ip.charAt(caretPos - 2) != '.')) {
                        if (caretPos != 1) {
                            textCtrl.deletePreviousChar();
                        }
                    }
                }
            }
        }
    }
    
    public void keyReleased(final KeyEvent keyEvent) {
    }
    
    protected void incrementInt(final HSinglelineEntry control, final int delta, final int min, final int max) {
        final String ip = control.getTextContent(128);
        final int caretPos = control.getCaretCharPosition();
        int prevDot = 0;
        int nextDot;
        for (nextDot = ip.indexOf(46); nextDot != -1 && nextDot < caretPos; nextDot = ip.indexOf(46, nextDot + 1)) {
            prevDot = nextDot;
        }
        if (nextDot == -1) {
            nextDot = ip.length();
        }
        final String ipComponent = ip.substring((prevDot == 0) ? 0 : (prevDot + 1), nextDot);
        int componentVal;
        try {
            componentVal = Integer.parseInt(ipComponent) + delta;
        }
        catch (final NumberFormatException e) {
            componentVal = min;
        }
        if (componentVal >= min && componentVal <= max) {
            final String newIp = ip.substring(0, (prevDot == 0) ? 0 : (prevDot + 1)) + componentVal + ip.substring(nextDot);
            control.setTextContent(newIp, 128);
            control.setCaretCharPosition(caretPos);
        }
    }
    
    protected Component getComponent(final String name) {
        Component result = null;
        for (int i = 0; i < this.getComponentCount(); ++i) {
            final Component comp = this.getComponent(i);
            if (name.equals((Object)comp.getName())) {
                result = comp;
                break;
            }
        }
        return result;
    }
    
    public void textChanged(final HTextEvent textEvent) {
        if (textEvent.getID() == 2020 || textEvent.getID() == 2022) {
            final Component component = (Component)textEvent.getSource();
            if (component.getName().equals((Object)"host")) {
                final HSinglelineEntry source = (HSinglelineEntry)component;
                this.loggerHost = source.getTextContent(128);
            }
        }
    }
    
    public void valueChanged(final HAdjustmentEvent changeEvent) {
        final Component component = (Component)changeEvent.getSource();
        if (component.getName().equals((Object)"port")) {
            final HRangeValue rangeValue = (HRangeValue)component;
            this.loggerPort = rangeValue.getValue();
            this.setStaticText("portval", Integer.toString(this.loggerPort));
        }
    }
    
    protected void setStaticText(final String componentName, final String value) {
        final Component comp = this.getComponent(componentName);
        final HStaticText textComp = (HStaticText)comp;
        Font font = textComp.getFont();
        if (font == null) {
            font = this.getFont();
        }
        final FontMetrics fm = this.getFontMetrics(font);
        textComp.setTextContent(value, 128);
        textComp.setSize(fm.stringWidth(value), textComp.getHeight());
    }
    
    public void caretMoved(final HTextEvent textEvent) {
    }
    
    public boolean render() {
        EventManager.getInstance().addUserEventListener((UserEventListener)this, (UserEventRepository)new OverallRepository());
        try {
            final HScene scene = HSceneFactory.getInstance().getDefaultHScene();
            scene.add((Component)this, (Object)"Center", 0);
            try {
                scene.validate();
                while (!this.canceled && !this.accepted && !this.aborted) {
                    scene.repaint();
                    Thread.yield();
                }
            }
            finally {
                this.setVisible(false);
                scene.remove((Component)this);
            }
            if (this.accepted) {
                this.applySelection();
            }
            else if (this.canceled) {
                DebugStatus.info("Logging configuration changes canceled");
            }
        }
        finally {
            EventManager.getInstance().removeUserEventListener((UserEventListener)this);
        }
        return !this.aborted;
    }
    
    protected void applySelection() {
        DebugStatus.level = this.debugLevel;
        String host = (this.loggerHost == null) ? null : this.loggerHost.trim();
        if ("".equals((Object)host) || "0.0.0.0".equals((Object)host)) {
            host = null;
        }
        Status.resetLogger(host, this.loggerPort, Config.getLoggerTimeout());
        DebugStatus.info("The logging level is changed to: " + DebugStatus.level);
        if (host == null) {
            DebugStatus.info("The remote logging is disabled");
        }
        else {
            DebugStatus.info("The remote logging server is changed to: " + host + ":" + this.loggerPort + ". Capture messages with `socat udp-recv:" + this.loggerPort + " stdout`");
        }
    }
    
    public static LoggingConfiguration createComponent() {
        final LoggingConfiguration loggingComponent = new LoggingConfiguration();
        loggingComponent.setSize(Config.getLoaderResolutionWidth(), Config.getLoaderResolutionHeight());
        loggingComponent.setFont(new Font((String)null, 0, 18));
        loggingComponent.setBackground(Color.lightGray);
        loggingComponent.setForeground(Color.black);
        loggingComponent.setVisible(true);
        final Font font = loggingComponent.getFont();
        final FontMetrics fm = loggingComponent.getFontMetrics(font);
        final Font valueFont = new Font((String)null, 1, 18);
        final FontMetrics vfm = loggingComponent.getFontMetrics(valueFont);
        final Font hintFont = new Font((String)null, 2, 14);
        final FontMetrics hfm = loggingComponent.getFontMetrics(hintFont);
        final int horizonalLabelSpace = 5;
        final int horizonalControlSpace = 20;
        final int verticalLabelSpace = 1;
        final int verticalControlSpace = 20;
        final int labelHeight = fm.getHeight();
        final int controlHeight = 50;
        final String text1 = "Logging level (screen and remote):";
        final HStaticText text1ctrl = new HStaticText(text1, 80, 80, fm.stringWidth(text1), labelHeight);
        text1ctrl.setForeground(Color.black);
        text1ctrl.setBordersEnabled(false);
        loggingComponent.add((Component)text1ctrl);
        final String text1val = loggingComponent.debugLevel.toString();
        final HStaticText text1valCtrl = new HStaticText(text1val, text1ctrl.getX() + text1ctrl.getWidth() + 5, text1ctrl.getY(), vfm.stringWidth(text1val), labelHeight);
        text1valCtrl.setForeground(Color.red);
        text1valCtrl.setBordersEnabled(false);
        text1valCtrl.setFont(valueFont);
        text1valCtrl.setName("level");
        loggingComponent.add((Component)text1valCtrl);
        final String text2 = "Press Triangle, then 0 [ERROR] or 1 [INFO] or 2 [NOTICE] or 3 [DEBUG] or 4 [TRACE]";
        final HStaticText text2ctrl = new HStaticText(text2, text1ctrl.getX(), text1ctrl.getY() + text1ctrl.getHeight() + 1, hfm.stringWidth(text2), labelHeight);
        text2ctrl.setForeground(Color.darkGray);
        text2ctrl.setBordersEnabled(false);
        text2ctrl.setFont(hintFont);
        loggingComponent.add((Component)text2ctrl);
        final String hostLabel = "Logging host:";
        final HStaticText hostLabelCtrl = new HStaticText(hostLabel, text1ctrl.getX(), text2ctrl.getY() + text2ctrl.getHeight() + 20, fm.stringWidth(hostLabel), labelHeight);
        hostLabelCtrl.setForeground(Color.black);
        hostLabelCtrl.setBordersEnabled(false);
        loggingComponent.add((Component)hostLabelCtrl);
        final HSinglelineEntry hostEntry = new HSinglelineEntry(loggingComponent.loggerHost, text1ctrl.getX(), hostLabelCtrl.getY() + hostLabelCtrl.getHeight() + 1, 200, 50, 15, valueFont, Color.lightGray);
        hostEntry.addHTextListener((HTextListener)loggingComponent);
        hostEntry.addHKeyListener((HKeyListener)loggingComponent);
        hostEntry.setForeground(Color.black);
        hostEntry.setName("host");
        loggingComponent.add((Component)hostEntry);
        final String portLabel = "Logging port:";
        final HStaticText portLabelCtrl = new HStaticText(portLabel, hostEntry.getX() + hostEntry.getWidth() + 20, hostLabelCtrl.getY(), fm.stringWidth(portLabel), labelHeight);
        portLabelCtrl.setForeground(Color.black);
        portLabelCtrl.setBordersEnabled(false);
        loggingComponent.add((Component)portLabelCtrl);
        final String portVal = Integer.toString(loggingComponent.loggerPort);
        final HStaticText portValCtrl = new HStaticText(portVal, portLabelCtrl.getX() + portLabelCtrl.getWidth() + 5, portLabelCtrl.getY(), vfm.stringWidth(portVal), labelHeight);
        portValCtrl.setForeground(Color.red);
        portValCtrl.setBordersEnabled(false);
        portValCtrl.setFont(valueFont);
        portValCtrl.setName("portval");
        loggingComponent.add((Component)portValCtrl);
        final HRangeValue portEntry = new HRangeValue(0, 0, 65535, loggingComponent.loggerPort, portLabelCtrl.getX(), portLabelCtrl.getY() + portLabelCtrl.getHeight() + 1, 200, 50);
        portEntry.addAdjustmentListener((HAdjustmentListener)loggingComponent);
        portEntry.setName("port");
        portEntry.setBlockIncrement(20);
        loggingComponent.add((Component)portEntry);
        final String text3 = "To disable remote logging, specify 0.0.0.0. Use Up/Down to change the IP components";
        final HStaticText text3ctrl = new HStaticText(text3, text1ctrl.getX(), hostEntry.getY() + hostEntry.getHeight() + 1, hfm.stringWidth(text3), labelHeight);
        text3ctrl.setForeground(Color.darkGray);
        text3ctrl.setBordersEnabled(false);
        text3ctrl.setFont(hintFont);
        loggingComponent.add((Component)text3ctrl);
        final String conclusionLabel = "Green Square - apply and proceed. Yellow Square - revert and proceed. Red Square - abort";
        final HStaticText conclusionCtrl = new HStaticText(conclusionLabel, text1ctrl.getX(), text3ctrl.getY() + text3ctrl.getHeight() + 20, fm.stringWidth(conclusionLabel), labelHeight);
        conclusionCtrl.setForeground(Color.black);
        conclusionCtrl.setBordersEnabled(false);
        loggingComponent.add((Component)conclusionCtrl);
        hostEntry.setMove(39, (HNavigable)portEntry);
        portEntry.setMove(37, (HNavigable)hostEntry);
        return loggingComponent;
    }
}

package org.ps5jb.client.payloads;

import org.dvb.event.UserEvent;
import java.awt.Rectangle;
import java.awt.image.ImageObserver;
import java.awt.Image;
import java.awt.Font;
import java.awt.Graphics;
import org.havi.ui.HScene;
import org.ps5jb.loader.Status;
import java.awt.Component;
import org.havi.ui.HSceneFactory;
import java.awt.Color;
import org.ps5jb.loader.Config;
import org.dvb.event.UserEventRepository;
import org.dvb.event.OverallRepository;
import org.dvb.event.EventManager;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import org.dvb.event.UserEventListener;
import org.havi.ui.HContainer;

public class MiniTennisGame extends HContainer implements Runnable, UserEventListener
{
    private static final int RACQUET_WIDTH = 150;
    private static final int RACQUET_HEIGHT = 10;
    private static final int RAQUET_SPEED = 10;
    private static final int BALL_DIAMETER = 30;
    private static int BALL_SPEED;
    private int x;
    private int y;
    int xa;
    int ya;
    int rx;
    int rxa;
    int ry;
    private boolean terminated;
    private boolean isGameOver;
    private long startTime;
    private BufferedImage offscreenBuffer;
    private Graphics2D offscreenGraphics;
    private int offscreenScale;
    
    public MiniTennisGame() {
        this.x = 0;
        this.y = 0;
        this.xa = 30 / MiniTennisGame.BALL_SPEED;
        this.ya = 30 / MiniTennisGame.BALL_SPEED;
        this.rx = 0;
        this.rxa = 0;
        this.ry = 0;
        this.terminated = false;
        this.isGameOver = false;
        this.offscreenScale = 3;
    }
    
    public void run() {
        EventManager.getInstance().addUserEventListener((UserEventListener)this, (UserEventRepository)new OverallRepository());
        try {
            this.setSize(Config.getLoaderResolutionWidth(), Config.getLoaderResolutionHeight());
            this.setBackground(Color.darkGray);
            this.setForeground(Color.lightGray);
            this.setVisible(true);
            final HScene scene = HSceneFactory.getInstance().getDefaultHScene();
            scene.add((Component)this, (Object)"Center", 0);
            try {
                scene.validate();
                final Graphics2D g2d = (Graphics2D)this.getGraphics();
                this.offscreenBuffer = g2d.getDeviceConfiguration().createCompatibleImage(this.offscreenScale * this.getWidth(), this.offscreenScale * this.getHeight());
                this.offscreenGraphics = this.offscreenBuffer.createGraphics();
                try {
                    this.startTime = System.currentTimeMillis();
                    while (!this.terminated) {
                        this.moveBall();
                        this.moveRacquet();
                        this.repaint();
                        try {
                            Thread.sleep(this.isGameOver ? 5000L : 10L);
                        }
                        catch (final InterruptedException e) {
                            Status.printStackTrace(e.getMessage(), (Throwable)e);
                            this.terminated = true;
                        }
                        if (this.isGameOver) {
                            this.x = 0;
                            this.y = 0;
                            this.xa = 30 / MiniTennisGame.BALL_SPEED;
                            this.ya = 30 / MiniTennisGame.BALL_SPEED;
                            this.rx = 0;
                            this.rxa = 0;
                            this.ry = 0;
                            this.isGameOver = false;
                            this.startTime = System.currentTimeMillis();
                            MiniTennisGame.BALL_SPEED = 15;
                        }
                        else {
                            MiniTennisGame.BALL_SPEED = Math.max(5, 15 - (int)((System.currentTimeMillis() - this.startTime) / 1000L / 10L));
                        }
                    }
                }
                finally {
                    this.setVisible(false);
                    scene.remove((Component)this);
                }
            }
            finally {
                if (this.offscreenGraphics != null) {
                    this.offscreenGraphics.dispose();
                }
            }
        }
        finally {
            EventManager.getInstance().removeUserEventListener((UserEventListener)this);
        }
        Status.println("Mini-Tennis Terminated");
    }
    
    private synchronized void paintTo(final Graphics g, final int scale) {
        g.setColor(this.getBackground());
        g.fillRect(0, 0, scale * this.getWidth(), scale * this.getHeight());
        g.setColor(this.getForeground());
        g.fillOval(scale * this.x, scale * this.y, scale * 30, scale * 30);
        g.fillRect(scale * this.rx, scale * this.ry, scale * 150, scale * 10);
        if (this.isGameOver) {
            g.setColor(Color.red);
            g.setFont(new Font((String)null, 1, scale * 25));
            final String text = "Game over, restarting in 5 seconds unless RED button is pressed...";
            final int height = g.getFontMetrics().getHeight();
            final int width = g.getFontMetrics().stringWidth(text);
            g.drawString(text, (scale * this.getWidth() - width) / 2, (scale * this.getHeight() - height) / 2);
        }
    }
    
    public synchronized void paint(final Graphics g) {
        this.paintTo((Graphics)this.offscreenGraphics, this.offscreenScale);
        g.drawImage((Image)this.offscreenBuffer, 0, 0, this.getWidth(), this.getHeight(), 0, 0, this.offscreenBuffer.getWidth(), this.offscreenBuffer.getHeight(), (ImageObserver)null);
    }
    
    private void moveBall() {
        if (this.x + this.xa < 0) {
            this.xa = 30 / MiniTennisGame.BALL_SPEED;
        }
        if (this.x + this.xa > this.getWidth() - 30) {
            this.xa = -(30 / MiniTennisGame.BALL_SPEED);
        }
        if (this.y + this.ya < 0) {
            this.ya = 30 / MiniTennisGame.BALL_SPEED;
        }
        if (this.y + this.ya > this.getHeight() - 30) {
            this.isGameOver = true;
        }
        if (this.isCollision()) {
            this.ya = -(30 / MiniTennisGame.BALL_SPEED);
            this.y = this.ry - 30;
        }
        this.x = Math.min(this.x + this.xa, this.getWidth() - 30);
        this.y = Math.min(this.y + this.ya, this.getHeight() - 30);
    }
    
    public void moveRacquet() {
        this.ry = this.getHeight() - 50;
        if (this.rx + this.rxa > 0 && this.rx + this.rxa < this.getWidth() - 150) {
            this.rx += this.rxa;
        }
    }
    
    private boolean isCollision() {
        final Rectangle rBounds = new Rectangle(this.rx, this.ry, 150, 10);
        final Rectangle bBounds = new Rectangle(this.x, this.y, 30, 30);
        return rBounds.intersects(bBounds);
    }
    
    public void userEventReceived(final UserEvent userEvent) {
        if (userEvent.getFamily() == 1) {
            if (userEvent.getType() == 401) {
                switch (userEvent.getCode()) {
                    case 37: {
                        this.rxa = -15;
                        break;
                    }
                    case 39: {
                        this.rxa = 15;
                        break;
                    }
                }
            }
            else if (userEvent.getType() == 402) {
                switch (userEvent.getCode()) {
                    case 37:
                    case 39: {
                        this.rxa = 0;
                        break;
                    }
                    case 403: {
                        this.terminated = true;
                        break;
                    }
                }
            }
        }
    }
    
    static {
        MiniTennisGame.BALL_SPEED = 15;
    }
}

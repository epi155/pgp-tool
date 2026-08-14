package io.github.epi155.pgp.ui;

import io.github.epi155.pgp.service.PGPEngine;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.prefs.Preferences;

public class MainFrame extends JFrame {

    private final PGPEngine engine;
    private final SendPanel sendPanel;
    private final ReceivePanel receivePanel;

    public MainFrame(boolean showKeyTab, boolean advanced, boolean privateExtensions, boolean curve448) {
        setTitle("PGP Tool");
        setIconImage(new ImageIcon(getClass().getResource("/891399.png")).getImage());
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(800, 500));

        engine = new PGPEngine();

        JTabbedPane tabbedPane = new JTabbedPane();
        sendPanel = new SendPanel(engine, advanced, privateExtensions);
        tabbedPane.addTab("Send", sendPanel);
        receivePanel = new ReceivePanel(engine);
        tabbedPane.addTab("Receive", receivePanel);
        if (showKeyTab) {
            tabbedPane.addTab("Key", new KeyTabPanel(advanced, curve448));
        }

        add(tabbedPane);
        restoreWindowState();

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                receivePanel.cleanupTempFiles();
                saveWindowState();
            }
        });
    }

    private void saveWindowState() {
        Preferences prefs = Preferences.userNodeForPackage(MainFrame.class);
        prefs.putInt("window_x", getX());
        prefs.putInt("window_y", getY());
        prefs.putInt("window_width", getWidth());
        prefs.putInt("window_height", getHeight());
        prefs.putBoolean("window_maximized",
                (getExtendedState() & Frame.MAXIMIZED_BOTH) != 0);
        sendPanel.savePreferences(prefs);
        receivePanel.savePreferences(prefs);
    }

    private void restoreWindowState() {
        Preferences prefs = Preferences.userNodeForPackage(MainFrame.class);
        int x = prefs.getInt("window_x", Integer.MIN_VALUE);
        if (x == Integer.MIN_VALUE) {
            setSize(1100, 750);
            setLocationRelativeTo(null);
            sendPanel.restorePreferences(prefs);
            receivePanel.restorePreferences(prefs);
            return;
        }
        int y = prefs.getInt("window_y", 0);
        int w = prefs.getInt("window_width", 1100);
        int h = prefs.getInt("window_height", 750);

        Dimension min = getMinimumSize();
        w = Math.max(w, min.width);
        h = Math.max(h, min.height);

        Rectangle savedRect = new Rectangle(x, y, w, h);
        GraphicsEnvironment env = GraphicsEnvironment.getLocalGraphicsEnvironment();
        boolean onScreen = false;
        for (GraphicsDevice device : env.getScreenDevices()) {
            for (GraphicsConfiguration config : device.getConfigurations()) {
                if (config.getBounds().intersects(savedRect)) {
                    onScreen = true;
                    break;
                }
            }
            if (onScreen) break;
        }

        if (onScreen) {
            setBounds(x, y, w, h);
        } else {
            setSize(w, h);
            setLocationRelativeTo(null);
        }

        if (prefs.getBoolean("window_maximized", false)) {
            setExtendedState(getExtendedState() | Frame.MAXIMIZED_BOTH);
        }
        sendPanel.restorePreferences(prefs);
        receivePanel.restorePreferences(prefs);
    }
}

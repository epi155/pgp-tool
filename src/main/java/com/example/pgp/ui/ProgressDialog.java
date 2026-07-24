package com.example.pgp.ui;

import com.example.pgp.service.ProgressCallback;

import javax.swing.*;
import java.awt.*;

public class ProgressDialog extends JDialog implements ProgressCallback {

    private final JProgressBar progressBar;
    private final JLabel statusLabel;

    public ProgressDialog(Frame owner, String title) {
        super(owner, title, true);
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        setLayout(new BorderLayout(10, 10));
        setSize(350, 120);
        setLocationRelativeTo(owner);

        statusLabel = new JLabel(" ");
        statusLabel.setHorizontalAlignment(SwingConstants.CENTER);
        add(statusLabel, BorderLayout.NORTH);

        progressBar = new JProgressBar(0, 100);
        progressBar.setValue(0);
        progressBar.setStringPainted(true);
        add(progressBar, BorderLayout.CENTER);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        add(btnPanel, BorderLayout.SOUTH);

        getRootPane().setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
    }

    @Override
    public void onProgress(int percent, String status) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setValue(Math.min(percent, 100));
            if (status != null) statusLabel.setText(status);
        });
    }
}

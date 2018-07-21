package swing;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.Timer;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

public class ProgressBar implements ActionListener, ChangeListener {

    JFrame frame = null;
    JProgressBar progressbar;
    JLabel label;
    Timer timer;
    JButton b;

    

    
    public ProgressBar() {
        frame = new JFrame("Intrusion Detection System");
        frame.setBounds(100, 100, 400, 130);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        Container contentPanel = frame.getContentPane();
        label = new JLabel("", JLabel.CENTER);
        progressbar = new JProgressBar();
        progressbar.setOrientation(JProgressBar.HORIZONTAL);
        progressbar.setMinimum(0);
        progressbar.setMaximum(100);
        progressbar.setValue(0);
        progressbar.setStringPainted(true);
        progressbar.addChangeListener(this);
        progressbar.setPreferredSize(new Dimension(300, 20));
        progressbar.setBorderPainted(true);
        progressbar.setBackground(Color.white);

        JPanel panel = new JPanel();
        b = new JButton("Open System");
        b.setForeground(Color.blue);
        b.addActionListener(this);
        panel.add(b);
        timer = new Timer(100, this);
        contentPanel.add(panel, BorderLayout.NORTH);
        contentPanel.add(progressbar, BorderLayout.CENTER);
        contentPanel.add(label, BorderLayout.SOUTH);
        //frame.pack();
        frame.setVisible(true);

    }

    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == b) {
            timer.start();
        }
        if (e.getSource() == timer) {
            int value = progressbar.getValue();
            if (value < 100) {
                progressbar.setValue(++value);
            } else {
                timer.stop();
                frame.dispose();
            }
        }

    }

    public void stateChanged(ChangeEvent e1) {
        int value = progressbar.getValue();
        if (e1.getSource() == progressbar) {
            label.setText("Now the Progress is " + Integer.toString(value) + "%");
                //        
//        jTextArea2.append(Home.timeStamp + " Program Actived");
//        jTextArea2.append(Home.timeStamp + " Initializing System Components");
//        initComponents();
//        jTextArea2.append(Home.timeStamp + " Initializing Intrusion Detection System");
//        initIDS();
//        jTextArea2.append(Home.timeStamp + " Intrusion Detection System Initialized");
//        jTextArea2.append(timeStamp + " Initializing Rule Configuration Panel");
//        initRuleConfiguration();
//        jTextArea2.append(timeStamp + " Rule Configuration Panel Initialized");
//        jTextArea2.append(timeStamp + " Initializing System Logs");
//        intAlerts();
//        jTextArea2.append(timeStamp + " System Logs Initialized");
//        jTextArea2.append(timeStamp + " Initializing other Components");
            label.setForeground(Color.blue);
        }

    }

    public static void main(String[] args) {
        ProgressBar app = new ProgressBar();
    }

}

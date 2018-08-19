package swing;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author Du
 */
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JProgressBar;
import javax.swing.JRootPane;
import javax.swing.SwingConstants;
import javax.swing.Timer;

public class ProgressBar {

    Timer timer;
    JProgressBar jpbFileLoading;

    public ProgressBar() {
        JFrame jf = new JFrame("Progress Bar");
        /**
         * Create a Progress bar, the direction is horilzation,min value is
         * 0,max value is 100,the default value is 0
         */
        jpbFileLoading = new JProgressBar();
        jpbFileLoading.setStringPainted(true);  //Set the progress bar style,the default value is false  
        jpbFileLoading.setBorderPainted(false); 
        jpbFileLoading.setPreferredSize(new Dimension(100, 40)); //设置首选大小  
        timer = new Timer(50, new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                int loadingValue = jpbFileLoading.getValue();
                if (loadingValue < 100) {
                    jpbFileLoading.setValue(++loadingValue);
                    
                } else {
                    timer.stop();
                }
                
            }
        });
        timer.start();
        
        JProgressBar jpbFileLoadingIndeterminate = new JProgressBar();
        jpbFileLoadingIndeterminate.setIndeterminate(true); //设置进度条为不确定模式,默认为确定模式  
        jpbFileLoadingIndeterminate.setStringPainted(true);
        jpbFileLoadingIndeterminate.setPreferredSize(new Dimension(100, 40)); 
        jpbFileLoadingIndeterminate.setString("System Loading......");
        
        JLabel InLoadingText = new JLabel("Initializing System Componements");
        InLoadingText.setHorizontalAlignment(SwingConstants.CENTER);
	InLoadingText.setFont(new Font("Tahoma", Font.PLAIN, 24));
	InLoadingText.setForeground(new Color(0, 0, 0));
        InLoadingText.setBounds(20, 100, 300, 200);
                
        jf.add(jpbFileLoading, BorderLayout.NORTH);
        jf.add(InLoadingText);
        jf.add(jpbFileLoadingIndeterminate, BorderLayout.SOUTH);
        jf.setSize(500, 300);
        jf.setLocationRelativeTo(null); //居中显示  
        jf.setUndecorated(true);        //禁用此窗体的装饰  
        jf.getRootPane().setWindowDecorationStyle(JRootPane.NONE); //采用指定的窗体装饰风格  
        jf.setVisible(true);
        
        
        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        jpbFileLoadingIndeterminate.setIndeterminate(false); //设置进度条为确定模式,即常规模式,否则那个条还会走来走去  
        jpbFileLoadingIndeterminate.setString("Finish System Loading..");
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
     
        jf.setVisible(false); 
        jf.dispose();        
        jf = null;            
    }

    public static void main(String[] args) {
        new ProgressBar();
    }
}

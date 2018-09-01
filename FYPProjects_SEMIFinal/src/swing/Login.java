package swing;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import java.awt.Color;
import java.awt.Button;
import javax.swing.JTextField;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.SwingConstants;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionAdapter;
import javax.swing.ImageIcon;

public class Login extends JFrame {

    private final JPanel contentPane;
    private final JTextField textField;
    private final JPasswordField passwordField;

    int xx, xy;

    /**
     * Launch the application.
     */
    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    Login frame = new Login();
                    frame.setUndecorated(true);
                    frame.setVisible(true);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    // going to borrow code from a gist to move frame.
    /**
     * Create the frame.
     */
    public Login() {
        setBackground(Color.WHITE);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setBounds(600, 320, 729, 476);
        contentPane = new JPanel();
        contentPane.setBackground(Color.WHITE);
        contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        setContentPane(contentPane);
        contentPane.setLayout(null);

        JPanel panel = new JPanel();
        panel.setBackground(Color.DARK_GRAY);
        panel.setBounds(0, 0, 346, 490);
        contentPane.add(panel);
        panel.setLayout(null);

        JLabel lblNewLabel = new JLabel("Student Name       : Du Mengyu\n");
        JLabel lblNewLabel2 = new JLabel("Student ID            : R00158148");
        JLabel lblNewLabel3 = new JLabel("Supervisor Name   : Mary Davin");
        JLabel lblNewLabel4 = new JLabel("Presentation Date : 05 Sept 2018");
        lblNewLabel.setHorizontalAlignment(SwingConstants.LEFT);
        lblNewLabel.setFont(new Font("Tahoma", Font.PLAIN, 20));
        lblNewLabel.setForeground(new Color(240, 248, 255));
        lblNewLabel.setBounds(20, 130, 300, 200);

        lblNewLabel2.setHorizontalAlignment(SwingConstants.LEFT);
        lblNewLabel2.setFont(new Font("Tahoma", Font.PLAIN, 20));
        lblNewLabel2.setForeground(new Color(240, 248, 255));
        lblNewLabel2.setBounds(20, 180, 300, 200);

        lblNewLabel3.setHorizontalAlignment(SwingConstants.LEFT);
        lblNewLabel3.setFont(new Font("Tahoma", Font.PLAIN, 20));
        lblNewLabel3.setForeground(new Color(240, 248, 255));
        lblNewLabel3.setBounds(20, 230, 300, 200);

        lblNewLabel4.setHorizontalAlignment(SwingConstants.LEFT);
        lblNewLabel4.setFont(new Font("Tahoma", Font.PLAIN, 20));
        lblNewLabel4.setForeground(new Color(240, 248, 255));
        lblNewLabel4.setBounds(20, 280, 300, 200);

        panel.add(lblNewLabel);
        panel.add(lblNewLabel2);
        panel.add(lblNewLabel3);
        panel.add(lblNewLabel4);
        JLabel label = new JLabel("");

        label.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {

                xx = e.getX();
                xy = e.getY();
            }
        });
        label.addMouseMotionListener(new MouseMotionAdapter() {
            @Override
            public void mouseDragged(MouseEvent arg0) {

                int x = arg0.getXOnScreen();
                int y = arg0.getYOnScreen();
                Login.this.setLocation(x - xx, y - xy);
            }
        });
        label.setBounds(0, 0, 420, 275);
        label.setVerticalAlignment(SwingConstants.TOP);
        label.setIcon(new ImageIcon(Login.class.getResource("/GUI/images/CIT_red.jpg")));
        panel.add(label);

//		JLabel lblWeGotYou = new JLabel("Aaaaaaa");
//		lblWeGotYou.setHorizontalAlignment(SwingConstants.CENTER);
//		lblWeGotYou.setForeground(new Color(240, 248, 255));
//		lblWeGotYou.setFont(new Font("Tahoma", Font.PLAIN, 20));
//		lblWeGotYou.setBounds(111, 360, 141, 27);
//		panel.add(lblWeGotYou);
        Button button = new Button("Login");
        button.setForeground(Color.WHITE);
        button.setFont(new Font("Tahoma", Font.PLAIN, 20));
        button.setBackground(new Color(241, 57, 83));
        button.setBounds(395, 390, 283, 36);
        contentPane.add(button);

        textField = new JTextField();
        textField.setBounds(395, 200, 283, 36);
        textField.setFont(new Font("Tahoma", Font.PLAIN, 20));
        contentPane.add(textField);
        textField.setColumns(10);

        JLabel SystemName = new JLabel("Intrusion Detection System");
        SystemName.setBounds(360, 50, 400, 50);
        SystemName.setFont(new Font("Tahoma", Font.PLAIN, 28));
        contentPane.add(SystemName);

        JLabel lblUsername = new JLabel("USERNAME");
        lblUsername.setBounds(395, 170, 180, 14);
        lblUsername.setFont(new Font("Tahoma", Font.PLAIN, 20));
        contentPane.add(lblUsername);

        JLabel lblPassword = new JLabel("PASSWORD");
        lblPassword.setBounds(395, 280, 180, 14);
        lblPassword.setFont(new Font("Tahoma", Font.PLAIN, 20));
        contentPane.add(lblPassword);

        passwordField = new JPasswordField();
        passwordField.setBounds(395, 310, 283, 36);
        passwordField.setFont(new Font("Tahoma", Font.PLAIN, 20));
        contentPane.add(passwordField);

        JLabel lbl_close = new JLabel("X");
        lbl_close.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent arg0) {

                System.exit(0);
            }
        });
        lbl_close.setHorizontalAlignment(SwingConstants.CENTER);
        lbl_close.setForeground(new Color(241, 57, 83));
        lbl_close.setFont(new Font("Tahoma", Font.PLAIN, 18));
        lbl_close.setBounds(691, 0, 37, 27);
        contentPane.add(lbl_close);
    }
}

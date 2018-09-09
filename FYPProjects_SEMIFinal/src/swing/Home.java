package swing;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import static java.lang.Integer.parseInt;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.RowFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import jpcap.PacketReceiver;
import jpcap.packet.ICMPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;
import javax.swing.table.TableRowSorter;
import java.util.Date;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.plot.PiePlot;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DefaultPieDataset;

/**
 *
 * @author Du
 */
public class Home extends javax.swing.JFrame {

    /**
     *
     */
    private static final long serialVersionUID = 422802721085702265L;

    boolean flag = false;

    private static final String RULEFILENAME = "C:\\Users\\du\\Desktop\\IDS\\Java_Intrusion-Detection-System-master\\"
            + "FYPProjects_SEMIFinal\\TempDB\\RuleText.txt";

    NetworkInterface[] devices;
    static ArrayList<Packet> packetlist = new ArrayList<Packet>();
    static DefaultTableModel packetTableModel;
    static DefaultTableModel tablemodelRule;

    JTable tabledisplay = null;
    JTable tabledisplayRules = null;

    static String FilterMess = "";
    JLabel statusLabel;
    JpcapCaptor jpcap = null;
    private Thread captureThread;
    Vector rows, columns;
    Vector RuleRows, RuleColumns;
    public static TCPPacket tcp;
    public static UDPPacket udp;
    public static ICMPPacket icmp;
    int IPCounter = 0;
    int a = 0;
    int count = 0;
    static int ctcp = 0;
    static int cudp = 0;
    static int cicmp = 0;
    static int cBlockedAttck = 0;
    static int cHighAttck = 0;
    static int cMediumAttck = 0;
    static int cLowAttck = 0;
    static int nRules = 0;
    static double dtcp = 0;
    static double dudp = 0;
    static double dicmp = 0;
    static double darp = 0;
    static int No = 0;
    static int RuleNo = 0;
    // email
    static Properties mailServerProperties;
    static Session getMailSession;
    static MimeMessage generateMailMessage;

    List<String> srcIPSet = new ArrayList<>();
    List<String> destIPSet = new ArrayList<>();
    List<String> UnknownIPSet = new ArrayList<>();
    List<String> AllIPSet = new ArrayList<>();
    List<String> srcIPSetTemp = new ArrayList<>();
    List<String> ProtocolSet = new ArrayList<>();
    List<String> srcPortSet = new ArrayList<>();
    List<String> destPortSet = new ArrayList<>();
    List<String> AllPortSet = new ArrayList<>();

    List<String> RuleNameSet = new ArrayList<>();
    List<String> RuleIPSet = new ArrayList<>();
    List<String> RuleIPSetCompare = new ArrayList<>();
    List<String> RulePortSet = new ArrayList<>();
    List<String> RuleAttempts = new ArrayList<>();
    List<String> RuleDescription = new ArrayList<>();
    List<String> RuleStatus = new ArrayList<>();

    List<String> RuleNameSet2 = new ArrayList<>();
    List<String> RulePortSet2 = new ArrayList<>();
    List<String> RuleStatus2 = new ArrayList<>();

    List<String> RuleNameSet3 = new ArrayList<>();
    List<String> RulePortSet3 = new ArrayList<>();
    List<String> RuleStatus3 = new ArrayList<>();

    List<String> RuleNameSet4 = new ArrayList<>();
    List<String> RuleStatus4 = new ArrayList<>();

    String timeStamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
    DefaultComboBoxModel model1 = new DefaultComboBoxModel();

    private JPanel jPanel91;
    private JPanel jPanel92;
    DefaultPieDataset dataset = new DefaultPieDataset();
    JFreeChart pieChart = ChartFactory.createPieChart("Packets Count", dataset, rootPaneCheckingEnabled,
            rootPaneCheckingEnabled, rootPaneCheckingEnabled);

    DefaultCategoryDataset dataset1 = new DefaultCategoryDataset();
    JFreeChart barChart1 = ChartFactory.createBarChart("Data Traffic Count", "Packet Data Type", "Data(KB)", dataset1,
            PlotOrientation.HORIZONTAL, true, true, false);

    public Home() {
        initComponents();
        initIDS();
        initRuleConfiguration();
        setColor(btn_1);
        ind_1.setOpaque(true);
        resetColor(new JPanel[]{btn_2, btn_3, btn_4}, new JPanel[]{ind_2, ind_3, ind_4});
        IDS.setVisible(false);
        RuleConfig.setVisible(false);
        Home.setVisible(true);
        Alerts.setVisible(false);
        jTextArea2.append(timeStamp + " ---> Program Actived\n");
        jTextArea2.append(timeStamp + " ---> Intrusion Detection System Initialized\n");
        jTextArea2.append(timeStamp + " ---> Initializing Rule Configuration Panel\n");
        jTextArea2.append(timeStamp + " ---> Rule Configuration Panel Initialized\n");
        jTextArea2.append(timeStamp + " ---> System Logs Initialized\n");
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated
	// Code">//GEN-BEGIN:initComponents
	private void initComponents() {

		jFrame1 = new javax.swing.JFrame();
		side_pane = new javax.swing.JPanel();
		btn_1 = new javax.swing.JPanel();
		ind_1 = new javax.swing.JPanel();
		HomeBtn = new javax.swing.JLabel();
		btn_2 = new javax.swing.JPanel();
		ind_2 = new javax.swing.JPanel();
		jLabel9 = new javax.swing.JLabel();
		btn_3 = new javax.swing.JPanel();
		ind_3 = new javax.swing.JPanel();
		jLabel10 = new javax.swing.JLabel();
		btn_4 = new javax.swing.JPanel();
		ind_4 = new javax.swing.JPanel();
		jLabel11 = new javax.swing.JLabel();
		Home = new javax.swing.JPanel();
		jPanel8 = new javax.swing.JPanel();
		jTextField2 = new javax.swing.JTextField();
		jLabel8 = new javax.swing.JLabel();
		jPanel9 = new javax.swing.JPanel();
		jPanel1 = new javax.swing.JPanel();
		button2 = new javax.swing.JButton();
		jLabel22 = new javax.swing.JLabel();
		jLabel23 = new javax.swing.JLabel();
		jScrollPane5 = new javax.swing.JScrollPane();
		jTextArea4 = new javax.swing.JTextArea();
		jPanel32 = new javax.swing.JPanel();
		btn_exit5 = new javax.swing.JLabel();
		jLabel42 = new javax.swing.JLabel();
		jPanel41 = new javax.swing.JPanel();
		jLabel43 = new javax.swing.JLabel();
		jLabel44 = new javax.swing.JLabel();
		jLabel45 = new javax.swing.JLabel();
		jSeparator6 = new javax.swing.JSeparator();
		jLabel47 = new javax.swing.JLabel();
		jPanel12 = new javax.swing.JPanel();
		jPanel13 = new javax.swing.JPanel();
		jLabel27 = new javax.swing.JLabel();
		jPanel26 = new javax.swing.JPanel();
		jLabel52 = new javax.swing.JLabel();
		jLabel53 = new javax.swing.JLabel();
		jPanel27 = new javax.swing.JPanel();
		jPanel28 = new javax.swing.JPanel();
		jLabel54 = new javax.swing.JLabel();
		jPanel29 = new javax.swing.JPanel();
		jLabel55 = new javax.swing.JLabel();
		jPanel30 = new javax.swing.JPanel();
		jLabel56 = new javax.swing.JLabel();
		jPanel31 = new javax.swing.JPanel();
		jLabel57 = new javax.swing.JLabel();
		jLabel1 = new javax.swing.JLabel();
		jPanel39 = new javax.swing.JPanel();
		jLabel59 = new javax.swing.JLabel();
		jPanel40 = new javax.swing.JPanel();
		jLabel61 = new javax.swing.JLabel();
		jLabel26 = new javax.swing.JLabel();
		jPanel6 = new javax.swing.JPanel();
		jScrollPane4 = new javax.swing.JScrollPane();
		jTextArea3 = new javax.swing.JTextArea();
		IDS = new javax.swing.JPanel();
		jPanel14 = new javax.swing.JPanel();
		jTextField3 = new javax.swing.JTextField();
		jLabel28 = new javax.swing.JLabel();
		jPanel15 = new javax.swing.JPanel();
		jPanel16 = new javax.swing.JPanel();
		jPanel17 = new javax.swing.JPanel();
		jLabel29 = new javax.swing.JLabel();
		jLabel30 = new javax.swing.JLabel();
		jLabel31 = new javax.swing.JLabel();
		jSeparator3 = new javax.swing.JSeparator();
		jLabel33 = new javax.swing.JLabel();
		btn_exit3 = new javax.swing.JLabel();
		jLabel48 = new javax.swing.JLabel();
		jPanel2 = new javax.swing.JPanel();
		WS_lists = new javax.swing.JComboBox<>();
		jScrollPane1 = new javax.swing.JScrollPane();
		WSProperty = new javax.swing.JTextArea();
		Load_Wireless_btn = new javax.swing.JButton();
		ScanNet = new javax.swing.JButton();
		jComboBox1 = new javax.swing.JComboBox<>();
		FilterPackets = new javax.swing.JButton();
		jLabel2 = new javax.swing.JLabel();
		jLabel14 = new javax.swing.JLabel();
		jComboBox5 = new javax.swing.JComboBox<>();
		jLabel15 = new javax.swing.JLabel();
		jComboBox6 = new javax.swing.JComboBox<>();
		ResetBtn = new javax.swing.JButton();
		jPanel18 = new javax.swing.JPanel();
		jPanel19 = new javax.swing.JPanel();
		jLabel39 = new javax.swing.JLabel();
		jPanel33 = new javax.swing.JPanel();
		ICMP_num = new javax.swing.JLabel();
		jLabel60 = new javax.swing.JLabel();
		jPanel34 = new javax.swing.JPanel();
		jPanel35 = new javax.swing.JPanel();
		tcp_num = new javax.swing.JLabel();
		jPanel36 = new javax.swing.JPanel();
		jLabel62 = new javax.swing.JLabel();
		jPanel37 = new javax.swing.JPanel();
		UDP_num = new javax.swing.JLabel();
		jPanel38 = new javax.swing.JPanel();
		jLabel64 = new javax.swing.JLabel();
		jScrollPane3 = new javax.swing.JScrollPane();
		jTextArea1 = new javax.swing.JTextArea();
		jPanel43 = new javax.swing.JPanel();
		Block_Num = new javax.swing.JLabel();
		jLabel65 = new javax.swing.JLabel();
		jPanel44 = new javax.swing.JPanel();
		jPanel3 = new javax.swing.JPanel();
		RuleConfig = new javax.swing.JPanel();
		jPanel20 = new javax.swing.JPanel();
		jTextField4 = new javax.swing.JTextField();
		jLabel40 = new javax.swing.JLabel();
		jPanel21 = new javax.swing.JPanel();
		jPanel5 = new javax.swing.JPanel();
		jLabel17 = new javax.swing.JLabel();
		jComboBox7 = new javax.swing.JComboBox<>();
		jLabel18 = new javax.swing.JLabel();
		jLabel19 = new javax.swing.JLabel();
		jLabel20 = new javax.swing.JLabel();
		jLabel21 = new javax.swing.JLabel();
		jComboBox8 = new javax.swing.JComboBox<>();
		jComboBox9 = new javax.swing.JComboBox<>();
		jComboBox10 = new javax.swing.JComboBox<>();
		jComboBox11 = new javax.swing.JComboBox<>();
		jButton1 = new javax.swing.JButton();
		jCheckBox1 = new javax.swing.JCheckBox();
		jTextField9 = new javax.swing.JTextField();
		ResetRuleBtn = new javax.swing.JButton();
		jPanel22 = new javax.swing.JPanel();
		jPanel23 = new javax.swing.JPanel();
		jLabel32 = new javax.swing.JLabel();
		jLabel34 = new javax.swing.JLabel();
		jLabel35 = new javax.swing.JLabel();
		jSeparator4 = new javax.swing.JSeparator();
		jLabel36 = new javax.swing.JLabel();
		btn_exit4 = new javax.swing.JLabel();
		jLabel49 = new javax.swing.JLabel();
		jPanel24 = new javax.swing.JPanel();
		jPanel25 = new javax.swing.JPanel();
		jLabel3 = new javax.swing.JLabel();
		jTextField1 = new javax.swing.JTextField();
		jLabel4 = new javax.swing.JLabel();
		jComboBox2 = new javax.swing.JComboBox<>();
		jButton2 = new javax.swing.JButton();
		jComboBox4 = new javax.swing.JComboBox<>();
		jLabel5 = new javax.swing.JLabel();
		jLabel6 = new javax.swing.JLabel();
		jLabel7 = new javax.swing.JLabel();
		jComboBox3 = new javax.swing.JComboBox<>();
		jTextField5 = new javax.swing.JTextField();
		jLabel12 = new javax.swing.JLabel();
		jTextField6 = new javax.swing.JTextField();
		jLabel13 = new javax.swing.JLabel();
		jTextField7 = new javax.swing.JTextField();
		jButton3 = new javax.swing.JButton();
		jLabel16 = new javax.swing.JLabel();
		jTextField8 = new javax.swing.JTextField();
		DeleteRule = new javax.swing.JButton();
		jPanel4 = new javax.swing.JPanel();
		Alerts = new javax.swing.JPanel();
		jScrollPane2 = new javax.swing.JScrollPane();
		jTextArea2 = new javax.swing.JTextArea();

		javax.swing.GroupLayout jFrame1Layout = new javax.swing.GroupLayout(jFrame1.getContentPane());
		jFrame1.getContentPane().setLayout(jFrame1Layout);
		jFrame1Layout.setHorizontalGroup(jFrame1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 400, Short.MAX_VALUE));
		jFrame1Layout.setVerticalGroup(jFrame1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 300, Short.MAX_VALUE));

		setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
		setBackground(new java.awt.Color(255, 255, 255));
		setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
		setLocation(new java.awt.Point(75, 100));
		setMinimumSize(new java.awt.Dimension(1700, 800));
		setUndecorated(true);
		getContentPane().setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

		side_pane.setBackground(new java.awt.Color(23, 35, 51));
		side_pane.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
		side_pane.setMinimumSize(new java.awt.Dimension(120, 800));
		side_pane.setPreferredSize(new java.awt.Dimension(200, 800));
		side_pane.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

		btn_1.setBackground(new java.awt.Color(23, 35, 51));
		btn_1.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
		btn_1.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mousePressed(java.awt.event.MouseEvent evt) {
				btn_1MousePressed(evt);
			}
		});

		ind_1.setOpaque(false);
		ind_1.setPreferredSize(new java.awt.Dimension(3, 43));

		javax.swing.GroupLayout ind_1Layout = new javax.swing.GroupLayout(ind_1);
		ind_1.setLayout(ind_1Layout);
		ind_1Layout.setHorizontalGroup(ind_1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 0, Short.MAX_VALUE));
		ind_1Layout.setVerticalGroup(ind_1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 0, Short.MAX_VALUE));

		HomeBtn.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
		HomeBtn.setForeground(new java.awt.Color(255, 255, 255));
		HomeBtn.setText("Home");

		javax.swing.GroupLayout btn_1Layout = new javax.swing.GroupLayout(btn_1);
		btn_1.setLayout(btn_1Layout);
		btn_1Layout.setHorizontalGroup(btn_1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(btn_1Layout.createSequentialGroup()
						.addComponent(ind_1, javax.swing.GroupLayout.PREFERRED_SIZE, 0,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(38, 38, 38).addComponent(HomeBtn).addGap(0, 160, Short.MAX_VALUE)));
		btn_1Layout.setVerticalGroup(btn_1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(btn_1Layout.createSequentialGroup().addContainerGap()
						.addComponent(HomeBtn, javax.swing.GroupLayout.DEFAULT_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addContainerGap())
				.addComponent(ind_1, javax.swing.GroupLayout.DEFAULT_SIZE, 59, Short.MAX_VALUE));

		side_pane.add(btn_1, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 100, 260, -1));

		btn_2.setBackground(new java.awt.Color(23, 35, 51));
		btn_2.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
		btn_2.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mouseClicked(java.awt.event.MouseEvent evt) {
				btn_2MouseClicked(evt);
			}
		});

		ind_2.setOpaque(false);
		ind_2.setPreferredSize(new java.awt.Dimension(3, 43));

		javax.swing.GroupLayout ind_2Layout = new javax.swing.GroupLayout(ind_2);
		ind_2.setLayout(ind_2Layout);
		ind_2Layout.setHorizontalGroup(ind_2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 0, Short.MAX_VALUE));
		ind_2Layout.setVerticalGroup(ind_2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 0, Short.MAX_VALUE));

		jLabel9.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
		jLabel9.setForeground(new java.awt.Color(255, 255, 255));
		jLabel9.setText("SystemLogs");

		javax.swing.GroupLayout btn_2Layout = new javax.swing.GroupLayout(btn_2);
		btn_2.setLayout(btn_2Layout);
		btn_2Layout.setHorizontalGroup(btn_2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(btn_2Layout.createSequentialGroup()
						.addComponent(ind_2, javax.swing.GroupLayout.PREFERRED_SIZE, 0,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(38, 38, 38).addComponent(jLabel9).addGap(0, 96, Short.MAX_VALUE)));
		btn_2Layout.setVerticalGroup(btn_2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(btn_2Layout.createSequentialGroup().addContainerGap()
						.addComponent(jLabel9, javax.swing.GroupLayout.DEFAULT_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addContainerGap())
				.addComponent(ind_2, javax.swing.GroupLayout.DEFAULT_SIZE, 59, Short.MAX_VALUE));

		side_pane.add(btn_2, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 340, 260, -1));

		btn_3.setBackground(new java.awt.Color(23, 35, 51));
		btn_3.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
		btn_3.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mousePressed(java.awt.event.MouseEvent evt) {
				btn_3MousePressed(evt);
			}
		});

		ind_3.setOpaque(false);
		ind_3.setPreferredSize(new java.awt.Dimension(3, 43));

		javax.swing.GroupLayout ind_3Layout = new javax.swing.GroupLayout(ind_3);
		ind_3.setLayout(ind_3Layout);
		ind_3Layout.setHorizontalGroup(ind_3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 0, Short.MAX_VALUE));
		ind_3Layout.setVerticalGroup(ind_3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 0, Short.MAX_VALUE));

		jLabel10.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
		jLabel10.setForeground(new java.awt.Color(255, 255, 255));
		jLabel10.setText("Introsion Deteciton");

		javax.swing.GroupLayout btn_3Layout = new javax.swing.GroupLayout(btn_3);
		btn_3.setLayout(btn_3Layout);
		btn_3Layout.setHorizontalGroup(btn_3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(btn_3Layout.createSequentialGroup()
						.addComponent(ind_3, javax.swing.GroupLayout.PREFERRED_SIZE, 0,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(38, 38, 38).addComponent(jLabel10).addGap(0, 20, Short.MAX_VALUE)));
		btn_3Layout.setVerticalGroup(btn_3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(btn_3Layout.createSequentialGroup().addContainerGap()
						.addComponent(jLabel10, javax.swing.GroupLayout.DEFAULT_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addContainerGap())
				.addComponent(ind_3, javax.swing.GroupLayout.DEFAULT_SIZE, 70, Short.MAX_VALUE));

		side_pane.add(btn_3, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 180, 260, -1));

		btn_4.setBackground(new java.awt.Color(23, 35, 51));
		btn_4.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
		btn_4.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mousePressed(java.awt.event.MouseEvent evt) {
				btn_4MousePressed(evt);
			}
		});

		ind_4.setOpaque(false);
		ind_4.setPreferredSize(new java.awt.Dimension(3, 43));

		javax.swing.GroupLayout ind_4Layout = new javax.swing.GroupLayout(ind_4);
		ind_4.setLayout(ind_4Layout);
		ind_4Layout.setHorizontalGroup(ind_4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 0, Short.MAX_VALUE));
		ind_4Layout.setVerticalGroup(ind_4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 0, Short.MAX_VALUE));

		jLabel11.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
		jLabel11.setForeground(new java.awt.Color(255, 255, 255));
		jLabel11.setText("Rule");

		javax.swing.GroupLayout btn_4Layout = new javax.swing.GroupLayout(btn_4);
		btn_4.setLayout(btn_4Layout);
		btn_4Layout.setHorizontalGroup(btn_4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(btn_4Layout.createSequentialGroup()
						.addComponent(ind_4, javax.swing.GroupLayout.PREFERRED_SIZE, 0,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(38, 38, 38).addComponent(jLabel11).addGap(0, 176, Short.MAX_VALUE)));
		btn_4Layout.setVerticalGroup(btn_4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(btn_4Layout.createSequentialGroup().addContainerGap()
						.addComponent(jLabel11, javax.swing.GroupLayout.DEFAULT_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addContainerGap())
				.addComponent(ind_4, javax.swing.GroupLayout.DEFAULT_SIZE, 59, Short.MAX_VALUE));

		side_pane.add(btn_4, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 260, 260, -1));

		getContentPane().add(side_pane, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0, 260, 800));

		Home.setFont(new java.awt.Font("Tahoma", 0, 14)); // NOI18N
		Home.setPreferredSize(new java.awt.Dimension(1480, 800));

		jPanel8.setBackground(new java.awt.Color(71, 120, 197));
		jPanel8.addMouseMotionListener(new java.awt.event.MouseMotionAdapter() {
			public void mouseDragged(java.awt.event.MouseEvent evt) {
				jPanel8MouseDragged(evt);
			}
		});
		jPanel8.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mousePressed(java.awt.event.MouseEvent evt) {
				jPanel8MousePressed(evt);
			}
		});

		jTextField2.setBackground(new java.awt.Color(123, 156, 225));
		jTextField2.setForeground(new java.awt.Color(255, 255, 255));
		jTextField2.setBorder(null);
		jTextField2.setCaretColor(new java.awt.Color(255, 255, 255));
		jTextField2.setPreferredSize(new java.awt.Dimension(2, 20));

		jLabel8.setIcon(new javax.swing.ImageIcon(getClass().getResource("/GUI/images/icons8_Search_18px.png"))); // NOI18N

		javax.swing.GroupLayout jPanel8Layout = new javax.swing.GroupLayout(jPanel8);
		jPanel8.setLayout(jPanel8Layout);
		jPanel8Layout.setHorizontalGroup(jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
						jPanel8Layout.createSequentialGroup().addContainerGap(1277, Short.MAX_VALUE)
								.addComponent(jTextField2, javax.swing.GroupLayout.PREFERRED_SIZE, 141,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
								.addComponent(jLabel8).addGap(34, 34, 34)));
		jPanel8Layout.setVerticalGroup(jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel8Layout.createSequentialGroup()
						.addContainerGap(17, Short.MAX_VALUE)
						.addGroup(jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
								.addComponent(jLabel8, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jTextField2, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
						.addContainerGap()));

		jPanel9.setBackground(new java.awt.Color(71, 120, 197));
		jPanel9.setPreferredSize(new java.awt.Dimension(301, 750));

		button2.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		button2.setText("Initialize Graphic");
		button2.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mouseClicked(java.awt.event.MouseEvent evt) {
				button2MouseClicked(evt);
			}
		});

		jLabel22.setFont(new java.awt.Font("Tahoma", 1, 20)); // NOI18N
		jLabel22.setText("Activated Rules");

		jLabel23.setFont(new java.awt.Font("Tahoma", 1, 20)); // NOI18N
		jLabel23.setText("System Alerts");

		jTextArea4.setEditable(false);
		jTextArea4.setColumns(20);
		jTextArea4.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		jTextArea4.setRows(5);
		jTextArea4.setOpaque(false);
		jScrollPane5.setViewportView(jTextArea4);

		javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
		jPanel1.setLayout(jPanel1Layout);
		jPanel1Layout.setHorizontalGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel1Layout.createSequentialGroup().addGroup(jPanel1Layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(
										jPanel1Layout.createSequentialGroup().addGap(75, 75, 75).addComponent(button2))
								.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
										jPanel1Layout.createSequentialGroup().addContainerGap()
												.addGroup(jPanel1Layout
														.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
														.addComponent(jLabel22, javax.swing.GroupLayout.PREFERRED_SIZE,
																158, javax.swing.GroupLayout.PREFERRED_SIZE)
														.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
																jPanel1Layout.createSequentialGroup()
																		.addComponent(jLabel23).addGap(19, 19, 19)))))
						.addGroup(jPanel1Layout.createSequentialGroup().addContainerGap().addComponent(jScrollPane5,
								javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
								javax.swing.GroupLayout.PREFERRED_SIZE)))
						.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));
		jPanel1Layout
				.setVerticalGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
								jPanel1Layout.createSequentialGroup().addGap(25, 25, 25).addComponent(button2)
										.addGap(41, 41, 41).addComponent(jLabel23).addGap(226, 226, 226)
										.addComponent(jLabel22).addGap(18, 18, 18).addComponent(jScrollPane5,
												javax.swing.GroupLayout.DEFAULT_SIZE, 176, Short.MAX_VALUE)
										.addContainerGap()));

		jPanel32.setBackground(new java.awt.Color(120, 168, 252));
		jPanel32.setPreferredSize(new java.awt.Dimension(301, 165));
		jPanel32.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

		btn_exit5.setIcon(new javax.swing.ImageIcon(getClass().getResource("/GUI/images/icons8_Exit_25px.png"))); // NOI18N
		btn_exit5.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mousePressed(java.awt.event.MouseEvent evt) {
				btn_exit5MousePressed(evt);
			}
		});
		jPanel32.add(btn_exit5, new org.netbeans.lib.awtextra.AbsoluteConstraints(260, 20, -1, 46));

		jLabel42.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
		jLabel42.setForeground(new java.awt.Color(255, 255, 255));
		jLabel42.setText("System Administator");
		jPanel32.add(jLabel42, new org.netbeans.lib.awtextra.AbsoluteConstraints(20, 30, -1, 30));

		jPanel41.setBackground(new java.awt.Color(84, 127, 206));

		jLabel43.setIcon(new javax.swing.ImageIcon(getClass().getResource("/GUI/images/icons8_Contacts_25px.png"))); // NOI18N

		jLabel44.setIcon(new javax.swing.ImageIcon(getClass().getResource("/GUI/images/icons8_Calendar_25px.png"))); // NOI18N

		jLabel45.setIcon(new javax.swing.ImageIcon(getClass().getResource("/GUI/images/icons8_Lock_25px.png"))); // NOI18N

		jLabel47.setIcon(
				new javax.swing.ImageIcon(getClass().getResource("/GUI/images/icons8_Secured_Letter_25px_2.png"))); // NOI18N

		javax.swing.GroupLayout jPanel41Layout = new javax.swing.GroupLayout(jPanel41);
		jPanel41.setLayout(jPanel41Layout);
		jPanel41Layout.setHorizontalGroup(jPanel41Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
						jPanel41Layout.createSequentialGroup().addGap(39, 39, 39).addComponent(jLabel47)
								.addGap(28, 28, 28).addComponent(jLabel43).addGap(45, 45, 45).addComponent(jLabel44)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 49,
										Short.MAX_VALUE)
								.addComponent(jLabel45).addGap(40, 40, 40))
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel41Layout.createSequentialGroup()
						.addContainerGap().addComponent(jSeparator6).addContainerGap()));
		jPanel41Layout.setVerticalGroup(jPanel41Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel41Layout.createSequentialGroup().addGap(32, 32, 32)
						.addGroup(jPanel41Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
								.addComponent(jLabel45, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jLabel44, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jLabel43, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jLabel47, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED).addComponent(jSeparator6,
								javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(0, 0, Short.MAX_VALUE)));

		jPanel32.add(jPanel41, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 85, -1, 80));

		javax.swing.GroupLayout jPanel9Layout = new javax.swing.GroupLayout(jPanel9);
		jPanel9.setLayout(jPanel9Layout);
		jPanel9Layout.setHorizontalGroup(jPanel9Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE)
				.addComponent(jPanel32, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE));
		jPanel9Layout.setVerticalGroup(jPanel9Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
						jPanel9Layout.createSequentialGroup()
								.addComponent(jPanel32, javax.swing.GroupLayout.PREFERRED_SIZE, 165,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
								.addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));

		jPanel12.setBackground(new java.awt.Color(255, 255, 255));
		jPanel12.setPreferredSize(new java.awt.Dimension(891, 750));

		jPanel13.setBackground(new java.awt.Color(242, 247, 247));

		jLabel27.setFont(new java.awt.Font("Tahoma", 0, 36)); // NOI18N
		jLabel27.setForeground(new java.awt.Color(102, 102, 102));
		jLabel27.setText("Dashboard");

		jPanel26.setBackground(new java.awt.Color(255, 255, 255));
		jPanel26.setForeground(new java.awt.Color(153, 0, 0));
		jPanel26.setPreferredSize(new java.awt.Dimension(150, 60));

		jLabel52.setFont(new java.awt.Font("Tahoma", 1, 36)); // NOI18N
		jLabel52.setForeground(new java.awt.Color(96, 83, 150));
		jLabel52.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
		jLabel52.setText("0");

		jLabel53.setFont(new java.awt.Font("Tahoma", 0, 20)); // NOI18N
		jLabel53.setForeground(new java.awt.Color(96, 83, 150));
		jLabel53.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
		jLabel53.setText("High Serverity Events");

		jPanel27.setBackground(new java.awt.Color(204, 0, 0));

		javax.swing.GroupLayout jPanel27Layout = new javax.swing.GroupLayout(jPanel27);
		jPanel27.setLayout(jPanel27Layout);
		jPanel27Layout.setHorizontalGroup(jPanel27Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 0, Short.MAX_VALUE));
		jPanel27Layout.setVerticalGroup(jPanel27Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 10, Short.MAX_VALUE));

		javax.swing.GroupLayout jPanel26Layout = new javax.swing.GroupLayout(jPanel26);
		jPanel26.setLayout(jPanel26Layout);
		jPanel26Layout.setHorizontalGroup(jPanel26Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel26Layout.createSequentialGroup()
						.addComponent(jLabel53, javax.swing.GroupLayout.PREFERRED_SIZE, 286,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(0, 0, Short.MAX_VALUE))
				.addComponent(jLabel52, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE)
				.addComponent(jPanel27, javax.swing.GroupLayout.Alignment.TRAILING,
						javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE));
		jPanel26Layout.setVerticalGroup(jPanel26Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel26Layout.createSequentialGroup()
						.addComponent(jPanel27, javax.swing.GroupLayout.PREFERRED_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(11, 11, 11)
						.addComponent(jLabel52, javax.swing.GroupLayout.PREFERRED_SIZE, 39,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).addComponent(jLabel53,
								javax.swing.GroupLayout.PREFERRED_SIZE, 39, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addContainerGap()));

		jPanel28.setBackground(new java.awt.Color(255, 255, 255));
		jPanel28.setMinimumSize(new java.awt.Dimension(150, 60));
		jPanel28.setPreferredSize(new java.awt.Dimension(150, 60));
		jPanel28.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

		jLabel54.setFont(new java.awt.Font("Tahoma", 1, 36)); // NOI18N
		jLabel54.setForeground(new java.awt.Color(96, 83, 150));
		jLabel54.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
		jLabel54.setText("0");
		jPanel28.add(jLabel54, new org.netbeans.lib.awtextra.AbsoluteConstraints(2, 22, 280, -1));

		jPanel29.setBackground(new java.awt.Color(255, 102, 0));

		javax.swing.GroupLayout jPanel29Layout = new javax.swing.GroupLayout(jPanel29);
		jPanel29.setLayout(jPanel29Layout);
		jPanel29Layout.setHorizontalGroup(jPanel29Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 290, Short.MAX_VALUE));
		jPanel29Layout.setVerticalGroup(jPanel29Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 10, Short.MAX_VALUE));

		jPanel28.add(jPanel29, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0, 290, 10));

		jLabel55.setFont(new java.awt.Font("Tahoma", 0, 20)); // NOI18N
		jLabel55.setForeground(new java.awt.Color(96, 83, 150));
		jLabel55.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
		jLabel55.setText("Medium Serverity Events");
		jPanel28.add(jLabel55, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 70, 300, 30));

		jPanel30.setBackground(new java.awt.Color(255, 255, 255));
		jPanel30.setMinimumSize(new java.awt.Dimension(150, 60));
		jPanel30.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

		jLabel56.setFont(new java.awt.Font("Tahoma", 1, 36)); // NOI18N
		jLabel56.setForeground(new java.awt.Color(96, 83, 150));
		jLabel56.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
		jLabel56.setText("0");
		jPanel30.add(jLabel56, new org.netbeans.lib.awtextra.AbsoluteConstraints(4, 21, 260, -1));

		jPanel31.setBackground(new java.awt.Color(0, 204, 51));

		javax.swing.GroupLayout jPanel31Layout = new javax.swing.GroupLayout(jPanel31);
		jPanel31.setLayout(jPanel31Layout);
		jPanel31Layout.setHorizontalGroup(jPanel31Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 290, Short.MAX_VALUE));
		jPanel31Layout.setVerticalGroup(jPanel31Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 10, Short.MAX_VALUE));

		jPanel30.add(jPanel31, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0, 290, 10));

		jLabel57.setFont(new java.awt.Font("Tahoma", 0, 20)); // NOI18N
		jLabel57.setForeground(new java.awt.Color(96, 83, 150));
		jLabel57.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
		jLabel57.setText("Low Serverity Events");
		jPanel30.add(jLabel57, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 70, 270, 30));

		jLabel1.setText(
				"-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");

		jPanel39.setBackground(new java.awt.Color(255, 255, 255));
		jPanel39.setMinimumSize(new java.awt.Dimension(150, 60));
		jPanel39.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

		jLabel59.setFont(new java.awt.Font("Tahoma", 1, 36)); // NOI18N
		jLabel59.setForeground(new java.awt.Color(96, 83, 150));
		jLabel59.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
		jLabel59.setText("0");
		jPanel39.add(jLabel59, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 20, 260, -1));

		jPanel40.setBackground(new java.awt.Color(0, 51, 255));

		javax.swing.GroupLayout jPanel40Layout = new javax.swing.GroupLayout(jPanel40);
		jPanel40.setLayout(jPanel40Layout);
		jPanel40Layout.setHorizontalGroup(jPanel40Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 260, Short.MAX_VALUE));
		jPanel40Layout.setVerticalGroup(jPanel40Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 10, Short.MAX_VALUE));

		jPanel39.add(jPanel40, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0, 260, 10));

		jLabel61.setFont(new java.awt.Font("Tahoma", 0, 20)); // NOI18N
		jLabel61.setForeground(new java.awt.Color(96, 83, 150));
		jLabel61.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
		jLabel61.setText("Number of Rules");
		jPanel39.add(jLabel61, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 70, 260, 30));

		jLabel26.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
		jLabel26.setForeground(new java.awt.Color(255, 255, 255));
		jLabel26.setText("System Administator");
		jPanel39.add(jLabel26, new org.netbeans.lib.awtextra.AbsoluteConstraints(30, 30, -1, 30));

		javax.swing.GroupLayout jPanel13Layout = new javax.swing.GroupLayout(jPanel13);
		jPanel13.setLayout(jPanel13Layout);
		jPanel13Layout.setHorizontalGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel13Layout.createSequentialGroup().addContainerGap().addGroup(jPanel13Layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanel13Layout.createSequentialGroup().addComponent(jLabel27)
								.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
						.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
								jPanel13Layout.createSequentialGroup().addGroup(jPanel13Layout
										.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
										.addComponent(jLabel1, javax.swing.GroupLayout.Alignment.LEADING,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
										.addGroup(jPanel13Layout.createSequentialGroup()
												.addComponent(jPanel26, javax.swing.GroupLayout.PREFERRED_SIZE, 280,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
												.addComponent(jPanel28, javax.swing.GroupLayout.PREFERRED_SIZE, 287,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
												.addComponent(jPanel30, javax.swing.GroupLayout.PREFERRED_SIZE, 271,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addGap(18, 18, 18)
												.addComponent(jPanel39, javax.swing.GroupLayout.PREFERRED_SIZE, 261,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addGap(3, 3, 3)))
										.addGap(18, 18, 18)))));
		jPanel13Layout.setVerticalGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel13Layout.createSequentialGroup().addContainerGap()
						.addComponent(jLabel27, javax.swing.GroupLayout.PREFERRED_SIZE, 63,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(21, 21, 21)
						.addGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
								.addComponent(jPanel39, javax.swing.GroupLayout.DEFAULT_SIZE, 110, Short.MAX_VALUE)
								.addComponent(jPanel28, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jPanel30, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jPanel26, javax.swing.GroupLayout.PREFERRED_SIZE, 110, Short.MAX_VALUE))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,
								javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(jLabel1).addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));

		javax.swing.GroupLayout jPanel6Layout = new javax.swing.GroupLayout(jPanel6);
		jPanel6.setLayout(jPanel6Layout);
		jPanel6Layout.setHorizontalGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 1174, Short.MAX_VALUE));
		jPanel6Layout.setVerticalGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 520, Short.MAX_VALUE));

		javax.swing.GroupLayout jPanel12Layout = new javax.swing.GroupLayout(jPanel12);
		jPanel12.setLayout(jPanel12Layout);
		jPanel12Layout.setHorizontalGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addComponent(jPanel13, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE)
				.addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addComponent(
						jPanel6, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE)));
		jPanel12Layout.setVerticalGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel12Layout.createSequentialGroup()
						.addComponent(jPanel13, javax.swing.GroupLayout.PREFERRED_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(0, 507, Short.MAX_VALUE))
				.addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(
						javax.swing.GroupLayout.Alignment.TRAILING,
						jPanel12Layout.createSequentialGroup().addGap(0, 230, Short.MAX_VALUE).addComponent(jPanel6,
								javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
								javax.swing.GroupLayout.PREFERRED_SIZE))));

		jTextArea3.setEditable(false);
		jTextArea3.setColumns(20);
		jTextArea3.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		jTextArea3.setRows(5);
		jTextArea3.setOpaque(false);
		jScrollPane4.setViewportView(jTextArea3);

		javax.swing.GroupLayout HomeLayout = new javax.swing.GroupLayout(Home);
		Home.setLayout(HomeLayout);
		HomeLayout.setHorizontalGroup(HomeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addComponent(jPanel8, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE)
				.addGroup(HomeLayout.createSequentialGroup().addContainerGap()
						.addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
				.addGroup(HomeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(HomeLayout.createSequentialGroup()
								.addComponent(jPanel9, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jPanel12, javax.swing.GroupLayout.PREFERRED_SIZE, 1174,
										javax.swing.GroupLayout.PREFERRED_SIZE))));
		HomeLayout.setVerticalGroup(HomeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(HomeLayout.createSequentialGroup()
						.addComponent(jPanel8, javax.swing.GroupLayout.PREFERRED_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 307, Short.MAX_VALUE)
						.addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE, 183,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(260, 260, 260))
				.addGroup(HomeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(HomeLayout
						.createSequentialGroup().addGap(0, 50, Short.MAX_VALUE)
						.addGroup(HomeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jPanel9, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jPanel12, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGap(0, 0, Short.MAX_VALUE))));

		getContentPane().add(Home, new org.netbeans.lib.awtextra.AbsoluteConstraints(260, 0, -1, 800));

		IDS.setPreferredSize(new java.awt.Dimension(1480, 800));

		jPanel14.setBackground(new java.awt.Color(71, 120, 197));

		jTextField3.setBackground(new java.awt.Color(123, 156, 225));
		jTextField3.setForeground(new java.awt.Color(255, 255, 255));
		jTextField3.setBorder(null);
		jTextField3.setCaretColor(new java.awt.Color(255, 255, 255));
		jTextField3.setPreferredSize(new java.awt.Dimension(2, 20));

		jLabel28.setIcon(new javax.swing.ImageIcon(getClass().getResource("/GUI/images/icons8_Search_18px.png"))); // NOI18N

		javax.swing.GroupLayout jPanel14Layout = new javax.swing.GroupLayout(jPanel14);
		jPanel14.setLayout(jPanel14Layout);
		jPanel14Layout.setHorizontalGroup(jPanel14Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
						jPanel14Layout.createSequentialGroup().addContainerGap(1275, Short.MAX_VALUE)
								.addComponent(jTextField3, javax.swing.GroupLayout.PREFERRED_SIZE, 141,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
								.addComponent(jLabel28).addGap(34, 34, 34)));
		jPanel14Layout.setVerticalGroup(jPanel14Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel14Layout.createSequentialGroup()
						.addContainerGap(17, Short.MAX_VALUE)
						.addGroup(jPanel14Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
								.addComponent(jLabel28, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jTextField3, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
						.addContainerGap()));

		jPanel15.setBackground(new java.awt.Color(71, 120, 197));
		jPanel15.setPreferredSize(new java.awt.Dimension(301, 750));

		jPanel16.setBackground(new java.awt.Color(120, 168, 252));
		jPanel16.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

		jPanel17.setBackground(new java.awt.Color(84, 127, 206));

		jLabel29.setIcon(new javax.swing.ImageIcon(getClass().getResource("/GUI/images/icons8_Contacts_25px.png"))); // NOI18N

		jLabel30.setIcon(new javax.swing.ImageIcon(getClass().getResource("/GUI/images/icons8_Calendar_25px.png"))); // NOI18N

		jLabel31.setIcon(new javax.swing.ImageIcon(getClass().getResource("/GUI/images/icons8_Lock_25px.png"))); // NOI18N

		jLabel33.setIcon(
				new javax.swing.ImageIcon(getClass().getResource("/GUI/images/icons8_Secured_Letter_25px_2.png"))); // NOI18N

		javax.swing.GroupLayout jPanel17Layout = new javax.swing.GroupLayout(jPanel17);
		jPanel17.setLayout(jPanel17Layout);
		jPanel17Layout.setHorizontalGroup(jPanel17Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
						jPanel17Layout.createSequentialGroup().addGap(39, 39, 39).addComponent(jLabel33)
								.addGap(28, 28, 28).addComponent(jLabel29).addGap(45, 45, 45).addComponent(jLabel30)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 49,
										Short.MAX_VALUE)
								.addComponent(jLabel31).addGap(40, 40, 40))
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel17Layout.createSequentialGroup()
						.addContainerGap().addComponent(jSeparator3).addContainerGap()));
		jPanel17Layout.setVerticalGroup(jPanel17Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel17Layout.createSequentialGroup().addGap(32, 32, 32)
						.addGroup(jPanel17Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
								.addComponent(jLabel31, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jLabel30, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jLabel29, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jLabel33, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED).addComponent(jSeparator3,
								javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(0, 0, Short.MAX_VALUE)));

		jPanel16.add(jPanel17, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 85, -1, 80));

		btn_exit3.setIcon(new javax.swing.ImageIcon(getClass().getResource("/GUI/images/icons8_Exit_25px.png"))); // NOI18N
		btn_exit3.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mousePressed(java.awt.event.MouseEvent evt) {
				btn_exit3MousePressed(evt);
			}
		});
		jPanel16.add(btn_exit3, new org.netbeans.lib.awtextra.AbsoluteConstraints(260, 20, -1, 46));

		jLabel48.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
		jLabel48.setForeground(new java.awt.Color(255, 255, 255));
		jLabel48.setText("System Administator");
		jPanel16.add(jLabel48, new org.netbeans.lib.awtextra.AbsoluteConstraints(20, 30, -1, 30));

		WS_lists.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N

		WSProperty.setEditable(false);
		WSProperty.setColumns(20);
		WSProperty.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		WSProperty.setRows(5);
		WSProperty.setOpaque(false);
		WSProperty.setPreferredSize(new java.awt.Dimension(280, 104));
		jScrollPane1.setViewportView(WSProperty);

		Load_Wireless_btn.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		Load_Wireless_btn.setText("Load Wireless Card");
		Load_Wireless_btn.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mouseClicked(java.awt.event.MouseEvent evt) {
				Load_Wireless_btnMouseClicked(evt);
			}
		});

		ScanNet.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		ScanNet.setText("Scan Network");
		ScanNet.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				ScanNetActionPerformed(evt);
			}
		});

		jComboBox1.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		jComboBox1.setToolTipText("");

		FilterPackets.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		FilterPackets.setText("Filter Packets");
		FilterPackets.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mouseClicked(java.awt.event.MouseEvent evt) {
				FilterPacketsMouseClicked(evt);
			}
		});

		jLabel2.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
		jLabel2.setText("IP Address");

		jLabel14.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
		jLabel14.setText("Protocol");

		jComboBox5.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N

		jLabel15.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
		jLabel15.setText("Port");

		jComboBox6.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N

		ResetBtn.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		ResetBtn.setText("Reset");
		ResetBtn.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mouseClicked(java.awt.event.MouseEvent evt) {
				ResetBtnMouseClicked(evt);
			}
		});

		javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
		jPanel2.setLayout(jPanel2Layout);
		jPanel2Layout.setHorizontalGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
						jPanel2Layout.createSequentialGroup().addContainerGap().addComponent(jScrollPane1))
				.addGroup(jPanel2Layout.createSequentialGroup().addGroup(jPanel2Layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
								jPanel2Layout.createSequentialGroup().addGap(0, 0, Short.MAX_VALUE).addComponent(
										WS_lists, javax.swing.GroupLayout.PREFERRED_SIZE, 280,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGroup(jPanel2Layout.createSequentialGroup().addGroup(jPanel2Layout
								.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanel2Layout.createSequentialGroup().addContainerGap().addGroup(
										jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
												.addComponent(jLabel2).addComponent(jLabel14).addComponent(jLabel15))
										.addGap(18, 18, 18)
										.addGroup(jPanel2Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
												.addComponent(jComboBox6, 0, 174, Short.MAX_VALUE)
												.addComponent(jComboBox5, 0, javax.swing.GroupLayout.DEFAULT_SIZE,
														Short.MAX_VALUE)
												.addComponent(jComboBox1, 0, javax.swing.GroupLayout.DEFAULT_SIZE,
														Short.MAX_VALUE)))
								.addGroup(jPanel2Layout.createSequentialGroup().addGap(49, 49, 49)
										.addGroup(jPanel2Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
												.addComponent(ScanNet, javax.swing.GroupLayout.PREFERRED_SIZE, 200,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addComponent(Load_Wireless_btn, javax.swing.GroupLayout.PREFERRED_SIZE,
														200, javax.swing.GroupLayout.PREFERRED_SIZE))))
								.addGap(0, 0, Short.MAX_VALUE))
						.addGroup(jPanel2Layout.createSequentialGroup().addGap(23, 23, 23).addComponent(FilterPackets)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
								.addComponent(ResetBtn, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
						.addContainerGap()));
		jPanel2Layout.setVerticalGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel2Layout.createSequentialGroup().addGap(21, 21, 21)
						.addComponent(WS_lists, javax.swing.GroupLayout.PREFERRED_SIZE, 40,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(18, 18, 18).addComponent(Load_Wireless_btn)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).addComponent(ScanNet)
						.addGap(18, 18, 18)
						.addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jComboBox1, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jLabel2))
						.addGap(18, 18, 18)
						.addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jComboBox5, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jLabel14))
						.addGap(20, 20, 20)
						.addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jLabel15).addComponent(jComboBox6, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGap(18, 18, 18)
						.addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(FilterPackets).addComponent(ResetBtn))
						.addGap(18, 18, 18)
						.addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 235, Short.MAX_VALUE)));

		javax.swing.GroupLayout jPanel15Layout = new javax.swing.GroupLayout(jPanel15);
		jPanel15.setLayout(jPanel15Layout);
		jPanel15Layout.setHorizontalGroup(jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addComponent(jPanel16, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE)
				.addComponent(jPanel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE));
		jPanel15Layout.setVerticalGroup(jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel15Layout.createSequentialGroup()
						.addComponent(jPanel16, javax.swing.GroupLayout.PREFERRED_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).addComponent(jPanel2,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
								Short.MAX_VALUE)));

		jPanel18.setBackground(new java.awt.Color(255, 255, 255));
		jPanel18.setPreferredSize(new java.awt.Dimension(872, 750));

		jPanel19.setBackground(new java.awt.Color(242, 247, 247));

		jLabel39.setFont(new java.awt.Font("Tahoma", 0, 36)); // NOI18N
		jLabel39.setForeground(new java.awt.Color(102, 102, 102));
		jLabel39.setText("Scan Packets");

		jPanel33.setBackground(new java.awt.Color(255, 255, 255));
		jPanel33.setPreferredSize(new java.awt.Dimension(150, 60));

		ICMP_num.setFont(new java.awt.Font("Tahoma", 1, 32)); // NOI18N
		ICMP_num.setForeground(new java.awt.Color(96, 83, 150));
		ICMP_num.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
		ICMP_num.setText("0");

		jLabel60.setFont(new java.awt.Font("Tahoma", 1, 22)); // NOI18N
		jLabel60.setForeground(new java.awt.Color(96, 83, 150));
		jLabel60.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
		jLabel60.setText("ICMP");

		jPanel34.setBackground(new java.awt.Color(204, 0, 0));

		javax.swing.GroupLayout jPanel34Layout = new javax.swing.GroupLayout(jPanel34);
		jPanel34.setLayout(jPanel34Layout);
		jPanel34Layout.setHorizontalGroup(jPanel34Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 286, Short.MAX_VALUE));
		jPanel34Layout.setVerticalGroup(jPanel34Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 10, Short.MAX_VALUE));

		javax.swing.GroupLayout jPanel33Layout = new javax.swing.GroupLayout(jPanel33);
		jPanel33.setLayout(jPanel33Layout);
		jPanel33Layout.setHorizontalGroup(jPanel33Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel33Layout.createSequentialGroup().addGroup(jPanel33Layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addComponent(jPanel34, javax.swing.GroupLayout.PREFERRED_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGroup(jPanel33Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
								.addComponent(jLabel60, javax.swing.GroupLayout.Alignment.LEADING,
										javax.swing.GroupLayout.DEFAULT_SIZE, 149, Short.MAX_VALUE)
								.addComponent(ICMP_num, javax.swing.GroupLayout.Alignment.LEADING,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
										Short.MAX_VALUE)))
						.addGap(0, 0, Short.MAX_VALUE)));
		jPanel33Layout.setVerticalGroup(jPanel33Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel33Layout.createSequentialGroup()
						.addComponent(jPanel34, javax.swing.GroupLayout.PREFERRED_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(11, 11, 11)
						.addComponent(ICMP_num, javax.swing.GroupLayout.DEFAULT_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).addComponent(jLabel60,
								javax.swing.GroupLayout.PREFERRED_SIZE, 33, javax.swing.GroupLayout.PREFERRED_SIZE)));

		jPanel35.setBackground(new java.awt.Color(255, 255, 255));
		jPanel35.setMinimumSize(new java.awt.Dimension(150, 60));
		jPanel35.setPreferredSize(new java.awt.Dimension(150, 60));
		jPanel35.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

		tcp_num.setFont(new java.awt.Font("Tahoma", 1, 32)); // NOI18N
		tcp_num.setForeground(new java.awt.Color(96, 83, 150));
		tcp_num.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
		tcp_num.setText("0");
		jPanel35.add(tcp_num, new org.netbeans.lib.awtextra.AbsoluteConstraints(-3, 22, 150, -1));

		jPanel36.setBackground(new java.awt.Color(255, 102, 0));

		javax.swing.GroupLayout jPanel36Layout = new javax.swing.GroupLayout(jPanel36);
		jPanel36.setLayout(jPanel36Layout);
		jPanel36Layout.setHorizontalGroup(jPanel36Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 290, Short.MAX_VALUE));
		jPanel36Layout.setVerticalGroup(jPanel36Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 10, Short.MAX_VALUE));

		jPanel35.add(jPanel36, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0, 290, 10));

		jLabel62.setFont(new java.awt.Font("Tahoma", 1, 22)); // NOI18N
		jLabel62.setForeground(new java.awt.Color(96, 83, 150));
		jLabel62.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
		jLabel62.setText("TCP");
		jPanel35.add(jLabel62, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 60, 150, 30));

		jPanel37.setBackground(new java.awt.Color(255, 255, 255));
		jPanel37.setMinimumSize(new java.awt.Dimension(150, 60));
		jPanel37.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

		UDP_num.setFont(new java.awt.Font("Tahoma", 1, 32)); // NOI18N
		UDP_num.setForeground(new java.awt.Color(96, 83, 150));
		UDP_num.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
		UDP_num.setText("0");
		jPanel37.add(UDP_num, new org.netbeans.lib.awtextra.AbsoluteConstraints(-5, 20, 150, -1));

		jPanel38.setBackground(new java.awt.Color(0, 204, 51));

		javax.swing.GroupLayout jPanel38Layout = new javax.swing.GroupLayout(jPanel38);
		jPanel38.setLayout(jPanel38Layout);
		jPanel38Layout.setHorizontalGroup(jPanel38Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 290, Short.MAX_VALUE));
		jPanel38Layout.setVerticalGroup(jPanel38Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 10, Short.MAX_VALUE));

		jPanel37.add(jPanel38, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0, 290, 10));

		jLabel64.setFont(new java.awt.Font("Tahoma", 1, 22)); // NOI18N
		jLabel64.setForeground(new java.awt.Color(96, 83, 150));
		jLabel64.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
		jLabel64.setText("UDP");
		jPanel37.add(jLabel64, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 60, 140, 30));

		jTextArea1.setEditable(false);
		jTextArea1.setColumns(20);
		jTextArea1.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		jTextArea1.setRows(5);
		jTextArea1.setOpaque(false);
		jScrollPane3.setViewportView(jTextArea1);

		jPanel43.setBackground(new java.awt.Color(255, 255, 255));
		jPanel43.setPreferredSize(new java.awt.Dimension(150, 60));

		Block_Num.setFont(new java.awt.Font("Tahoma", 1, 32)); // NOI18N
		Block_Num.setForeground(new java.awt.Color(96, 83, 150));
		Block_Num.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
		Block_Num.setText("0");

		jLabel65.setFont(new java.awt.Font("Tahoma", 1, 20)); // NOI18N
		jLabel65.setForeground(new java.awt.Color(96, 83, 150));
		jLabel65.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
		jLabel65.setText("Blocked Attack");

		jPanel44.setBackground(new java.awt.Color(0, 0, 0));

		javax.swing.GroupLayout jPanel44Layout = new javax.swing.GroupLayout(jPanel44);
		jPanel44.setLayout(jPanel44Layout);
		jPanel44Layout.setHorizontalGroup(jPanel44Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 286, Short.MAX_VALUE));
		jPanel44Layout.setVerticalGroup(jPanel44Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 10, Short.MAX_VALUE));

		javax.swing.GroupLayout jPanel43Layout = new javax.swing.GroupLayout(jPanel43);
		jPanel43.setLayout(jPanel43Layout);
		jPanel43Layout.setHorizontalGroup(jPanel43Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel43Layout.createSequentialGroup().addGroup(jPanel43Layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addComponent(jPanel44, javax.swing.GroupLayout.PREFERRED_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGroup(jPanel43Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
								.addComponent(Block_Num, javax.swing.GroupLayout.Alignment.LEADING,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
										Short.MAX_VALUE)
								.addComponent(jLabel65, javax.swing.GroupLayout.Alignment.LEADING,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
										Short.MAX_VALUE)))
						.addGap(0, 0, Short.MAX_VALUE)));
		jPanel43Layout.setVerticalGroup(jPanel43Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel43Layout.createSequentialGroup()
						.addComponent(jPanel44, javax.swing.GroupLayout.PREFERRED_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(11, 11, 11)
						.addComponent(Block_Num, javax.swing.GroupLayout.DEFAULT_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).addComponent(jLabel65,
								javax.swing.GroupLayout.PREFERRED_SIZE, 33, javax.swing.GroupLayout.PREFERRED_SIZE)));

		javax.swing.GroupLayout jPanel19Layout = new javax.swing.GroupLayout(jPanel19);
		jPanel19.setLayout(jPanel19Layout);
		jPanel19Layout
				.setHorizontalGroup(
						jPanel19Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel19Layout
										.createSequentialGroup().addContainerGap().addGroup(jPanel19Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
												.addGroup(jPanel19Layout.createSequentialGroup().addComponent(
														jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 967,
														javax.swing.GroupLayout.PREFERRED_SIZE).addGap(18, 18, 18))
												.addGroup(jPanel19Layout.createSequentialGroup()
														.addComponent(jLabel39, javax.swing.GroupLayout.PREFERRED_SIZE,
																271, javax.swing.GroupLayout.PREFERRED_SIZE)
														.addGap(351, 351, 351)
														.addComponent(jPanel37, javax.swing.GroupLayout.PREFERRED_SIZE,
																142, javax.swing.GroupLayout.PREFERRED_SIZE)
														.addPreferredGap(
																javax.swing.LayoutStyle.ComponentPlacement.RELATED,
																javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
														.addComponent(jPanel35, javax.swing.GroupLayout.PREFERRED_SIZE,
																javax.swing.GroupLayout.DEFAULT_SIZE,
																javax.swing.GroupLayout.PREFERRED_SIZE)
														.addGap(32, 32, 32)))
										.addGroup(jPanel19Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
												.addComponent(jPanel33, javax.swing.GroupLayout.PREFERRED_SIZE,
														javax.swing.GroupLayout.DEFAULT_SIZE,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addGroup(jPanel19Layout.createSequentialGroup().addGap(10, 10, 10)
														.addComponent(jPanel43, javax.swing.GroupLayout.PREFERRED_SIZE,
																157, javax.swing.GroupLayout.PREFERRED_SIZE)))
										.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));
		jPanel19Layout.setVerticalGroup(jPanel19Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel19Layout.createSequentialGroup()
						.addContainerGap()
						.addGroup(jPanel19Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jLabel39, javax.swing.GroupLayout.Alignment.TRAILING,
										javax.swing.GroupLayout.PREFERRED_SIZE, 82,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addGroup(jPanel19Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
										.addComponent(jPanel37, javax.swing.GroupLayout.PREFERRED_SIZE, 89,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jPanel35, javax.swing.GroupLayout.PREFERRED_SIZE, 90,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jPanel33, javax.swing.GroupLayout.PREFERRED_SIZE, 93,
												javax.swing.GroupLayout.PREFERRED_SIZE)))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,
								javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addGroup(jPanel19Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
								.addComponent(jPanel43, javax.swing.GroupLayout.DEFAULT_SIZE, 100, Short.MAX_VALUE)
								.addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE))
						.addGap(40, 40, 40)));

		jPanel3.setEnabled(false);
		jPanel3.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		jPanel3.setLayout(new java.awt.BorderLayout());

		javax.swing.GroupLayout jPanel18Layout = new javax.swing.GroupLayout(jPanel18);
		jPanel18.setLayout(jPanel18Layout);
		jPanel18Layout.setHorizontalGroup(jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addComponent(jPanel19, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE)
				.addGroup(jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanel18Layout
								.createSequentialGroup().addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE,
										1165, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addGap(0, 100, Short.MAX_VALUE))));
		jPanel18Layout.setVerticalGroup(jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel18Layout.createSequentialGroup()
						.addComponent(jPanel19, javax.swing.GroupLayout.PREFERRED_SIZE, 213,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(0, 537, Short.MAX_VALUE))
				.addGroup(jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(
						javax.swing.GroupLayout.Alignment.TRAILING,
						jPanel18Layout.createSequentialGroup().addGap(0, 215, Short.MAX_VALUE).addComponent(jPanel3,
								javax.swing.GroupLayout.PREFERRED_SIZE, 535, javax.swing.GroupLayout.PREFERRED_SIZE))));

		javax.swing.GroupLayout IDSLayout = new javax.swing.GroupLayout(IDS);
		IDS.setLayout(IDSLayout);
		IDSLayout.setHorizontalGroup(IDSLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 1484, Short.MAX_VALUE)
				.addGroup(IDSLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(IDSLayout.createSequentialGroup()
								.addComponent(jPanel15, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
								.addComponent(jPanel18, javax.swing.GroupLayout.DEFAULT_SIZE, 1176, Short.MAX_VALUE))
						.addGroup(IDSLayout.createSequentialGroup()
								.addComponent(jPanel14, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addGap(0, 0, Short.MAX_VALUE))));
		IDSLayout.setVerticalGroup(IDSLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 800, Short.MAX_VALUE)
				.addGroup(IDSLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(IDSLayout
						.createSequentialGroup().addGap(0, 0, Short.MAX_VALUE)
						.addComponent(jPanel14, javax.swing.GroupLayout.PREFERRED_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGroup(IDSLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jPanel15, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jPanel18, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGap(0, 0, Short.MAX_VALUE))));

		getContentPane().add(IDS, new org.netbeans.lib.awtextra.AbsoluteConstraints(260, 0, -1, 800));

		RuleConfig.setPreferredSize(new java.awt.Dimension(1480, 800));

		jPanel20.setBackground(new java.awt.Color(71, 120, 197));

		jTextField4.setBackground(new java.awt.Color(123, 156, 225));
		jTextField4.setForeground(new java.awt.Color(255, 255, 255));
		jTextField4.setBorder(null);
		jTextField4.setCaretColor(new java.awt.Color(255, 255, 255));
		jTextField4.setPreferredSize(new java.awt.Dimension(2, 20));

		jLabel40.setIcon(new javax.swing.ImageIcon(getClass().getResource("/GUI/images/icons8_Search_18px.png"))); // NOI18N

		javax.swing.GroupLayout jPanel20Layout = new javax.swing.GroupLayout(jPanel20);
		jPanel20.setLayout(jPanel20Layout);
		jPanel20Layout.setHorizontalGroup(jPanel20Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
						jPanel20Layout.createSequentialGroup()
								.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jTextField4, javax.swing.GroupLayout.PREFERRED_SIZE, 141,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
								.addComponent(jLabel40).addGap(34, 34, 34)));
		jPanel20Layout.setVerticalGroup(jPanel20Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel20Layout.createSequentialGroup()
						.addContainerGap(17, Short.MAX_VALUE)
						.addGroup(jPanel20Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
								.addComponent(jLabel40, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jTextField4, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
						.addContainerGap()));

		jPanel21.setBackground(new java.awt.Color(71, 120, 197));
		jPanel21.setPreferredSize(new java.awt.Dimension(301, 750));

		jLabel17.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
		jLabel17.setText("Wireless Card");

		jComboBox7.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N

		jLabel18.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
		jLabel18.setText("Protocol");

		jLabel19.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
		jLabel19.setText("Port Number");

		jLabel20.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
		jLabel20.setText("Action");

		jLabel21.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
		jLabel21.setText("Status");

		jComboBox8.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		jComboBox8.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "TCP", "UDP", "ICMP" }));

		jComboBox9.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N

		jComboBox10.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		jComboBox10.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Block", "Allow" }));

		jComboBox11.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		jComboBox11
				.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Inactive", "Active", "Implemented" }));

		jButton1.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		jButton1.setText("Filter Rules");
		jButton1.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mouseClicked(java.awt.event.MouseEvent evt) {
				jButton1MouseClicked(evt);
			}
		});

		jCheckBox1.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
		jCheckBox1.setText("Enable Email Notification");
		jCheckBox1.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mouseClicked(java.awt.event.MouseEvent evt) {
				jCheckBox1MouseClicked(evt);
			}
		});

		jTextField9.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		jTextField9.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jTextField9ActionPerformed(evt);
			}
		});

		ResetRuleBtn.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		ResetRuleBtn.setText("Reset");

		javax.swing.GroupLayout jPanel5Layout = new javax.swing.GroupLayout(jPanel5);
		jPanel5.setLayout(jPanel5Layout);
		jPanel5Layout.setHorizontalGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel5Layout.createSequentialGroup().addContainerGap()
						.addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
								.addGroup(jPanel5Layout.createSequentialGroup()
										.addGroup(jPanel5Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
												.addComponent(jLabel17, javax.swing.GroupLayout.DEFAULT_SIZE,
														javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
												.addComponent(jLabel21, javax.swing.GroupLayout.DEFAULT_SIZE,
														javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
												.addComponent(jLabel20, javax.swing.GroupLayout.DEFAULT_SIZE,
														javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
												.addComponent(jLabel19, javax.swing.GroupLayout.DEFAULT_SIZE,
														javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
												.addComponent(jLabel18, javax.swing.GroupLayout.DEFAULT_SIZE,
														javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
										.addGroup(jPanel5Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
												.addComponent(jComboBox8, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addComponent(jComboBox7, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addComponent(jComboBox10, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addComponent(jComboBox9, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addComponent(jComboBox11, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
														javax.swing.GroupLayout.PREFERRED_SIZE)))
								.addComponent(jCheckBox1, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jTextField9).addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
										jPanel5Layout.createSequentialGroup().addComponent(jButton1).addGap(18, 18, 18)
												.addComponent(ResetRuleBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 111,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addGap(15, 15, 15)))
						.addContainerGap()));
		jPanel5Layout.setVerticalGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel5Layout.createSequentialGroup().addGap(42, 42, 42)
						.addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jLabel17).addComponent(jComboBox7, javax.swing.GroupLayout.PREFERRED_SIZE,
										30, javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGap(25, 25, 25)
						.addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jLabel18).addComponent(jComboBox8, javax.swing.GroupLayout.PREFERRED_SIZE,
										30, javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGap(23, 23, 23)
						.addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jComboBox9, javax.swing.GroupLayout.PREFERRED_SIZE, 30,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jLabel19))
						.addGap(21, 21, 21)
						.addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jComboBox10, javax.swing.GroupLayout.PREFERRED_SIZE, 30,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jLabel20))
						.addGap(24, 24, 24)
						.addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jLabel21).addComponent(jComboBox11,
										javax.swing.GroupLayout.PREFERRED_SIZE, 30,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGap(34, 34, 34)
						.addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jButton1).addComponent(ResetRuleBtn))
						.addGap(39, 39, 39).addComponent(jCheckBox1).addGap(18, 18, 18).addComponent(jTextField9,
								javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addContainerGap(112, Short.MAX_VALUE)));

		jPanel22.setBackground(new java.awt.Color(120, 168, 252));
		jPanel22.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

		jPanel23.setBackground(new java.awt.Color(84, 127, 206));

		jLabel32.setIcon(new javax.swing.ImageIcon(getClass().getResource("/GUI/images/icons8_Contacts_25px.png"))); // NOI18N

		jLabel34.setIcon(new javax.swing.ImageIcon(getClass().getResource("/GUI/images/icons8_Calendar_25px.png"))); // NOI18N

		jLabel35.setIcon(new javax.swing.ImageIcon(getClass().getResource("/GUI/images/icons8_Lock_25px.png"))); // NOI18N

		jLabel36.setIcon(
				new javax.swing.ImageIcon(getClass().getResource("/GUI/images/icons8_Secured_Letter_25px_2.png"))); // NOI18N

		javax.swing.GroupLayout jPanel23Layout = new javax.swing.GroupLayout(jPanel23);
		jPanel23.setLayout(jPanel23Layout);
		jPanel23Layout.setHorizontalGroup(jPanel23Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
						jPanel23Layout.createSequentialGroup().addGap(39, 39, 39).addComponent(jLabel36)
								.addGap(28, 28, 28).addComponent(jLabel32).addGap(45, 45, 45).addComponent(jLabel34)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 49,
										Short.MAX_VALUE)
								.addComponent(jLabel35).addGap(40, 40, 40))
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel23Layout.createSequentialGroup()
						.addContainerGap().addComponent(jSeparator4).addContainerGap()));
		jPanel23Layout.setVerticalGroup(jPanel23Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel23Layout.createSequentialGroup().addGap(32, 32, 32)
						.addGroup(jPanel23Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
								.addComponent(jLabel35, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jLabel34, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jLabel32, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jLabel36, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED).addComponent(jSeparator4,
								javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(0, 0, Short.MAX_VALUE)));

		jPanel22.add(jPanel23, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 85, -1, 80));

		btn_exit4.setIcon(new javax.swing.ImageIcon(getClass().getResource("/GUI/images/icons8_Exit_25px.png"))); // NOI18N
		btn_exit4.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mousePressed(java.awt.event.MouseEvent evt) {
				btn_exit4MousePressed(evt);
			}
		});
		jPanel22.add(btn_exit4, new org.netbeans.lib.awtextra.AbsoluteConstraints(260, 20, -1, 46));

		jLabel49.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
		jLabel49.setForeground(new java.awt.Color(255, 255, 255));
		jLabel49.setText("System Administator");
		jPanel22.add(jLabel49, new org.netbeans.lib.awtextra.AbsoluteConstraints(20, 30, -1, 30));

		javax.swing.GroupLayout jPanel21Layout = new javax.swing.GroupLayout(jPanel21);
		jPanel21.setLayout(jPanel21Layout);
		jPanel21Layout.setHorizontalGroup(jPanel21Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addComponent(jPanel5, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE)
				.addComponent(jPanel22, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE));
		jPanel21Layout.setVerticalGroup(jPanel21Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel21Layout.createSequentialGroup()
						.addComponent(jPanel22, javax.swing.GroupLayout.PREFERRED_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).addComponent(jPanel5,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
								Short.MAX_VALUE)));

		jPanel24.setBackground(new java.awt.Color(255, 255, 255));
		jPanel24.setPreferredSize(new java.awt.Dimension(872, 750));
		jPanel24.setRequestFocusEnabled(false);

		jPanel25.setBackground(new java.awt.Color(242, 247, 247));

		jLabel3.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
		jLabel3.setText("Rule Name");

		jTextField1.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N

		jLabel4.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
		jLabel4.setText("Wireless Card");

		jComboBox2.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N

		jButton2.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		jButton2.setText("Add Rule");
		jButton2.setMaximumSize(new java.awt.Dimension(147, 31));
		jButton2.setMinimumSize(new java.awt.Dimension(147, 31));
		jButton2.setPreferredSize(new java.awt.Dimension(147, 31));
		jButton2.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mouseClicked(java.awt.event.MouseEvent evt) {
				jButton2MouseClicked(evt);
			}
		});

		jComboBox4.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		jComboBox4.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Block", "Allow" }));

		jLabel5.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
		jLabel5.setText("Actions");

		jLabel6.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
		jLabel6.setText("Port Number");

		jLabel7.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
		jLabel7.setText("Protocol");

		jComboBox3.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		jComboBox3.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "TCP", "UDP", "ICMP" }));

		jTextField5.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N

		jLabel12.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
		jLabel12.setText("IP Address");

		jTextField6.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N

		jLabel13.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
		jLabel13.setText("Description:");

		jTextField7.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N

		jButton3.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		jButton3.setText("Change Status");
		jButton3.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mouseClicked(java.awt.event.MouseEvent evt) {
				jButton3MouseClicked(evt);
			}
		});

		jLabel16.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
		jLabel16.setText("Attempts");

		jTextField8.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N

		DeleteRule.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		DeleteRule.setText("Delete Rule");
		DeleteRule.setMaximumSize(new java.awt.Dimension(147, 31));
		DeleteRule.setMinimumSize(new java.awt.Dimension(147, 31));
		DeleteRule.setPreferredSize(new java.awt.Dimension(147, 31));
		DeleteRule.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mouseClicked(java.awt.event.MouseEvent evt) {
				DeleteRuleMouseClicked(evt);
			}
		});

		javax.swing.GroupLayout jPanel25Layout = new javax.swing.GroupLayout(jPanel25);
		jPanel25.setLayout(jPanel25Layout);
		jPanel25Layout.setHorizontalGroup(jPanel25Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel25Layout.createSequentialGroup().addGap(37, 37, 37).addGroup(jPanel25Layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanel25Layout.createSequentialGroup().addGroup(jPanel25Layout
								.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(
										jPanel25Layout.createSequentialGroup().addComponent(jLabel3).addGap(41, 41, 41)
												.addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
														javax.swing.GroupLayout.PREFERRED_SIZE))
								.addGroup(jPanel25Layout.createSequentialGroup()
										.addComponent(jLabel12, javax.swing.GroupLayout.PREFERRED_SIZE, 89,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(37, 37, 37)
										.addGroup(jPanel25Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
												.addComponent(jTextField8, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addComponent(jTextField5, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
														javax.swing.GroupLayout.PREFERRED_SIZE))))
								.addGap(81, 81, 81)
								.addGroup(jPanel25Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
										.addGroup(jPanel25Layout.createSequentialGroup()
												.addComponent(jLabel13, javax.swing.GroupLayout.DEFAULT_SIZE, 157,
														Short.MAX_VALUE)
												.addGap(621, 621, 621))
										.addGroup(jPanel25Layout.createSequentialGroup().addGroup(jPanel25Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
												.addComponent(jLabel6, javax.swing.GroupLayout.PREFERRED_SIZE, 106,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addComponent(jLabel4)).addGap(42, 42, 42)
												.addGroup(jPanel25Layout
														.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
														.addGroup(jPanel25Layout
																.createParallelGroup(
																		javax.swing.GroupLayout.Alignment.LEADING)
																.addComponent(jTextField7,
																		javax.swing.GroupLayout.PREFERRED_SIZE, 527,
																		javax.swing.GroupLayout.PREFERRED_SIZE)
																.addGroup(jPanel25Layout.createSequentialGroup()
																		.addGroup(jPanel25Layout.createParallelGroup(
																				javax.swing.GroupLayout.Alignment.TRAILING)
																				.addComponent(jComboBox2,
																						javax.swing.GroupLayout.PREFERRED_SIZE,
																						150,
																						javax.swing.GroupLayout.PREFERRED_SIZE)
																				.addComponent(jTextField6,
																						javax.swing.GroupLayout.PREFERRED_SIZE,
																						150,
																						javax.swing.GroupLayout.PREFERRED_SIZE))
																		.addGap(82, 82, 82)
																		.addGroup(jPanel25Layout.createParallelGroup(
																				javax.swing.GroupLayout.Alignment.LEADING)
																				.addComponent(jLabel7,
																						javax.swing.GroupLayout.PREFERRED_SIZE,
																						103,
																						javax.swing.GroupLayout.PREFERRED_SIZE)
																				.addComponent(jLabel5,
																						javax.swing.GroupLayout.PREFERRED_SIZE,
																						89,
																						javax.swing.GroupLayout.PREFERRED_SIZE))
																		.addGap(42, 42, 42)
																		.addGroup(jPanel25Layout.createParallelGroup(
																				javax.swing.GroupLayout.Alignment.LEADING)
																				.addComponent(jComboBox3,
																						javax.swing.GroupLayout.PREFERRED_SIZE,
																						150,
																						javax.swing.GroupLayout.PREFERRED_SIZE)
																				.addComponent(jComboBox4,
																						javax.swing.GroupLayout.PREFERRED_SIZE,
																						150,
																						javax.swing.GroupLayout.PREFERRED_SIZE))))
														.addGroup(jPanel25Layout.createSequentialGroup()
																.addComponent(jButton2,
																		javax.swing.GroupLayout.PREFERRED_SIZE,
																		javax.swing.GroupLayout.DEFAULT_SIZE,
																		javax.swing.GroupLayout.PREFERRED_SIZE)
																.addGap(28, 28, 28).addComponent(jButton3)
																.addGap(26, 26, 26).addComponent(DeleteRule,
																		javax.swing.GroupLayout.PREFERRED_SIZE, 147,
																		javax.swing.GroupLayout.PREFERRED_SIZE)))
												.addGap(71, 71, 71))))
						.addGroup(jPanel25Layout.createSequentialGroup().addComponent(jLabel16,
								javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addContainerGap()))));
		jPanel25Layout.setVerticalGroup(jPanel25Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel25Layout.createSequentialGroup().addGap(11, 11, 11)
						.addGroup(jPanel25Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jLabel3)
								.addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, 30,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jLabel4)
								.addComponent(jComboBox2, javax.swing.GroupLayout.PREFERRED_SIZE, 30,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jLabel7).addComponent(jComboBox3, javax.swing.GroupLayout.PREFERRED_SIZE,
										30, javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGap(37, 37, 37)
						.addGroup(jPanel25Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jLabel6)
								.addComponent(jTextField5, javax.swing.GroupLayout.PREFERRED_SIZE, 31,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jTextField6, javax.swing.GroupLayout.PREFERRED_SIZE, 30,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jLabel12).addComponent(jLabel5).addComponent(jComboBox4,
										javax.swing.GroupLayout.PREFERRED_SIZE, 30,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGroup(jPanel25Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanel25Layout.createSequentialGroup().addGap(32, 32, 32)
										.addGroup(jPanel25Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
												.addComponent(jLabel16).addComponent(jTextField8,
														javax.swing.GroupLayout.PREFERRED_SIZE, 30,
														javax.swing.GroupLayout.PREFERRED_SIZE)))
								.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
										jPanel25Layout.createSequentialGroup()
												.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
												.addGroup(jPanel25Layout
														.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
														.addComponent(jLabel13).addComponent(jTextField7,
																javax.swing.GroupLayout.PREFERRED_SIZE, 30,
																javax.swing.GroupLayout.PREFERRED_SIZE))))
						.addGap(18, 18, 18)
						.addGroup(jPanel25Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jButton3)
								.addComponent(jButton2, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(DeleteRule, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
						.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));

		jPanel4.setLayout(new java.awt.BorderLayout());

		javax.swing.GroupLayout jPanel24Layout = new javax.swing.GroupLayout(jPanel24);
		jPanel24.setLayout(jPanel24Layout);
		jPanel24Layout.setHorizontalGroup(jPanel24Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addComponent(jPanel25, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE)
				.addComponent(jPanel4, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE));
		jPanel24Layout.setVerticalGroup(jPanel24Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel24Layout.createSequentialGroup()
						.addComponent(jPanel25, javax.swing.GroupLayout.PREFERRED_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,
								javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(jPanel4, javax.swing.GroupLayout.PREFERRED_SIZE, 519,
								javax.swing.GroupLayout.PREFERRED_SIZE)));

		javax.swing.GroupLayout RuleConfigLayout = new javax.swing.GroupLayout(RuleConfig);
		RuleConfig.setLayout(RuleConfigLayout);
		RuleConfigLayout.setHorizontalGroup(RuleConfigLayout
				.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGap(0, 1480, Short.MAX_VALUE)
				.addGroup(RuleConfigLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(RuleConfigLayout.createSequentialGroup()
								.addComponent(jPanel21, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
								.addComponent(jPanel24, javax.swing.GroupLayout.DEFAULT_SIZE, 1172, Short.MAX_VALUE))
						.addComponent(jPanel20, javax.swing.GroupLayout.DEFAULT_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));
		RuleConfigLayout.setVerticalGroup(RuleConfigLayout
				.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGap(0, 800, Short.MAX_VALUE)
				.addGroup(RuleConfigLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(RuleConfigLayout.createSequentialGroup().addGap(0, 0, Short.MAX_VALUE)
								.addComponent(jPanel20, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addGroup(
										RuleConfigLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
												.addComponent(jPanel21, javax.swing.GroupLayout.PREFERRED_SIZE,
														javax.swing.GroupLayout.DEFAULT_SIZE,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addComponent(jPanel24, javax.swing.GroupLayout.PREFERRED_SIZE,
														javax.swing.GroupLayout.DEFAULT_SIZE,
														javax.swing.GroupLayout.PREFERRED_SIZE))
								.addGap(0, 0, Short.MAX_VALUE))));

		getContentPane().add(RuleConfig, new org.netbeans.lib.awtextra.AbsoluteConstraints(260, 0, -1, 800));

		Alerts.setFont(new java.awt.Font("Tahoma", 0, 14)); // NOI18N
		Alerts.setPreferredSize(new java.awt.Dimension(1480, 800));

		jTextArea2.setEditable(false);
		jTextArea2.setColumns(20);
		jTextArea2.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
		jTextArea2.setRows(5);
		jTextArea2.setOpaque(false);
		jScrollPane2.setViewportView(jTextArea2);

		javax.swing.GroupLayout AlertsLayout = new javax.swing.GroupLayout(Alerts);
		Alerts.setLayout(AlertsLayout);
		AlertsLayout.setHorizontalGroup(AlertsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 1480, Short.MAX_VALUE));
		AlertsLayout.setVerticalGroup(AlertsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 800, Short.MAX_VALUE));

		getContentPane().add(Alerts, new org.netbeans.lib.awtextra.AbsoluteConstraints(260, 0, -1, 800));

		pack();
	}// </editor-fold>//GEN-END:initComponents

    public void setDevice(NetworkInterface[] devices) {
        this.devices = devices;
    }

    public void setTable(DefaultTableModel packetTableModel) {
        this.packetTableModel = packetTableModel;
    }

    public void setFilter(String FilterMess) {
        this.FilterMess = FilterMess;
    }

    public void clearpackets() {
        packetlist.clear();
    }

    private void btn_1MousePressed(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_btn_1MousePressed
        setColor(btn_1);
        ind_1.setOpaque(true);
        resetColor(new JPanel[]{btn_2, btn_3, btn_4}, new JPanel[]{ind_2, ind_3, ind_4});
        IDS.setVisible(false);
        RuleConfig.setVisible(false);
        Home.setVisible(true);
        Alerts.setVisible(false);
    }// GEN-LAST:event_btn_1MousePressed

    private void btn_3MousePressed(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_btn_3MousePressed
        setColor(btn_3);
        ind_3.setOpaque(true);
        resetColor(new JPanel[]{btn_2, btn_1, btn_4}, new JPanel[]{ind_2, ind_1, ind_4});
        RuleConfig.setVisible(false);
        Home.setVisible(false);
        IDS.setVisible(true);
        Alerts.setVisible(false);
    }// GEN-LAST:event_btn_3MousePressed

    private void btn_4MousePressed(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_btn_4MousePressed
        setColor(btn_4);
        ind_4.setOpaque(true);
        resetColor(new JPanel[]{btn_2, btn_3, btn_1}, new JPanel[]{ind_2, ind_3, ind_1});

        IDS.setVisible(false);
        Home.setVisible(false);
        RuleConfig.setVisible(true);
        Alerts.setVisible(false);

    }// GEN-LAST:event_btn_4MousePressed

    private void jPanel8MouseDragged(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_jPanel8MouseDragged
    }// GEN-LAST:event_jPanel8MouseDragged

    private void jPanel8MousePressed(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_jPanel8MousePressed
    }// GEN-LAST:event_jPanel8MousePressed

    private void Load_Wireless_btnMouseClicked(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_Load_Wireless_btnMouseClicked
        WS_lists.removeAllItems();
        Load_Wireless_btn.setEnabled(false);

        devices = JpcapCaptor.getDeviceList();
        for (int i = 0; i < devices.length; i++) {
            WS_lists.addItem(i + 1 + ": " + devices[i].description);
        }
        WS_lists.getSelectedItem().hashCode();
        WS_lists.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent arg0) {
                int k = WS_lists.getSelectedIndex();
                WSProperty.setText("");
                WSProperty.append("---- NETWORK INTERFACE ----");
                WSProperty.append("\nName: " + devices[k].description);
                WSProperty.append("\nIP Address: ");
                for (NetworkInterfaceAddress c : devices[k].addresses) {
                    String[] strarray = c.address.toString().split("/");
                    if (strarray[1].contains(":")) {
                        // DO NOTHING
                    } else {
                        WSProperty.append(strarray[1]);
                    }
                }

                WSProperty.append("\nMAC Address: ");
                for (byte c : devices[k].mac_address) {
                    WSProperty.append(Integer.toHexString(c & 0xff) + ":");
                }

                WSProperty.append("\nDataLink Name: " + devices[k].datalink_name);

                WSProperty.append("\nDataLink Layer Protocol: " + devices[k].datalink_description);
                WSProperty.append("\nLoop Back: " + devices[k].loopback);
            }
        });
    }// GEN-LAST:event_Load_Wireless_btnMouseClicked

    private void ScanNetActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_ScanNetActionPerformed

        if (flag == false) {
            DefaultTableModel model = (DefaultTableModel) tabledisplay.getModel();
            model.setRowCount(0);
            RuleStatus.clear();
            srcIPSetTemp.clear();
            for (count = 0; count < tablemodelRule.getRowCount(); count++) {
                RulePortSet.add(tablemodelRule.getValueAt(count, 5).toString());
                RuleAttempts.add(tablemodelRule.getValueAt(count, 7).toString());
                RuleStatus.add(tablemodelRule.getValueAt(count, 10).toString());

                if (RuleIPSet.contains(tablemodelRule.getValueAt(count, 4).toString())
                        || RuleIPSetCompare.contains(tablemodelRule.getValueAt(count, 4).toString())) {

                } else {
                    RuleNameSet.add(tablemodelRule.getValueAt(count, 1).toString());
                    RuleIPSet.add("/" + tablemodelRule.getValueAt(count, 4).toString());
                    RuleIPSetCompare.add(tablemodelRule.getValueAt(count, 4).toString());
                }
            }

            devices = JpcapCaptor.getDeviceList();
            int i = WS_lists.getSelectedIndex();
            try {
                jpcap = JpcapCaptor.openDevice(devices[i], 65535, false, 500);
                if (captureThread != null) {
                    return;
                }
                captureThread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        while (captureThread != null) {
                            jpcap.processPacket(2, handler);

                        }

                    }
                });
                captureThread.setPriority(Thread.MIN_PRIORITY);
                captureThread.start();
                ScanNet.setText("Stop");
                flag = true;
            } catch (IOException ex) {
                Logger.getLogger(Home.class.getName()).log(Level.SEVERE, null, ex);
            }
        } else {
            flag = false;
            captureThread = null;
            ScanNet.setText("Scan Network");
        }
    }// GEN-LAST:event_ScanNetActionPerformed

    private void jButton2MouseClicked(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_jButton2MouseClicked

        Vector rulesVector = new Vector();
        if (jTextField1.getText() != "" && jTextField5.getText() != "" && jTextField6.getText() != ""
                && jTextField7.getText() != "") {
            RuleNo++;
            rulesVector.addElement(RuleNo);
            rulesVector.addElement(jTextField1.getText());
            RuleNameSet.add(jTextField1.getText());
            rulesVector.addElement(jComboBox2.getSelectedItem());
            rulesVector.addElement(jComboBox3.getSelectedItem());
            rulesVector.addElement(jTextField5.getText());
            RuleIPSet.add(jTextField5.getText());
            rulesVector.addElement(jTextField6.getText());
            RulePortSet.add(jTextField6.getText());
            rulesVector.addElement(jComboBox4.getSelectedItem());
            rulesVector.addElement(jTextField8.getText());
            RuleAttempts.add(jTextField8.getText());
            rulesVector.addElement(jTextField7.getText());
            RuleDescription.add(jTextField7.getText());
            rulesVector.addElement(timeStamp);
            rulesVector.addElement("Inactive");
            nRules = parseInt(jLabel59.getText().toString().trim());
            nRules++;
        } else {
            JOptionPane.showMessageDialog(null, "Please enter all the details", "Message", JOptionPane.ERROR_MESSAGE);
        }
        jLabel59.setText(String.valueOf(nRules));
        RuleRows.addElement(rulesVector);
        tabledisplayRules.addNotify();
        saveToRuleTxt();
        jTextField1.setText("");
        jTextField5.setText("");
        jTextField6.setText("");
        jTextField7.setText("");
        jTextField8.setText("");

    }// GEN-LAST:event_jButton2MouseClicked

    private void jButton3MouseClicked(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_jButton3MouseClicked
        int col = tabledisplayRules.getSelectedColumn();
        int row = tabledisplayRules.getSelectedRow();
        DefaultTableModel model2 = (DefaultTableModel) tabledisplayRules.getModel();
        String timeStamp2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        Object val = model2.getValueAt(row, 10);
        System.out.println(val);
        Object ruleName = model2.getValueAt(row, 1);

        if ("Implemented".equals(val.toString().trim())) {
            System.out.println(ruleName);
            model2.setValueAt("Inactive", row, 10);
            String command = "netsh advfirewall firewall delete rule name=" + ruleName;
            Runtime runtime = Runtime.getRuntime();
            try {
                Process process = runtime.exec(command);
                System.out.println("removed rule from windows firewall");
                jTextArea1.append(
                        timeStamp2 + " ---> Rule: " + ruleName + " has been deactivated. status: Inactive" + "\n");
                jTextArea2.append(
                        timeStamp2 + " ---> Rule: " + ruleName + " has been deactivated. status: Inactive" + "\n");
            } catch (IOException e) {
                e.printStackTrace();
            }

        } else if ("Inactive".equals(val.toString().trim())) {
            model2.setValueAt("Active", row, 10);
        } else if ("Active".equals(val.toString().trim())) {
            model2.setValueAt("Inactive", row, 10);
        }

        RuleNameSet4.clear();
        RuleStatus4.clear();
        for (count = 0; count < tablemodelRule.getRowCount(); count++) {
            // System.out.println(tablemodelRule.getRowCount());
            RuleNameSet4.add(tablemodelRule.getValueAt(count, 1).toString());
            RuleStatus4.add(tablemodelRule.getValueAt(count, 10).toString());
        }
        jTextArea4.setText("");
        for (int m = 0; m < RuleStatus4.size(); m++) {
            if (RuleStatus4.get(m).trim().equals("Active")) {
                jTextArea4.append("Rule: " + RuleNameSet4.get(m).trim() + " ==> Status: Active" + "\n");
            }
        }
        jTextArea2.append(timeStamp2 + " ---> Rule: " + ruleName + " ==> Status: Active" + "\n");

        saveToRuleTxt();
    }// GEN-LAST:event_jButton3MouseClicked

    private void FilterPacketsMouseClicked(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_FilterPacketsMouseClicked
        String ipAdd = jComboBox1.getSelectedItem().toString();
        String proto = jComboBox5.getSelectedItem().toString();
        TableRowSorter<TableModel> sorter = new TableRowSorter<>(packetTableModel);
        tabledisplay.setRowSorter(sorter);
        if (ipAdd.trim().length() == 0 || proto.trim().length() == 0) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(RowFilter.regexFilter("(?i)" + ipAdd));
            sorter.setRowFilter(RowFilter.regexFilter("(?i)" + proto));
        }
    }// GEN-LAST:event_FilterPacketsMouseClicked

    private void button2MouseClicked(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_button2MouseClicked
        initHomeGrpahic();
    }// GEN-LAST:event_button2MouseClicked

    private void btn_exit3MousePressed(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_btn_exit3MousePressed
        System.exit(0);
    }// GEN-LAST:event_btn_exit3MousePressed

    private void btn_exit5MousePressed(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_btn_exit5MousePressed
    }// GEN-LAST:event_btn_exit5MousePressed

    private void jTextField9ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextField9ActionPerformed
    }// GEN-LAST:event_jTextField9ActionPerformed

    private void btn_2MouseClicked(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_btn_2MouseClicked
        setColor(btn_2);
        ind_2.setOpaque(true);
        resetColor(new JPanel[]{btn_3, btn_1, btn_4}, new JPanel[]{ind_3, ind_1, ind_4});
        RuleConfig.setVisible(false);
        Home.setVisible(false);
        IDS.setVisible(false);
        Alerts.setVisible(true);
    }// GEN-LAST:event_btn_2MouseClicked

    private void ResetBtnMouseClicked(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_ResetBtnMouseClicked
        TableRowSorter<TableModel> sorter2 = new TableRowSorter<>(packetTableModel);
        sorter2.setRowFilter(null);
    }// GEN-LAST:event_ResetBtnMouseClicked

    private void jCheckBox1MouseClicked(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_jCheckBox1MouseClicked

        if (jCheckBox1.isSelected() == true) {
            jTextField9.setEditable(false);
        } else {
            jTextField9.setEditable(true);
        }

    }// GEN-LAST:event_jCheckBox1MouseClicked

    private void DeleteRuleMouseClicked(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_DeleteRuleMouseClicked
        DefaultTableModel model = (DefaultTableModel) this.tabledisplayRules.getModel();
        int[] rows = tabledisplayRules.getSelectedRows();
        for (int i = 0; i < rows.length; i++) {
            model.removeRow(rows[i] - i);
            jLabel59.setText(String.valueOf(tablemodelRule.getRowCount()));
            saveToRuleTxt();
        }
    }// GEN-LAST:event_DeleteRuleMouseClicked

    private void btn_exit4MousePressed(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_btn_exit4MousePressed

    }// GEN-LAST:event_btn_exit4MousePressed

    private void jButton1MouseClicked(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_jButton1MouseClicked
        RowFilter<Object, Object> rf = null;
        List<RowFilter<Object, Object>> filters = new ArrayList<RowFilter<Object, Object>>();
        if (jComboBox7.getSelectedItem().toString().trim() != "") {
            filters.add(RowFilter.regexFilter(jComboBox7.getSelectedItem().toString().trim(), 2));
        } else if (jComboBox8.getSelectedItem().toString().trim() != "") {
            filters.add(RowFilter.regexFilter(jComboBox8.getSelectedItem().toString().trim(), 3));
        } else if (jComboBox9.getSelectedItem().toString().trim() != "") {
            filters.add(RowFilter.regexFilter(jComboBox9.getSelectedItem().toString().trim(), 5));
        } else if (jComboBox10.getSelectedItem().toString().trim() != "") {
            filters.add(RowFilter.regexFilter(jComboBox10.getSelectedItem().toString().trim(), 6));
        } else if (jComboBox11.getSelectedItem().toString().trim() != "") {
            filters.add(RowFilter.regexFilter(jComboBox11.getSelectedItem().toString().trim(), 10));
        }

        try {
            rf = RowFilter.orFilter(filters);
        } catch (java.util.regex.PatternSyntaxException e) {
            return;
        }
        TableRowSorter<TableModel> sorter5 = new TableRowSorter<>(tablemodelRule);
        sorter5.setRowFilter(rf);
        tabledisplayRules.setRowSorter(sorter5);
    }// GEN-LAST:event_jButton1MouseClicked

    private final PacketReceiver handler = new PacketReceiver() {
        @Override
        public void receivePacket(Packet packet) {

            try {
                String timeStamp3 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
                Vector r = new Vector();
                No++;
                r.addElement(No);
                r.addElement(timeStamp3.toString());
                if (packet instanceof TCPPacket) {
                    tcp = (TCPPacket) packet;
                    r.addElement(tcp.src_ip.toString());
                    r.addElement(tcp.dst_ip.toString());
                    r.addElement("TCP");
                    r.addElement(tcp.src_port);
                    r.addElement(tcp.dst_port);
                    r.addElement(tcp.dont_frag == true ? "Yes" : "No");
                    r.addElement(tcp.offset);

                } else if (packet instanceof UDPPacket) {
                    udp = (UDPPacket) packet;
                    r.addElement(udp.src_ip.toString());
                    r.addElement(udp.dst_ip.toString());
                    r.addElement("UDP");
                    r.addElement(udp.src_port);
                    r.addElement(udp.dst_port);
                    r.addElement(udp.dont_frag == true ? "Yes" : "No"); //
                    r.addElement(udp.offset);

                } else if (packet instanceof ICMPPacket) {
                    icmp = (ICMPPacket) packet;
                    r.addElement(icmp.src_ip.toString());
                    r.addElement(icmp.dst_ip.toString());
                    r.addElement("ICMP");
                    r.addElement("Null");
                    r.addElement("Null");
                    r.addElement(icmp.dont_frag == true ? "Yes" : "No"); //
                    r.addElement(icmp.offset);
                }

                srcIPSetTemp.add((String) r.elementAt(2));
                if (r.isEmpty()) {

                } else {
                    packetTableModel.addRow(r);
                }

                if (srcIPSet.contains((String) r.elementAt(2)) || ((String) r.elementAt(1) == "/172.20.10.9")) {
                    // System.out.println("IP already exist");
                    // do nothing
                } else {
                    srcIPSet.add((String) r.elementAt(2));
                }

                if (destIPSet.contains((String) r.elementAt(3)) || ((String) r.elementAt(2) == "/172.20.10.9")) {

                } else {

                    destIPSet.add((String) r.elementAt(3));
                }
                AllIPSet.addAll(srcIPSet);
                AllIPSet.addAll(destIPSet);

                UnknownIPSet.addAll(srcIPSet);
                destIPSet.stream().filter((element) -> (!UnknownIPSet.contains(element))).forEachOrdered((element) -> {
                    UnknownIPSet.add(element);
                });

                for (int k = 0; k < UnknownIPSet.size(); k++) {
                    if (((DefaultComboBoxModel) jComboBox1.getModel()).getIndexOf(UnknownIPSet.get(k)) == -1) {
                        jComboBox1.addItem(UnknownIPSet.get(k));
                    }
                }

                if (r.elementAt(4) == "TCP" || r.elementAt(4) == "UDP" || r.elementAt(4) == "ICMP") {
                    ProtocolSet.add((String) r.elementAt(4));
                    for (int y = 0; y < ProtocolSet.size(); y++) {
                        if (((DefaultComboBoxModel) jComboBox5.getModel()).getIndexOf(ProtocolSet.get(y)) == -1) {
                            jComboBox5.addItem(ProtocolSet.get(y));
                        }
                    }
                }

                if (srcPortSet.contains(r.elementAt(5)) || destPortSet.contains(r.elementAt(6))) {
                    // do nothing
                } else {
                    srcPortSet.add((String) r.elementAt(5));
                    destPortSet.add((String) r.elementAt(6));
                }
                System.out.println(srcPortSet);
                System.out.println(destPortSet);
                AllPortSet.addAll(srcPortSet);
                for (String element : destPortSet) {
                    if (!AllPortSet.contains(element)) {
                        AllPortSet.add(element);
                    }
                }
                System.out.println(AllPortSet);
                for (int j = 0; j < AllPortSet.size(); j++) {
                    if (((DefaultComboBoxModel) jComboBox6.getModel()).getIndexOf(AllPortSet.get(j)) == -1) {
                        jComboBox6.addItem(AllPortSet.get(j));
                    }
                }

            } catch (Exception e) {

            }

            int size2 = srcIPSetTemp.size();
            int size3 = RuleStatus.size();
            String timeStamp4 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
            for (int m = 0; m < size3; m++) {

                if (RuleStatus.get(m).trim().equals("Active")) {
                    for (int j = 0; j < size2; j++) {

                        if (RuleIPSet.get(m).trim().equals(srcIPSetTemp.get(j).trim())) {
                            System.out.println("true");
                            IPCounter++;
                            if (IPCounter <= Integer.parseInt((RuleAttempts.get(m).trim()))) {
                                jTextArea2.append(timeStamp4 + " ---> " + RuleIPSet.get(m).trim()
                                        + " is detected in the network traffic, Times: " + IPCounter + "\n");
                            } else {
                                String command = "netsh advfirewall firewall add rule name=" + RuleNameSet.get(m).trim()
                                        + " Dir=Out Action=Block RemoteIP=" + RuleIPSetCompare.get(m).trim();
                                Runtime runtime = Runtime.getRuntime();
                                try {
                                    Process process = runtime.exec(command);
                                    int col = 10;
                                    int row = m;
                                    DefaultTableModel model = (DefaultTableModel) tabledisplayRules.getModel();
                                    Object val = model.getValueAt(row, col);
                                    model.setValueAt("Implemented", row, col);
                                    saveToRuleTxt();
                                    jTextArea1.append(timeStamp4 + " ---> Rule Name: " + RuleNameSet.get(m).trim()
                                            + " is added into the Firewall\n");
                                    jTextArea1.append(timeStamp4 + " ---> " + RuleIPSet.get(m).trim()
                                            + " is added into the firewall. status: Blocked" + "\n");
                                    jTextArea3.append(timeStamp4 + "\n" + "Rule: " + RuleNameSet.get(m).trim() + " "
                                            + RuleIPSet.get(m).trim() + ":Blocked" + "\n");
                                    jTextArea3.append("--------------------------------------------");
                                    jTextArea2.append(timeStamp4 + " ---> Rule Name: " + RuleNameSet.get(m).trim()
                                            + " is added into the Firewall\n");
                                    jTextArea2.append(timeStamp4 + " ---> " + RuleIPSet.get(m).trim()
                                            + " is added into the firewall. status: Blocked" + "\n");
                                    javax.swing.JOptionPane.showMessageDialog(null,
                                            "A suspicous attemp has been blocked\n" + "\nSuspicous IP Address: "
                                            + RuleIPSetCompare.get(m).trim() + "\nNumber of IP Address: 1"
                                            + "\nProtocol: TCP" + "\nPort Number: " + RulePortSet.get(m).trim()
                                            + "\nAttemps: " + RuleAttempts.get(m).trim() + "\nStatus: Blocked",
                                            "Notification", 2);
                                    if (jTextField9.getText().equals("")) {
                                        // do nothing
                                    } else {
                                        try {
                                            SendAlert(m);
                                        } catch (MessagingException ex) {
                                            Logger.getLogger(Home.class.getName()).log(Level.SEVERE, null, ex);
                                        }
                                    }
                                    RuleIPSet.set(m, "checked");
                                    cBlockedAttck++;
                                    cLowAttck++;
                                    jLabel56.setText(String.valueOf(cLowAttck));
                                    Block_Num.setText(String.valueOf(cBlockedAttck));
                                } catch (IOException e) {
                                    e.printStackTrace();
                                }

                            }

                        } else {
                            j++;
                        }
                    }
                } else { // implemented. inactive
                    m++;
                }
            }
            newdeal(packet);
            UpdateHomeGrpahic();
            tabledisplay.addNotify();
            tabledisplay.validate();
            jPanel91.repaint();
            jPanel92.repaint();
        }

        private void SendAlert(int m) throws AddressException, MessagingException {
            String timeStamp5 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Calendar.getInstance().getTime());
            // Step1
            System.out.println("\n 1st ===> Setup Mail Server Properties..");
            jTextArea2.append(timeStamp5 + " ---> " + "1st ===> Setup Mail Server Properties..\n");
            mailServerProperties = System.getProperties();
            mailServerProperties.put("mail.smtp.port", "587");
            mailServerProperties.put("mail.smtp.auth", "true");
            mailServerProperties.put("mail.smtp.starttls.enable", "true");
            System.out.println("Mail Server Properties have been setup successfully..");
            jTextArea2.append(timeStamp5 + " ---> " + "Mail Server Properties have been setup successfully..\n");
            // Step2
            System.out.println("\n\n 2nd ===> get Mail Session..");
            jTextArea2.append(timeStamp5 + " ---> " + " 2nd ===> get Mail Session..\n");
            getMailSession = Session.getDefaultInstance(mailServerProperties, null);
            generateMailMessage = new MimeMessage(getMailSession);
            generateMailMessage.addRecipient(Message.RecipientType.TO,
                    new InternetAddress(jTextField9.getText().trim()));
            // generateMailMessage.addRecipient(Message.RecipientType.CC, new
            // InternetAddress("test2@crunchify.com"));
            generateMailMessage.setSubject("Warning, A Intrusion has been detected and blocked!");
            String emailBody = "<br>*************************************************************************************"
                    + "<br><strong>This Email is automatically sent by Intrusion Detection System."
                    + "<br>Please do not reply to this email.<strong>"
                    + "<br>**************************************************************************************"
                    + "<br>" + "<br>Event: A suspicous attemp has been blocked by Intrution Detection System" + "<br>"
                    + "<br><hr>Suspicous IP Address: " + RuleIPSetCompare.get(m).trim() + "<br>Number of IP Address: 1"
                    + "<br>Protocol: TCP" + "<br>Port Number: " + RulePortSet.get(m).trim() + "<br>Attemps: "
                    + RuleAttempts.get(m).trim() + "<br>" + "<br>Triggerred by Rule: " + RuleNameSet.get(m).trim()
                    + "<br>Current Status: Implemented" + "<br>Time: " + timeStamp5 + "<br>" + "<hr>" + "<br> Regards, "
                    + "<br>Du Mengyu" + "<br>Intrusion Detection System";

            generateMailMessage.setContent(emailBody, "text/html");

            System.out.println("Mail Session has been created successfully..");
            jTextArea2.append(timeStamp5 + " ---> " + "Mail Session has been created successfully..\n");
            // Step3
            System.out.println("\n\n 3rd ===> Get Session and Send mail");
            jTextArea2.append(timeStamp5 + " ---> " + "Get Session and sening email..\n");
            Transport transport = getMailSession.getTransport("smtp");
            // Enter your correct gmail UserID and Password
            // if you have 2FA enabled then provide App Specific Password
            transport.connect("smtp.gmail.com", "cit.intrusiondetection@gmail.com", "gvrzqqsbztichsoh");
            transport.sendMessage(generateMailMessage, generateMailMessage.getAllRecipients());
            transport.close();
            jTextArea2.append(timeStamp5 + " ---> " + "Email has been sent out..\n");
        }
    };

    public void newdeal(Packet packet) {
        if (packet.getClass().equals(TCPPacket.class)) {
            ctcp++;
            tcp_num.setText(String.valueOf(ctcp));
            dtcp += (double) packet.len / 1024;
        } else if (packet.getClass().equals(UDPPacket.class)) {
            cudp++;
            UDP_num.setText(String.valueOf(cudp));
            dudp += (double) packet.len / 1024;
        } else if (packet.getClass().equals(ICMPPacket.class)) {
            cicmp++;
            ICMP_num.setText(String.valueOf(cicmp));
            dicmp += (double) packet.len / 1024;
        }
    }

    private void initRuleConfiguration() {
        devices = JpcapCaptor.getDeviceList();
        for (int i = 0; i < devices.length; i++) {
            jComboBox2.addItem(i + 1 + ": " + devices[i].description);
            jComboBox7.addItem(i + 1 + ": " + devices[i].description);
        }

        jPanel4.setLayout(new BorderLayout());
        RuleRows = new Vector();
        RuleColumns = new Vector();

        RuleColumns.addElement("Rule No");
        RuleColumns.addElement("Rule Name");
        RuleColumns.addElement("Wireless Card");
        RuleColumns.addElement("Protocol");
        RuleColumns.addElement("IP Number");
        RuleColumns.addElement("Port Number");
        RuleColumns.addElement("Actions");
        RuleColumns.addElement("Attempts");
        RuleColumns.addElement("Description");
        RuleColumns.addElement("Added Time");
        RuleColumns.addElement("Status");
        FileReader reader;
        try {
            reader = new FileReader(RULEFILENAME);
            BufferedReader br = new BufferedReader(reader);
            String eachLine = null;
            try {
                while ((eachLine = br.readLine()) != null) {

                    String[] temp = eachLine.split(",");
                    Vector<String> row = new Vector<String>();
                    for (int i = 0; i < temp.length; i++) {
                        row.add(temp[i]);
                    }
                    RuleRows.add(row);
                }
            } catch (IOException ex) {
                Logger.getLogger(Home.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Home.class.getName()).log(Level.SEVERE, null, ex);
        }

        tablemodelRule = new DefaultTableModel();
        tablemodelRule.setDataVector(RuleRows, RuleColumns);
        tabledisplayRules = new JTable(tablemodelRule);
        for (count = 0; count < tabledisplayRules.getRowCount(); count++) {
            RuleNameSet3.add(tabledisplayRules.getValueAt(count, 1).toString());
            RulePortSet3.add(tabledisplayRules.getValueAt(count, 5).toString());
            RuleStatus3.add(tabledisplayRules.getValueAt(count, 10).toString());
        }
        jLabel59.setText(String.valueOf(tabledisplayRules.getRowCount()));
        for (int p = 0; p < RulePortSet3.size(); p++) {
            jComboBox9.addItem(RulePortSet3.get(p));
            if (RuleStatus3.get(p).toString().trim().equals("Active")) {
                jTextArea4.append("Rule: " + RuleNameSet3.get(p) + " ==> Status: Active" + "\n");
            }
        }
        tabledisplayRules.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        tabledisplayRules.getColumnModel().getColumn(0).setPreferredWidth(65);
        tabledisplayRules.getColumnModel().getColumn(1).setPreferredWidth(100);
        tabledisplayRules.getColumnModel().getColumn(2).setPreferredWidth(120);
        tabledisplayRules.getColumnModel().getColumn(3).setPreferredWidth(80);
        tabledisplayRules.getColumnModel().getColumn(4).setPreferredWidth(140);
        tabledisplayRules.getColumnModel().getColumn(5).setPreferredWidth(100);
        tabledisplayRules.getColumnModel().getColumn(6).setPreferredWidth(80);
        tabledisplayRules.getColumnModel().getColumn(7).setPreferredWidth(80);
        tabledisplayRules.getColumnModel().getColumn(8).setPreferredWidth(100);
        tabledisplayRules.getColumnModel().getColumn(9).setPreferredWidth(150);
        tabledisplayRules.getColumnModel().getColumn(10).setPreferredWidth(120);
        tabledisplayRules.setFont(new Font("Tahoma", Font.PLAIN, 15));
        jPanel4.add(new JScrollPane(tabledisplayRules), BorderLayout.CENTER);
    }

    private void initIDS() {
        jPanel3.setLayout(new BorderLayout());
        rows = new Vector();
        columns = new Vector();

        columns.addElement("PacketNo");
        columns.addElement("Time");
        columns.addElement("Source IP");
        columns.addElement("Dest IP");
        columns.addElement("Protocol");
        columns.addElement("Source Port");
        columns.addElement("Dest Port");
        columns.addElement("Fragment");
        columns.addElement("Offset");

        packetTableModel = new DefaultTableModel();
        packetTableModel.setDataVector(rows, columns);
        tabledisplay = new JTable(packetTableModel);
        tabledisplay.setEnabled(false);

        tabledisplay.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        tabledisplay.getColumnModel().getColumn(0).setPreferredWidth(100);
        tabledisplay.getColumnModel().getColumn(1).setPreferredWidth(200);
        tabledisplay.getColumnModel().getColumn(2).setPreferredWidth(160);
        tabledisplay.getColumnModel().getColumn(3).setPreferredWidth(160);
        tabledisplay.getColumnModel().getColumn(4).setPreferredWidth(80);
        tabledisplay.getColumnModel().getColumn(5).setPreferredWidth(130);
        tabledisplay.getColumnModel().getColumn(6).setPreferredWidth(130);
        tabledisplay.getColumnModel().getColumn(7).setPreferredWidth(80);
        tabledisplay.getColumnModel().getColumn(8).setPreferredWidth(80);
        tabledisplay.setFont(new Font("Tahoma", Font.PLAIN, 15));
        jPanel3.add(new JScrollPane(tabledisplay), BorderLayout.CENTER);
    }

    private void saveToRuleTxt() {
        try {
            File file = new File("C:\\Users\\du\\Desktop\\IDS\\Java_Intrusion-Detection-System-master\\"
                    + "FYPProjects_SEMIFinal\\TempDB\\RuleText.txt");
            FileWriter fw = new FileWriter(file.getAbsoluteFile());
            try (BufferedWriter bfw = new BufferedWriter(fw)) {
                for (int i = 0; i < tabledisplayRules.getRowCount(); i++) {
                    for (int j = 0; j < tabledisplayRules.getColumnCount(); j++) {
                        bfw.write((String) (tabledisplayRules.getValueAt(i, j).toString()));
                        bfw.write(",");
                    }
                    bfw.newLine();
                }
            }
        } catch (IOException ex) {
        }
    }

    private void UpdateHomeGrpahic() {
        dataset.setValue("TCP", ctcp);
        dataset.setValue("UDP", cudp);
        dataset.setValue("ICMP", cicmp);

        dataset1.addValue(dtcp, "TCP", "Data Traffic");
        dataset1.addValue(dudp, "UDP", "Data Traffic");
        dataset1.addValue(dicmp, "ICMP", "Data Traffic");
    }

    private void initHomeGrpahic() {
        Font font3 = new Font("Tahoma", Font.PLAIN, 18);
        pieChart.getTitle().setFont(new Font("Tahoma", Font.PLAIN, 18));
        PiePlot plot = (PiePlot) pieChart.getPlot();
        plot.setLabelFont(font3);
        CategoryPlot plot2 = barChart1.getCategoryPlot();

        plot2.getDomainAxis().setLabelFont(font3);
        plot2.getRangeAxis().setLabelFont(font3);
        BorderLayout thisLayout = new BorderLayout();
        jPanel6.setLayout(new BorderLayout());
        try {
            {
                jPanel6.setLayout(thisLayout);
                {

                    jPanel91 = new JPanel();
                    jPanel6.add(jPanel91);
                    jPanel91.setPreferredSize(new java.awt.Dimension(554, 500));
                    {
                        ChartPanel myChart1 = new ChartPanel(pieChart);
                        jPanel91.add(myChart1);
                        myChart1.setPreferredSize(new java.awt.Dimension(550, 490));
                        myChart1.setVisible(true);
                    }

                }
                {
                    jPanel92 = new JPanel();
                    jPanel6.add(jPanel92, BorderLayout.EAST);
                    jPanel92.setPreferredSize(new java.awt.Dimension(554, 500));
                    {
                        ChartPanel myChart = new ChartPanel(barChart1);
                        jPanel92.add(myChart);
                        myChart.setPreferredSize(new java.awt.Dimension(500, 473));
                        myChart.setVisible(true);
                    }

                }
            }
            jPanel6.setSize(500, 659);
            jPanel6.updateUI();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        // <editor-fold defaultstate="collapsed" desc=" Look and feel setting code
        // (optional) ">
        /*
		 * If Nimbus (introduced in Java SE 6) is not available, stay with the default
		 * look and feel. For details see
		 * http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Windows".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Home.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Home.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Home.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Home.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        // </editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                // System.out.println(System.getProperty("java.library.path"));
                new Home().setVisible(true);
            }
        });
    }

    private void setColor(JPanel pane) {
        pane.setBackground(new Color(41, 57, 80));
    }

    private void resetColor(JPanel[] pane, JPanel[] indicators) {
        for (int i = 0; i < pane.length; i++) {
            pane[i].setBackground(new Color(23, 35, 51));

        }
        for (int i = 0; i < indicators.length; i++) {
            indicators[i].setOpaque(false);
        }

    }

	// Variables declaration - do not modify//GEN-BEGIN:variables
	private javax.swing.JPanel Alerts;
	private javax.swing.JLabel Block_Num;
	private javax.swing.JButton DeleteRule;
	private javax.swing.JButton FilterPackets;
	private javax.swing.JPanel Home;
	private javax.swing.JLabel HomeBtn;
	private javax.swing.JLabel ICMP_num;
	private javax.swing.JPanel IDS;
	private javax.swing.JButton Load_Wireless_btn;
	private javax.swing.JButton ResetBtn;
	private javax.swing.JButton ResetRuleBtn;
	private javax.swing.JPanel RuleConfig;
	private javax.swing.JButton ScanNet;
	private javax.swing.JLabel UDP_num;
	private javax.swing.JTextArea WSProperty;
	private javax.swing.JComboBox<String> WS_lists;
	private javax.swing.JPanel btn_1;
	private javax.swing.JPanel btn_2;
	private javax.swing.JPanel btn_3;
	private javax.swing.JPanel btn_4;
	private javax.swing.JLabel btn_exit3;
	private javax.swing.JLabel btn_exit4;
	private javax.swing.JLabel btn_exit5;
	private javax.swing.JButton button2;
	private javax.swing.JPanel ind_1;
	private javax.swing.JPanel ind_2;
	private javax.swing.JPanel ind_3;
	private javax.swing.JPanel ind_4;
	private javax.swing.JButton jButton1;
	private javax.swing.JButton jButton2;
	private javax.swing.JButton jButton3;
	private javax.swing.JCheckBox jCheckBox1;
	private javax.swing.JComboBox<String> jComboBox1;
	private javax.swing.JComboBox<String> jComboBox10;
	private javax.swing.JComboBox<String> jComboBox11;
	private javax.swing.JComboBox<String> jComboBox2;
	private javax.swing.JComboBox<String> jComboBox3;
	private javax.swing.JComboBox<String> jComboBox4;
	private javax.swing.JComboBox<String> jComboBox5;
	private javax.swing.JComboBox<String> jComboBox6;
	private javax.swing.JComboBox<String> jComboBox7;
	private javax.swing.JComboBox<String> jComboBox8;
	private javax.swing.JComboBox<String> jComboBox9;
	private javax.swing.JFrame jFrame1;
	private javax.swing.JLabel jLabel1;
	private javax.swing.JLabel jLabel10;
	private javax.swing.JLabel jLabel11;
	private javax.swing.JLabel jLabel12;
	private javax.swing.JLabel jLabel13;
	private javax.swing.JLabel jLabel14;
	private javax.swing.JLabel jLabel15;
	private javax.swing.JLabel jLabel16;
	private javax.swing.JLabel jLabel17;
	private javax.swing.JLabel jLabel18;
	private javax.swing.JLabel jLabel19;
	private javax.swing.JLabel jLabel2;
	private javax.swing.JLabel jLabel20;
	private javax.swing.JLabel jLabel21;
	private javax.swing.JLabel jLabel22;
	private javax.swing.JLabel jLabel23;
	private javax.swing.JLabel jLabel26;
	private javax.swing.JLabel jLabel27;
	private javax.swing.JLabel jLabel28;
	private javax.swing.JLabel jLabel29;
	private javax.swing.JLabel jLabel3;
	private javax.swing.JLabel jLabel30;
	private javax.swing.JLabel jLabel31;
	private javax.swing.JLabel jLabel32;
	private javax.swing.JLabel jLabel33;
	private javax.swing.JLabel jLabel34;
	private javax.swing.JLabel jLabel35;
	private javax.swing.JLabel jLabel36;
	private javax.swing.JLabel jLabel39;
	private javax.swing.JLabel jLabel4;
	private javax.swing.JLabel jLabel40;
	private javax.swing.JLabel jLabel42;
	private javax.swing.JLabel jLabel43;
	private javax.swing.JLabel jLabel44;
	private javax.swing.JLabel jLabel45;
	private javax.swing.JLabel jLabel47;
	private javax.swing.JLabel jLabel48;
	private javax.swing.JLabel jLabel49;
	private javax.swing.JLabel jLabel5;
	private javax.swing.JLabel jLabel52;
	private javax.swing.JLabel jLabel53;
	private javax.swing.JLabel jLabel54;
	private javax.swing.JLabel jLabel55;
	private javax.swing.JLabel jLabel56;
	private javax.swing.JLabel jLabel57;
	private javax.swing.JLabel jLabel59;
	private javax.swing.JLabel jLabel6;
	private javax.swing.JLabel jLabel60;
	private javax.swing.JLabel jLabel61;
	private javax.swing.JLabel jLabel62;
	private javax.swing.JLabel jLabel64;
	private javax.swing.JLabel jLabel65;
	private javax.swing.JLabel jLabel7;
	private javax.swing.JLabel jLabel8;
	private javax.swing.JLabel jLabel9;
	private javax.swing.JPanel jPanel1;
	private javax.swing.JPanel jPanel12;
	private javax.swing.JPanel jPanel13;
	private javax.swing.JPanel jPanel14;
	private javax.swing.JPanel jPanel15;
	private javax.swing.JPanel jPanel16;
	private javax.swing.JPanel jPanel17;
	private javax.swing.JPanel jPanel18;
	private javax.swing.JPanel jPanel19;
	private javax.swing.JPanel jPanel2;
	private javax.swing.JPanel jPanel20;
	private javax.swing.JPanel jPanel21;
	private javax.swing.JPanel jPanel22;
	private javax.swing.JPanel jPanel23;
	private javax.swing.JPanel jPanel24;
	private javax.swing.JPanel jPanel25;
	private javax.swing.JPanel jPanel26;
	private javax.swing.JPanel jPanel27;
	private javax.swing.JPanel jPanel28;
	private javax.swing.JPanel jPanel29;
	private javax.swing.JPanel jPanel3;
	private javax.swing.JPanel jPanel30;
	private javax.swing.JPanel jPanel31;
	private javax.swing.JPanel jPanel32;
	private javax.swing.JPanel jPanel33;
	private javax.swing.JPanel jPanel34;
	private javax.swing.JPanel jPanel35;
	private javax.swing.JPanel jPanel36;
	private javax.swing.JPanel jPanel37;
	private javax.swing.JPanel jPanel38;
	private javax.swing.JPanel jPanel39;
	private javax.swing.JPanel jPanel4;
	private javax.swing.JPanel jPanel40;
	private javax.swing.JPanel jPanel41;
	private javax.swing.JPanel jPanel43;
	private javax.swing.JPanel jPanel44;
	private javax.swing.JPanel jPanel5;
	private javax.swing.JPanel jPanel6;
	private javax.swing.JPanel jPanel8;
	private javax.swing.JPanel jPanel9;
	private javax.swing.JScrollPane jScrollPane1;
	private javax.swing.JScrollPane jScrollPane2;
	private javax.swing.JScrollPane jScrollPane3;
	private javax.swing.JScrollPane jScrollPane4;
	private javax.swing.JScrollPane jScrollPane5;
	private javax.swing.JSeparator jSeparator3;
	private javax.swing.JSeparator jSeparator4;
	private javax.swing.JSeparator jSeparator6;
	private javax.swing.JTextArea jTextArea1;
	private javax.swing.JTextArea jTextArea2;
	private javax.swing.JTextArea jTextArea3;
	private javax.swing.JTextArea jTextArea4;
	private javax.swing.JTextField jTextField1;
	private javax.swing.JTextField jTextField2;
	private javax.swing.JTextField jTextField3;
	private javax.swing.JTextField jTextField4;
	private javax.swing.JTextField jTextField5;
	private javax.swing.JTextField jTextField6;
	private javax.swing.JTextField jTextField7;
	private javax.swing.JTextField jTextField8;
	private javax.swing.JTextField jTextField9;
	private javax.swing.JPanel side_pane;
	private javax.swing.JLabel tcp_num;
	// End of variables declaration//GEN-END:variables

}

package swing;

import java.awt.BorderLayout;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.category.DefaultCategoryDataset;


/**
* This code was edited or generated using CloudGarden's Jigloo
* SWT/Swing GUI Builder, which is free for non-commercial
* use. If Jigloo is being used commercially (ie, by a corporation,
* company or business for any purpose whatever) then you
* should purchase a license for each developer using Jigloo.
* Please visit www.cloudgarden.com for details.
* Use of Jigloo implies acceptance of these licensing terms.
* A COMMERCIAL LICENSE HAS NOT BEEN PURCHASED FOR
* THIS MACHINE, SO JIGLOO OR THIS CODE CANNOT BE USED
* LEGALLY FOR ANY CORPORATE OR COMMERCIAL PURPOSE.
*/
public class newChart1 extends javax.swing.JDialog {
	private JPanel jPanel1;
	private JPanel jPanel2;
	private JLabel jLabel1;
	private JPanel jPanel3;

	/**
	* Auto-generated main method to display this JDialog
	*/
	public static void main(String[] args) {
		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				JFrame frame = new JFrame();
				newChart1 inst = new newChart1(frame);
				inst.setVisible(true);
			}
		});
	}
	
	public newChart1(JFrame frame) {
		super(frame);
		initGUI();
		this.setLocationRelativeTo(null);
	}
	
	private void initGUI() {
		//10-11 new add.
		//�������ӻ�
		DefaultCategoryDataset dataset = new DefaultCategoryDataset();
		dataset.addValue(newCount.ctcp, "TCP", "����");
		dataset.addValue(newCount.cudp, "UDP", "����");
		dataset.addValue(newCount.cicmp, "ICMP", "����");
		//dataset.addValue(newCount.carp, "ARP", "����");
		//dataset.addValue(newCount.cGuangBo, "�㲥��", "����");
		JFreeChart barChart = ChartFactory.createBarChart("���ݰ�ͳ�ƽ��", "���ݰ�����", "����(��)", dataset,
				PlotOrientation.HORIZONTAL, true, true, false);
		//�������ӻ�
		DefaultCategoryDataset dataset1 = new DefaultCategoryDataset();
		dataset1.addValue(newCount.dtcp, "TCP", "����");
		dataset1.addValue(newCount.dudp, "UDP", "����");
		dataset1.addValue(newCount.dicmp, "ICMP", "����");
		//dataset1.addValue(newCount.darp, "ARP", "����");
		//dataset1.addValue(newCount.dGuangBo, "�㲥��", "����");
		JFreeChart barChart1 = ChartFactory.createBarChart("����ͳ�ƽ��", "���ݰ�����", "����(KB)", dataset1,
				PlotOrientation.HORIZONTAL, true, true, false);
		
		try {
			{
				BorderLayout thisLayout = new BorderLayout();
				getContentPane().setLayout(thisLayout);
				{
					jPanel1 = new JPanel();
					getContentPane().add(jPanel1, BorderLayout.NORTH);
					jPanel1.setPreferredSize(new java.awt.Dimension(384, 66));
					jPanel1.setLayout(null);
					{
						jLabel1 = new JLabel();
						jPanel1.add(jLabel1);
						jLabel1.setText("\u7ed3\u679c\u56fe\u8868\u663e\u793a");
						jLabel1.setBounds(159, 12, 81, 42);
					}
				}
				{
					//�������Ǹ����
					jPanel2 = new JPanel();
					getContentPane().add(jPanel2);
					jPanel2.setPreferredSize(new java.awt.Dimension(358, 97));
					{
						ChartPanel myChart1 = new ChartPanel(barChart);
						jPanel2.add(myChart1);
						myChart1.setPreferredSize(new java.awt.Dimension(386, 173));
					}
				}
				{
					//�м������ʾ
					jPanel3 = new JPanel();
					getContentPane().add(jPanel3, BorderLayout.SOUTH);
					jPanel3.setPreferredSize(new java.awt.Dimension(384, 178));
					{
						ChartPanel myChart = new ChartPanel(barChart1);
						jPanel3.add(myChart);
						myChart.setPreferredSize(new java.awt.Dimension(386, 173));
					}
				}
				{
					
				}
			}
			this.setSize(400, 459);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}

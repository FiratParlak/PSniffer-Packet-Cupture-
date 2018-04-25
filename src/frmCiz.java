import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.util.Objects;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.category.DefaultCategoryDataset;

public class frmCiz extends JFrame {

	private JPanel contentPane;

	/**
	 * Launch the application.
	 */
	public static void main(DefaultCategoryDataset dataset, String IP) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					frmCiz frame = new frmCiz(dataset, IP);
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
    private JFreeChart lineChart ;
    private ChartPanel chartPanel;
	/**
	 * Create the frame.
	 */
	public frmCiz(DefaultCategoryDataset dataset, String IP) {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 450, 300);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		contentPane.setLayout(new BorderLayout(0, 0));
		setContentPane(contentPane);


	      
 		  lineChart = ChartFactory.createLineChart(
 				 IP,
                  "Zaman","Adet",
                  dataset,
                  PlotOrientation.VERTICAL,
                  true,true,false);
                  
               chartPanel = new ChartPanel( lineChart );
               chartPanel.setPreferredSize( new java.awt.Dimension( 300 , 300 ) );
               chartPanel.setBounds(925,264,400,400);
               
               contentPane.add(chartPanel);
               
	
               contentPane.revalidate();
               contentPane.repaint();
	}

}

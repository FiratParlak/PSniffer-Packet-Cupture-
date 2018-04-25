import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.EventQueue;
import java.io.File; 
import java.io.FileInputStream;
import java.text.SimpleDateFormat;
import java.net.InetAddress;
import java.net.UnknownHostException;

import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JToggleButton;
import javax.swing.ListSelectionModel;

import java.awt.GridLayout;
import java.awt.Toolkit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JTable;
import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;


import org.jfree.chart.ChartPanel;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.JFreeChart;
import org.jfree.ui.ApplicationFrame;
import org.jfree.ui.RefineryUtilities;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.category.DefaultCategoryDataset;

import org.jfree.chart.ChartFactory; 
import org.jfree.chart.ChartPanel; 
import org.jfree.chart.JFreeChart; 
import org.jfree.data.general.SeriesException; 
import org.jfree.data.time.Second; 
import org.jfree.data.time.TimeSeries; 
import org.jfree.data.time.TimeSeriesCollection; 
import org.jfree.data.xy.XYDataset; 
import org.jfree.ui.ApplicationFrame; 
import org.jfree.ui.RefineryUtilities;

import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.util.checksum.Checksum;



import javax.swing.JScrollPane;
import javax.swing.JTable;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;


import net.sourceforge.jpcap.capture.PacketCapture;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class PacketAnalysisForm extends JFrame {

	private JPanel contentPane;
	private JPanel tablo;
	/**
	 * Launch the application.
	 */
	private JFileChooser filedialog; 
	private File filepcap;
	private JTable table;
	private JButton Capture,Stop,Save,Load;
    private static  PcapIf devc;
	private static JButton ListDevice;
	private static JList Interfaces;
	private static boolean value=false;
	private static JButton SelectDevice;
	public  static DefaultTableModel tablemodel;
	public  static  Thread t;
	private static Pcap pcap;
	public  static DefaultListModel device;
    private JScrollPane jScrollPane2, scrollPane;
    private static PacketAnalysisForm frame;
    public String path;
    public static List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Bütün NIC leri al
    
    private static String SecilenIP = "";
    
    private JFreeChart lineChart ;
    private ChartPanel chartPanel;
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					frame = new PacketAnalysisForm();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public PacketAnalysisForm() {
		setTitle("Packet Analysis");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
//      Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
//      setBounds(0,0, screenSize.width, screenSize.height);
        setExtendedState(JFrame.MAXIMIZED_BOTH);
        contentPane = new JPanel();
      
        //contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        setContentPane(contentPane);
        contentPane.setLayout(null); 
        
        scrollPane = new JScrollPane();
       
        scrollPane.setBounds(15, 10, 961, 500);
        contentPane.add(scrollPane);
        contentPane.setBackground(Color.CYAN);
        tablemodel=new DefaultTableModel( );	    
	    table = new JTable(tablemodel);
	    table.addMouseListener(new MouseAdapter() {
	    	@Override
	    	public void mouseClicked(MouseEvent e) {
	    		if (e.getClickCount() == 2 && table.getSelectedColumn() == 2){
	    			packetNumber = 0;
        			int row = table.getSelectedRow();
            		int column = table.getSelectedColumn();
            		SecilenIP = (String)table.getValueAt(row, column);
            		
            		 JOptionPane.showMessageDialog(contentPane,SecilenIP,"",JOptionPane.INFORMATION_MESSAGE);
        		
            		 DefaultTableModel dm = ((DefaultTableModel)table.getModel());
            		 int rowCount = dm.getRowCount();
            		//Remove rows one by one from the end of the table
            		for (int i = rowCount - 1; i >= 0; i--) {
            		    dm.removeRow(i);
            		}

	    		
	    		}
        		
	    	}
	    });
	    
        table.setColumnSelectionAllowed(true);
        table.setSurrendersFocusOnKeystroke(true);
        scrollPane.setViewportView(table);
        
        String []ilkdizi=new String[9];
        ilkdizi[0]="Packet Number";
        ilkdizi[1]="Time";
        ilkdizi[2]="Source Address";
        ilkdizi[3]="Dest.Address";
        ilkdizi[4]="Protocol";
        ilkdizi[5]="Src. Port";
        ilkdizi[6]="Dest. Port";
        ilkdizi[7]="IP Domain";
        ilkdizi[8]="Capture Domain";        
        
        
        //Dizileri model kýsmýna aktarýyoruz.
        tablemodel=new DefaultTableModel(null,ilkdizi){
        	  @Override
        	    public boolean isCellEditable(int row, int column) {
        	       //all cells false
        	       return false;
        	    }
        };
        
        //Modelide Table aktarýyoruz.
        table.setModel(tablemodel);
       
        //paket yakalamayý baþlat
        Capture = new JButton("Capture");
        Capture.addActionListener(new ActionListener() {
        	public void actionPerformed(ActionEvent e) { 
        		
        		packetNumber = 0;
        		SecilenIP = "";
        		DefaultTableModel dm = ((DefaultTableModel)table.getModel());
	       		int rowCount = dm.getRowCount();
	       		//Tabloyu
	       		for (int i = rowCount - 1; i >= 0; i--) {
	       		    dm.removeRow(i);
	       		}
       		
        	    t = new Thread(new TestThd());
        	    t.start();
        	    
        	    Capture.setEnabled(false);
        	    Stop.setEnabled(true);
        	    Stop.setBackground(Color.WHITE);
        	    Capture.setBackground(Color.GREEN);
        	}
        });
        Capture.setBounds(15, 550, 89, 23);
        contentPane.add(Capture);
        
        //Paket almayý durdur
        Stop=new JButton("Stop");
        Stop.setEnabled(false);
        Stop.addActionListener(new ActionListener() {
        	public void actionPerformed(ActionEvent e) {     	    
        		t.stop();
        		Capture.setBackground(Color.WHITE);
        		Stop.setBackground(Color.RED);
        		Capture.setEnabled(true);
        		Stop.setEnabled(false);
        	}
        });
        Stop.setBounds(130, 550, 89, 23);
        contentPane.add(Stop);
        
        //Paket kaydet
        Load=new JButton("Load");
        Load.addActionListener(new ActionListener() {
        	public void actionPerformed(ActionEvent e) {      
        	  Load();     			        		
        	  
        	}
        });
        Load.setBounds(395, 550, 89, 23);
        contentPane.add(Load);
        
        //Pcap Dosyasýný aç
        Save=new JButton("Save");
        Save.addActionListener(new ActionListener() {
        	public void actionPerformed(ActionEvent e) {      
        	   Save();      			        		
        	  
        	}
        });
        Save.setBounds(256, 550, 89, 23);
        contentPane.add(Save);
        
        //Device listlemeyi yapýyoruz
        ListDevice=new JButton("List");
        device=new DefaultListModel();
        ListDevice.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
            	//JOptionPane.showMessageDialog(null, "Merhaba JAVA", "Mesaj -1", -1);
            	/*t = new Thread(new TestThd());
        	    t.start();*/
            	StringBuilder errbuf = new StringBuilder(); // herhangi bir hata mesajý 
        		
       		 
        		//Sitemdeki çihazlarý alýyoruz   
        		int r = Pcap.findAllDevs(alldevs, errbuf);  
        		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {  
        			System.err.printf("Can't read list of devices, error is %s", errbuf  
        					.toString());  
        			return;  
        		}  
        		
                if(alldevs!=null){
                for(int i=0;i<alldevs.size();i++)
                {
                    device.addElement(alldevs.get(i).getName());
                    
                }
                
                Interfaces.setModel(device);
                Interfaces.setEnabled(true);
                Interfaces.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
                Interfaces.setSelectedIndex(0);
                }
                else{
                    
                    JOptionPane.showMessageDialog(null,"Error in loading devices.\n"
                            + "Program Needs admin priviledges to run ","Error",
                            JOptionPane.ERROR_MESSAGE);
                }
                
  
            }
        });
        ListDevice.setBounds(1000, 230, 90, 23);
        contentPane.add(ListDevice);
        
        //device secmeyi yapýyoruz.
        SelectDevice=new JButton("Select");
        SelectDevice.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                devc=alldevs.get(Interfaces.getSelectedIndex());
               // value=true;
               // enableButtons(value);
                if(devc!=null)
                {
                    JOptionPane.showMessageDialog(null,devc.getName()+" Selected!","Confirmation",
                            JOptionPane.OK_OPTION);
                }
                
                
                
            }
        });
        SelectDevice.setBounds(1210, 230, 90, 23);
        contentPane.add(SelectDevice);
        
        jScrollPane2=new JScrollPane();
        jScrollPane2.setBounds(1000, 10, 300, 200);
        contentPane.add(jScrollPane2);
        Interfaces = new JList();
        jScrollPane2.setViewportView(Interfaces);
        
        filedialog=new JFileChooser();
        
             //Zaman grafik Cizdirme 
             btnNewButton = new JButton("Ciz");
             btnNewButton.addMouseListener(new MouseAdapter() {
             	@Override
             	public void mouseClicked(MouseEvent e) {
             		btnNewButton.setBackground(Color.green);
             	   DefaultCategoryDataset dataset = new DefaultCategoryDataset( );
          	        
	          		int row = table.getSelectedRow();//Bütün satýrlarý al
	        		int column = table.getSelectedColumn();//Bütün Sütünlarý al
	        		String IP = (String)table.getValueAt(row, column);//Bütün bilgileri al
        		
	        		
        		 DefaultTableModel dm = ((DefaultTableModel)table.getModel());
        		 int rowCount = dm.getRowCount();//satýr sayisi
        		
        		for (int i = 0; i < rowCount; i++) { // zaman
        			if(Objects.equals((String)table.getValueAt(i, 2), // iplere bak 2
							IP)){
        				int say = 0;
        				for (int j = 0; j < rowCount; j++) {        					
        					if(Objects.equals((String)table.getValueAt(i, 1), 
        							(String)table.getValueAt(j, 1)) && 
        							Objects.equals((String)table.getValueAt(i, 2), 
                							(String)table.getValueAt(j, 2))){
        						say++;
        					}
        				}
        				dataset.addValue(say, "Adet" , (String)table.getValueAt(i, 1) );
        			}
        		}
             		  lineChart = ChartFactory.createLineChart(
             				 IP,
                              "Zaman","Adet",
                              dataset,//Verilerimiz
                              PlotOrientation.VERTICAL,
                              true,true,false);
                              
                           chartPanel = new ChartPanel( lineChart );//Cizim yapmak Ýçin
                           chartPanel.setPreferredSize( new java.awt.Dimension( 300 , 300 ) );
                           chartPanel.setBounds(925,264,400,400);
                           
                           contentPane.add(chartPanel);
                           
        		           //Ekraný güncelleme
                           contentPane.revalidate();
                           contentPane.repaint();
                           
                           frmCiz ciz = new frmCiz(dataset, IP);
                           ciz.show();
             	}
             });
             btnNewButton.setBounds(535, 550, 89, 23);
             contentPane.add(btnNewButton);
          
          
                  
             
	}
	
	
	//////////////////////////////////////////////////////////////////////////////
	
	public class TestThd implements Runnable{
		
		@Override
		public void run(){
			try {
				test();
			} catch (UnknownHostException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
     	 public void Save(){
	    
	        int returnVal = filedialog.showSaveDialog(contentPane);
	         String filename="";
	         
	         
	                if (returnVal==JFileChooser.APPROVE_OPTION) {
	                     File fileToSave = filedialog.getSelectedFile();
	                     //add .pcap or .pacpng extension;
	                     if(!(fileToSave.getName().endsWith(".pcapng")|| fileToSave.getName().endsWith(".pcap")))
	                     {
	                          filename=fileToSave.getAbsolutePath().concat(".pcapng");
	                         
	                     }
	                     StringBuilder errbuf = new StringBuilder();  
	                     PcapDumper dumper = pcap.dumpOpen(filename); //Dosya çýktýsý 
	                     
	                     JBufferHandler<PcapDumper> dumpHandler = new JBufferHandler<PcapDumper>() {  
	  
	                     public void nextPacket(PcapHeader header, JBuffer buffer, PcapDumper dumper) {  
	  
	                      dumper.dump(header, buffer);  }  
	                     };  
	                      
	                     pcap.loop(packetNumber, dumpHandler, dumper);  
	                     System.out.println(packetNumber);
	                     dumper.close();  
	                     pcap.close();
	                     JOptionPane.showMessageDialog(contentPane,"Dosya Kaydedildi!","",JOptionPane.INFORMATION_MESSAGE);
	                }                
		               	                
	                	                
	            }
     	 ///////////////////////////////////////////////////////////////////////////////////
     	public void Load()
     	{int returnVal = filedialog.showOpenDialog(frame);
     	            if (returnVal == JFileChooser.APPROVE_OPTION) {
     	                filepcap = filedialog.getSelectedFile();
     	               if(isValidFile(filepcap.getName())==true)
     	               {
     	                  t.start(); 
     	               }
     	               else{
     	                   JOptionPane.showMessageDialog(frame,"The Selected file is not a pcap file\n"+
     	                           "Please select files with .pcap or .pcapng extension","Error",JOptionPane.ERROR_MESSAGE);
     	               }
     	}
     	} 
     public boolean isValidFile(String file)
         {
             if (file.endsWith(".pcapng") || file.endsWith(".pcap"))
             {
                 return true;
             }
             else
                 return false;
         }
	public static int packetNumber = 0;
	private JButton btnNewButton;
	//////////////////////////////////////////////////////////////////////////////////
	public static void  test() throws UnknownHostException{
		
		  
		  
		StringBuilder errbuf = new StringBuilder(); // herhangi bir hata mesajý 
		
		 
		//Sitemdeki çihazlarý alýyoruz   
		int r = Pcap.findAllDevs(alldevs, errbuf);  
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {  
			System.err.printf("Can't read list of devices, error is %s", errbuf  
					.toString());  
			return;  
		}  

		System.out.println("Network devices found:");  

		int i = 0;
		for (PcapIf device : alldevs) {  
			String description =  
					(device.getDescription() != null) ? device.getDescription()  
							: "No description available";  
					System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);  
		}  
        
		
		
		//PcapIf device = alldevs.get(0); // Bir tane cihaz seçiyorz 
		
		
		System.out  
		.printf("\nChoosing '%s' on your behalf:\n",  
				(devc.getDescription() != null) ? devc.getDescription()  
						: devc.getName()); 

		  
		 //seçilen cihazý açarýz 
		   
		int snaplen = 64 * 1024;           // tüm paketleri yakala,kesme olmaz
		int flags = Pcap.MODE_PROMISCUOUS; // Tüm paketleri al 
		int timeout = 10 * 1000;            
		pcap =Pcap.openLive(devc.getName(), snaplen, flags, timeout, errbuf);  
				  

		if (pcap == null) {  
			System.err.printf("Error while opening device for capture: "  
					+ errbuf.toString()); 
			return;  
		}  

		 
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {  

			public void nextPacket(PcapPacket packet, String user) {  
				try {
					byte[] data = packet.getByteArray(0, packet.size());  

					//Checksum checksum=new Checksum();
					Ip4 ip = new Ip4();   
					Icmp icmp = new Icmp();
					Tcp tcp = new Tcp();
					Udp udp=new Udp();
					

					 
					 
					if (packet.hasHeader(ip) && packet.hasHeader(tcp) ) {  

						int destPort = tcp.destination();
						int srcPort = tcp.source();
						
						if(packet.hasHeader(udp)){
						int destPort1 = udp.destination();
						int srcPort1  = udp.source();
						}
						byte[] dest = ip.destination();
						byte[] src = ip.source();

						/* JNetPcap formatýndaki yardýmcý programlarý kullanýyoruz */  
						String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(dest);  
						String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(src)  ;

						String headerName1= icmp.getName();
						String headerName = tcp.getName();
						String headerName2 = udp.getName();
					    
						Date d = new Date(packet.getCaptureHeader().timestampInMillis());
						SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
						
//						 InetAddress[] addresses = InetAddress.getAllByName(destinationIP);
//						  for (InetAddress address : addresses) {
//						    System.out.println(address.getHostName());
//						  }
						   
						
						  InetAddress addr = InetAddress.getByName(domain);
					     // System.out.println("Local HostAddress:"+addr.getByName(destinationIP).getHostName());
					     
 				        readDomainOfPackageData(packet);
						System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s SRC = %s:%d DEST = %s:%d\n",  
								new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(d),   
								packet.getCaptureHeader().caplen(), //gerçek uzunluk,kesme yok  
								packet.getCaptureHeader().wirelen(), // Original uzunluk   
								headerName,
								sourceIP,
								srcPort,
								destinationIP,
								destPort
								);  
						
						
						
						if(SecilenIP == ""  || Objects.equals(SecilenIP, sourceIP)){
							//yyyy-MM-dd HH:mm:ss.SSS
							packetNumber++;
							  tablemodel.addRow(new Object[]{packetNumber,
									  new SimpleDateFormat("HH:mm:ss").format(d),
									  sourceIP,
									  destinationIP,
									  headerName,
									  srcPort,
									  destPort,
									  addr.getByName(destinationIP).getHostName()  ,
									  addr.getHostName()}); 
							  
							  
						}
						
						

						
					 

					} // end if header
				} catch (Exception e){
					e.printStackTrace();
				}
			}	

		};  

		  
		pcap.loop(Integer.MAX_VALUE, jpacketHandler, "jNetPcap rocks!");  

		//Son olarak pcap kapatýyoruz
		pcap.close(); 
	}
	static String domain;
	private static void readDomainOfPackageData(PcapPacket packet){
		int size = packet.size();  
		JBuffer buffer = packet;  		 

		StringBuilder sB = new StringBuilder();

		for (int i = 0; i < size; i ++) {  
			sB.append((char) buffer.getUByte(i));
			//System.out.printf("%s", (char) buffer.getUByte(i));  
		}  
	 

		Pattern p = Pattern.compile("(\\w+\\.com\\.tr)");
		Matcher m = p.matcher(sB.toString());

		//domain = null;
		if (m.find()){
			domain = m.group();

		} // end if

		if (domain != null){
			System.out.println("#########DOMINIO CAPTURADO::::::::"+domain);	
		}

	}
}

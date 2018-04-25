 
//http://oi59.tinypic.com/2zjdh88.jpg
//swing packages
 import javax.swing.JButton;
 import javax.swing.JList;
 import javax.swing.JMenu;
 import javax.swing.JMenuBar;
 import javax.swing.JMenuItem;  
 import javax.swing.JScrollBar;
 import javax.swing.JScrollPane;
 import javax.swing.JTextArea;
 import javax.swing.JOptionPane;
 import javax.swing.ListSelectionModel;
 import java.awt.Dimension;
 import java.awt.Color;
 import javax.swing.JFrame; 
 import java.awt.event.KeyEvent;
 import javax.swing.ImageIcon;
 import javax.swing.JFileChooser;
 //layout managers
 import javax.swing.GroupLayout; 
 import javax.swing.LayoutStyle; 
 //Event handlers
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
//Jnetpcap lib
import java.io.File;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;




public class NetCaptureUI extends NetCapture 
{

    
    // Variables declaration
    private JFrame frame;
    private JButton capture,stop,save,load,SelectInterface,ListInterface;
    
    private JList Interfaces;
    private JMenu file,help;
   
    private JMenuBar MenuBar;
    private JMenuItem jMenuItem1;
    private JScrollBar jScrollBar2;
    private JScrollPane jScrollPane2,jScrollPane3;
    private JTextArea output;
    private JFileChooser filedialog;
    private boolean value=false;
    private File filepcap;
    private String dirpath;
    private Pcap pcap;
    private PcapDumper dumper;
    
    
    
    // End of variables declaration        
    
    
    public NetCaptureUI() {
        initComponents();
    }
    public Thread offlineCapture=new Thread(new Runnable(){
        public void run()
        {
            /*************************************************************************** 
         * Second we open up the selected file using openOffline call 
         **************************************************************************/  
         pcap = Pcap.openOffline(filepcap.getName(), errbuf);  
  
        if (pcap == null) {  
            JOptionPane.showMessageDialog(null,"Error while opening file for capture:"  
                + errbuf.toString(),"Error",JOptionPane.ERROR_MESSAGE);  
             
        } 
        else{
  
        /*************************************************************************** 
         * Third we create a packet handler which will receive packets from the 
         * libpcap loop. 
         **************************************************************************/  
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {  
  
            public void nextPacket(PcapPacket packet, String user) {  
  
               output.append(packet.toString()
                );  
               
            }  
        };  
  
        /*************************************************************************** 
         * Fourth we enter the loop and tell it to capture 10 packets. The loop 
         * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which 
         * is needed by JScanner. The scanner scans the packet buffer and decodes 
         * the headers. The mapping is done automatically, although a variation on 
         * the loop method exists that allows the programmer to sepecify exactly 
         * which protocol ID to use as the data link type for this pcap interface. 
         **************************************************************************/  
        
            pcap.loop(10, jpacketHandler,"");  
       
            
        }
        }
    });
    
    
    public  Thread liveCapture=new Thread(new Runnable(){
    public void run()
    {
       /**
         * *************************************************************************
         * we open up the selected device
         *************************************************************************
         */
        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000;           // 10 seconds in millis  
        pcap= Pcap.openLive(devc.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            JOptionPane.showMessageDialog(null,"Error while opening device for capture:"
                    +errbuf.toString(),"Error",JOptionPane.ERROR_MESSAGE);
            return;
        }
        else{

        /**
         * *************************************************************************
         * Third we create a packet handler which will receive packets from the
         * libpcap loop. 
         *************************************************************************
         */
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            @Override
            public void nextPacket(PcapPacket packet, String user) {

                output.append("------------------------------------------------------------------PACKET#"+packet.getFrameNumber()+"---------------------------------------------\n"+
                        packet.toString()+
                            "\n\n"
                );
                
                
            }
        }; 
        pcap.loop(10, jpacketHandler, "");
        }
    }
    });
    void enableButtons(boolean val)
    {
        save.setEnabled(val);
        capture.setEnabled(val);
        stop.setEnabled(val);
        
    }
                        
    public void initComponents() {
        frame=new JFrame();
        jMenuItem1 = new JMenuItem();
        jScrollBar2 = new JScrollBar();
        capture = new JButton();
        stop= new JButton();
        save= new JButton();
        load = new JButton();
        Interfaces = new JList();
        jScrollPane2 = new JScrollPane();
        ListInterface= new JButton();
        jScrollPane3 = new JScrollPane(output);
        output = new JTextArea();
        SelectInterface = new JButton();
        MenuBar = new JMenuBar();
        file = new JMenu();
        help = new JMenu();
        ImageIcon Openicon = new ImageIcon("open.png");
        ImageIcon Exiticon = new ImageIcon("Exit.png");
        ImageIcon Saveicon= new ImageIcon("save.png");
        
        dirpath=setDir(); 
        filedialog=new JFileChooser(dirpath);
        jMenuItem1.setText("MenuItem");
        frame.setTitle("NetCapture version 1.0");
        frame.setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        capture.setBackground(new java.awt.Color(51, 255, 0));
        capture.setText("Capture");
        capture.setEnabled(value);
        capture.setToolTipText("Capture packets");
        capture.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                
                liveCapture.start();
                
            
                }
        });
        
       stop.setBackground(new Color(233, 52, 52));
       stop.setForeground(new Color(0, 0, 0));
       stop.setText("Stop");
       stop.setEnabled(value);
       stop.setToolTipText("stop capture");
       stop.setMaximumSize(new Dimension(91, 25));
       stop.setMinimumSize(new Dimension(91, 25));
       stop.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                Thread current=Thread.currentThread();
                if (pcap!=null){
                if(liveCapture.isAlive() && liveCapture==current)
                {
                  //liveCapture.stop(); //unsafe
                    liveCapture=null;
                    pcap.breakloop();
                 
                }
                else if(offlineCapture.isAlive() && liveCapture==current){
                    //offlineCapture.stop(); //unsafe
                    liveCapture=null;
                    pcap.breakloop();
                    
                }
                else{
                    
                     pcap.close();
                    
                }
                }
                
            }
        });
        
    

        save.setToolTipText("save captured packets to a pcap file");
        save.setLabel("Save");
        save.setEnabled(value);
        save.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                
                  Save();
                }
                });

        load.setText("Load");
        load.setEnabled(true);
        load.setToolTipText("load previous capture");
        load.addActionListener(new ActionListener() {
         @Override
         public void actionPerformed(ActionEvent e) {
            int returnVal = filedialog.showOpenDialog(frame);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                filepcap = filedialog.getSelectedFile();
               if(isValidFile(filepcap.getName())==true)
               {
                  offlineCapture.start(); 
               }
               else{
                   JOptionPane.showMessageDialog(frame,"The Selected file is not a pcap file\n"+
                           "Please select files with .pcap or .pcapng extension","Error",JOptionPane.ERROR_MESSAGE);
               }
               
            }
                
         }
      });
        //output.setEditable(false);
        //output.setLineWrap(true);
        //output.setWrapStyleWord(true);

        
        jScrollPane2.getViewport().add(Interfaces);

        ListInterface.setText("List ");
        ListInterface.setToolTipText("lists all the available interfaces");
        SelectInterface.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                devc=devices.get(Interfaces.getSelectedIndex());
                value=true;
                enableButtons(value);
                if(devc!=null)
                {
                    JOptionPane.showMessageDialog(null,devc.getName()+" Selected!","Confirmation",
                            JOptionPane.OK_OPTION);
                }
                
                
                
            }
        });
        ListInterface.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                devices=listInterfaces();
                if(devices!=null){
                for(int i=0;i<devices.size();i++)
                {
                    device.addElement(devices.get(i).getName());
                    
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
        

        output.setColumns(20);
        output.setRows(5);
        jScrollPane3.setViewportView(output);

        SelectInterface.setText("select");
        SelectInterface.setToolTipText("select an interface for capture");
        SelectInterface.setMaximumSize(new Dimension(64, 25));
        SelectInterface.setMinimumSize(new Dimension(64, 25));
        
        file.setText("File");
        MenuBar.add(file);
        file.setMnemonic(KeyEvent.VK_F);
        JMenuItem open = new JMenuItem("Open", Openicon);
        open.setMnemonic(KeyEvent.VK_E);
        open.setToolTipText("open pcap file");
        open.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                Load();
            
            }         
        });
        JMenuItem exit = new JMenuItem("Exit", Openicon);
        exit.setMnemonic(KeyEvent.VK_E);
        exit.setToolTipText("Exit application");
        exit.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                System.exit(0);
            }
        });
        JMenuItem savef=new JMenuItem("Save",Saveicon);
        savef.setMnemonic(KeyEvent.VK_S);
        savef.setToolTipText("Save file");
        savef.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                Save();
               
            }
        });

        file.add(open);
        file.add(savef);
        file.add(exit);
        

        help.setText("Help");
        MenuBar.add(help);
        help.setMnemonic(KeyEvent.VK_F1);
        JMenuItem about=new JMenuItem("About");
        about.setMnemonic(KeyEvent.VK_F1);
        about.setToolTipText("About NetCapture Program");
        about.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                JOptionPane.showMessageDialog(frame,"*******************************************\n"+
                        "NetCapture Version 1.0\n"+
                        "This Program was made by Null_00."
                        + "\n Its the first example for a bigger project.\n"+
                        "*******************************************",
                        "About NetCapture",JOptionPane.INFORMATION_MESSAGE);
            }
        });
        help.add(about);

        frame.setJMenuBar(MenuBar);
        

        GroupLayout layout = new GroupLayout(frame.getContentPane());
        frame.getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(20, 20, 20)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
                            .addComponent(capture, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(save,GroupLayout.PREFERRED_SIZE, 91, GroupLayout.PREFERRED_SIZE))
                        .addGap(18, 18, 18)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
                            .addComponent(load, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(stop, GroupLayout.PREFERRED_SIZE, 91, GroupLayout.PREFERRED_SIZE))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jScrollPane3, GroupLayout.PREFERRED_SIZE, 626, GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, 25, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(ListInterface, GroupLayout.PREFERRED_SIZE, 73, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(SelectInterface,GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,GroupLayout.PREFERRED_SIZE))
                            .addComponent(jScrollPane2, GroupLayout.PREFERRED_SIZE, 162, GroupLayout.PREFERRED_SIZE))
                        .addGap(3, 17, Short.MAX_VALUE))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(21, 21, 21)
                        .addComponent(jScrollPane3, GroupLayout.PREFERRED_SIZE, 311, GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(20, 20, 20)
                        .addComponent(jScrollPane2,GroupLayout.PREFERRED_SIZE, 139, GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(ListInterface)
                            .addComponent(SelectInterface,GroupLayout.PREFERRED_SIZE,GroupLayout.DEFAULT_SIZE,GroupLayout.PREFERRED_SIZE))))
                .addGap(32, 32, 32)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(stop, GroupLayout.PREFERRED_SIZE,GroupLayout.DEFAULT_SIZE,GroupLayout.PREFERRED_SIZE)
                    .addComponent(capture))
                .addGap(31, 31, 31)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(save)
                    .addComponent(load))
                .addContainerGap(52, Short.MAX_VALUE))
        );

        frame.pack();
        frame.setVisible(true);
    }
public void Load()
{int returnVal = filedialog.showOpenDialog(frame);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                filepcap = filedialog.getSelectedFile();
               if(isValidFile(filepcap.getName())==true)
               {
                  offlineCapture.start(); 
               }
               else{
                   JOptionPane.showMessageDialog(frame,"The Selected file is not a pcap file\n"+
                           "Please select files with .pcap or .pcapng extension","Error",JOptionPane.ERROR_MESSAGE);
               }
}
}

    public void Save()
    {if (pcap!=null){
        int returnVal = filedialog.showSaveDialog(frame);
         String filename="";
                if (returnVal==JFileChooser.APPROVE_OPTION) {
                     File fileToSave = filedialog.getSelectedFile();
                     //add .pcap or .pacpng extension;
                     if(!(fileToSave.getName().endsWith(".pcapng")||fileToSave.getName().endsWith(".pcap")))
                     {
                          filename=fileToSave.getAbsolutePath().concat(".pcapng");
                         
                     }
                     StringBuilder errbuf = new StringBuilder();  
                     PcapDumper dumper = pcap.dumpOpen(filename); // output file  
                     
                     JBufferHandler<PcapDumper> dumpHandler = new JBufferHandler<PcapDumper>() {  
  
                     public void nextPacket(PcapHeader header, JBuffer buffer, PcapDumper dumper) {  
  
                      dumper.dump(header, buffer);  }  
                     };  
  
                     pcap.loop(10, dumpHandler, dumper);  
                  
                     dumper.close(); // Won't be able to delete without explicit close 
                     pcap.close();
                     JOptionPane.showMessageDialog(frame,"File Successfully saved!","",JOptionPane.INFORMATION_MESSAGE);
                }
                else{
                    JOptionPane.showMessageDialog(frame,"Error No Device selected!","Error",
                            JOptionPane.ERROR);
                }
}
                
                
                
                
            }
    
  

     public static void main(String args[]) {
        
        java.awt.EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                NetCapture exe=new NetCaptureUI();
                
          
                
                
                
                        
            }
        });
    }

      
    
}


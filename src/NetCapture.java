/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
 
import javax.swing.JOptionPane;
import javax.swing.ListSelectionModel;
//Event handlers
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
//Jnetpcap lib
import java.util.ArrayList;
import java.util.List;
import javax.swing.DefaultListModel;
import java.io.File;

//Pcap class provides a direct mapping of various library methods from Java. 
import org.jnetpcap.Pcap;

/*PcapIf class enables addresses to be replaced as a list to 
simulate a linked list of address structures.*/
import org.jnetpcap.PcapIf;

/*Fully decoded packet that provides access to protocol headers as determined 
during the decoding process.A PcapPacket class is designed to work with pcap library.*/
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;




/**
 *
 * @author root
 */
public class NetCapture {
    public PcapIf devc;
    public Pcap pcap;
    
    public List<PcapIf>devices=new ArrayList<PcapIf>();
    public DefaultListModel device=new DefaultListModel();
    public StringBuilder errbuf = new StringBuilder(); // For any error msgs 
    
    public String setDir()
    {
        File file=new File(System.getProperty("user.dir")+"/NetCapture");
        if(!file.exists()){
            file.mkdir();
            return file.getPath();
        }
        else
            return file.getPath();
            
        
        
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
        
    public List listInterfaces()
    {
        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs 
            int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            JOptionPane.showMessageDialog(null,"Can't read list of devices."+errbuf,"Error",
                    JOptionPane.ERROR_MESSAGE);
                    
            return null;
        }
        else{
            return alldevs;
    }
    }
     
   
}
    


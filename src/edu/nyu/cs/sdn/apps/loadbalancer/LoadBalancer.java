package edu.nyu.cs.sdn.apps.loadbalancer;

import java.util.*;

import edu.nyu.cs.sdn.apps.sps.ShortestPathSwitching;
import edu.nyu.cs.sdn.apps.util.SwitchCommands;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import org.openflow.protocol.*;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionSetField;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionGotoTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.nyu.cs.sdn.apps.sps.InterfaceShortestPathSwitching;
import edu.nyu.cs.sdn.apps.util.ArpServer;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.util.MACAddress;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
		IOFMessageListener
{
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();

	private static final byte TCP_FLAG_SYN = 0x02;
	private static final byte TCP_FLAG_RST = 0x04;

	private static final short IDLE_TIMEOUT = 20;
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;
    
    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Interface to ShortestPathSwitching application
    private InterfaceShortestPathSwitching shortestPathSwitching;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Set of virtual IPs and the load balancer instances they correspond with
    private Map<Integer,LoadBalancerInstance> instances;

    /**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		
		// Obtain table number from config
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
        // Create instances from config
        this.instances = new HashMap<Integer,LoadBalancerInstance>();
        String[] instanceConfigs = config.get("instances").split(";");
        for (String instanceConfig : instanceConfigs)
        {
        	String[] configItems = instanceConfig.split(" ");
        	if (configItems.length != 3)
        	{ 
        		log.error("Ignoring bad instance config: " + instanceConfig);
        		continue;
        	}
        	LoadBalancerInstance instance = new LoadBalancerInstance(
        			configItems[0], configItems[1], configItems[2].split(","));
            this.instances.put(instance.getVirtualIP(), instance);
            log.info("Added load balancer instance: " + instance);
        }
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        this.shortestPathSwitching = context.getServiceImpl(InterfaceShortestPathSwitching.class);

	}

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
		
		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */
		
		/*********************************************************************/
	}
	
	/**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	/*
	* Installing rules in switches to route the virtual IP packets to loadbalance controller*/
	@Override
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));

		for(Map.Entry<Integer, LoadBalancerInstance> entry: instances.entrySet()){
			Integer virtualIP = entry.getKey();
			SwitchCommands.installRule(sw, this.table, SwitchCommands.DEFAULT_PRIORITY,
					this.getMatchCriteria(OFMatch.ETH_TYPE_IPV4, virtualIP), getInstruction(OFPort.OFPP_CONTROLLER));

			SwitchCommands.installRule(sw, this.table, SwitchCommands.DEFAULT_PRIORITY,
					this.getMatchCriteria(OFMatch.ETH_TYPE_ARP, virtualIP), getInstruction(OFPort.OFPP_CONTROLLER));
		}


		OFInstructionGotoTable action = new OFInstructionGotoTable(shortestPathSwitching.getTable());
		List<OFInstruction> inst = new ArrayList<OFInstruction>();
		inst.add(action);
		SwitchCommands.installRule(sw, this.table, SwitchCommands.MIN_PRIORITY,
				this.getMatchCriteria(), inst);
	}
	private List<OFInstruction> getInstruction(OFPort port){
		OFAction action = new OFActionOutput(port);
		OFInstruction inst = new OFInstructionApplyActions(Arrays.asList(action));
		return Arrays.asList(inst);
	}
	private OFMatch getMatchCriteria(short type, short transSrc, short transDest,
									 byte proto, Integer netSrc, Integer netDest){
		OFMatch matchCriteria = new OFMatch();
		if(type != -1) matchCriteria.setDataLayerType(type);
		if(proto != 0) matchCriteria.setNetworkProtocol(proto);
		if(netSrc != null) matchCriteria.setNetworkSource(OFMatch.ETH_TYPE_IPV4, netSrc);
		if(netDest != null) matchCriteria.setNetworkDestination(OFMatch.ETH_TYPE_IPV4, netDest);
		if(transSrc != -1) matchCriteria.setTransportSource(OFMatch.IP_PROTO_TCP, transSrc);
		if(transDest != -1) matchCriteria.setTransportDestination(OFMatch.IP_PROTO_TCP, transDest);
		return matchCriteria;
	}
	private OFMatch getMatchCriteria(){
		return getMatchCriteria((short)(-1), (short)(-1), (short)(-1), (byte)0, null, null);
	}
	private OFMatch getMatchCriteria(short type, Integer netDest){
		return getMatchCriteria(type, (short)(-1), (short)(-1), (byte)0, null, netDest);
	}
	private List<OFInstruction> getFieldInstruction(byte[] ethAddr, OFOXMFieldType ethType, int ipAddr, OFOXMFieldType ipType){
		OFActionSetField ethAction = new OFActionSetField(ethType, ethAddr);
		OFActionSetField ipAction = new OFActionSetField(ipType, ipAddr);
		List<OFAction> actions = new ArrayList<OFAction>();
		actions.add(ethAction);
		actions.add(ipAction);
		OFInstructionApplyActions inst = new OFInstructionApplyActions(actions);
		OFInstructionGotoTable tble = new OFInstructionGotoTable(shortestPathSwitching.getTable());
		return Arrays.asList(inst, tble);
	}
	/**
	 * Handle incoming packets sent from switches.
	 * @param sw switch on which the packet was received
	 * @param msg message from the switch
	 * @param cntx the Floodlight context in which the message should be handled
	 * @return indication whether another module should also process the packet
	 */
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
	{
		// We're only interested in packet-in messages
//		log.info(String.format("Recieving packages in "));
		if (msg.getType() != OFType.PACKET_IN)
		{ return Command.CONTINUE; }
		OFPacketIn pktIn = (OFPacketIn)msg;
		
		// Handle the packet
		Ethernet ethPkt = new Ethernet();
		ethPkt.deserialize(pktIn.getPacketData(), 0,
				pktIn.getPacketData().length);
		
		/*********************************************************************/
		/* TODO: Send an ARP reply for ARP requests for virtual IPs; for TCP */
		/*       SYNs sent to a virtual IP, select a host and install        */
		/*       connection-specific rules to rewrite IP and MAC addresses;  */
		/*       for all other TCP packets sent to a virtual IP, send a TCP  */
		/*       reset; ignore all other packets                             */

		/*********************************************************************/
		if(ethPkt.getEtherType() == Ethernet.TYPE_IPv4) return handleIPv4Pkt(ethPkt, sw, pktIn.getInPort());
		else if(ethPkt.getEtherType() == Ethernet.TYPE_ARP) return handleArpPkt(ethPkt, sw, pktIn.getInPort());
		else return Command.CONTINUE;
	}
	/* creating and replying for the ARP packet for the virtual ip*/
	private net.floodlightcontroller.core.IListener.Command handleArpPkt(
			Ethernet ethPkt, IOFSwitch sw, int port) {
		log.info(String.format("In ARP PKT Reply #########"));
		ARP arpPayload = (ARP)ethPkt.getPayload();
		if(arpPayload == null
				|| arpPayload.getOpCode() != ARP.OP_REQUEST
				|| arpPayload.getProtocolType() != ARP.PROTO_TYPE_IP) {
			log.info(String.format("ARP payload null"));
			return Command.CONTINUE;
		}

		int virtualIP = IPv4.toIPv4Address(arpPayload.getTargetProtocolAddress());
		LoadBalancerInstance instance = instances.get(virtualIP);

		// Create ARP reply
		log.info(String.format("Sending packet %s in LoadBalancer", Arrays.toString(instance.getVirtualMAC())));
		ARP arpReply = new ARP();
		arpReply.setSenderHardwareAddress(instance.getVirtualMAC());
		arpReply.setProtocolType(ARP.PROTO_TYPE_IP);
		arpReply.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
		arpReply.setProtocolAddressLength((byte) 4);
		arpReply.setSenderProtocolAddress(virtualIP);
		arpReply.setTargetHardwareAddress(arpPayload.getSenderHardwareAddress());
		arpReply.setTargetProtocolAddress(arpPayload.getSenderProtocolAddress());
		arpReply.setOpCode(ARP.OP_REPLY);

		Ethernet ethReplyPkt = new Ethernet();
		ethReplyPkt.setEtherType(Ethernet.TYPE_ARP);
		ethReplyPkt.setSourceMACAddress(instance.getVirtualMAC());
		ethReplyPkt.setDestinationMACAddress(ethPkt.getSourceMACAddress());
		ethReplyPkt.setPayload(arpReply);

		SwitchCommands.sendPacket(sw, (short)port, ethReplyPkt);
		log.info(String.format("Sent ARP payload destAddr"));
		return Command.STOP;
	}
	/* creating and replying for the TCP SYN packet for the virtual ip*/
	private net.floodlightcontroller.core.IListener.Command handleIPv4Pkt(Ethernet ethPkt, IOFSwitch sw, int port) {
		IPv4 ipPayload = (IPv4)ethPkt.getPayload();
//		log.info(String.format("TCP Handle"));

		if(ipPayload.getProtocol() != IPv4.PROTOCOL_TCP) {
//			log.info(String.format("IP payload null Handle"));
			return Command.CONTINUE;
		}

		TCP tcpPayload = (TCP)ipPayload.getPayload();
//		if(tcpPayload == null) {
//			log.info(String.format("TCP payload null Handle"));
//			return Command.CONTINUE;
//		}
		if(tcpPayload.getFlags() != TCP_FLAG_SYN) {
			log.info(String.format("TCP Handle RST"));

			TCP tcpRst = new TCP();
			tcpRst.setFlags(TCP_FLAG_RST);
			tcpRst.setSequence(tcpPayload.getAcknowledge());
			tcpRst.setSourcePort(tcpPayload.getDestinationPort());
			tcpRst.setDestinationPort(tcpPayload.getSourcePort());
			tcpRst.setWindowSize((short)0);
			tcpRst.setChecksum((short)0);
			tcpRst.serialize();

			IPv4 ipReplyPkt = new IPv4();
			ipReplyPkt.setPayload(tcpRst);
			ipReplyPkt.setSourceAddress(ipPayload.getDestinationAddress());
			ipReplyPkt.setDestinationAddress(ipPayload.getSourceAddress());
			ipReplyPkt.setChecksum((short)0);
			ipReplyPkt.serialize();

			Ethernet ethReplyPkt = new Ethernet();
			ethReplyPkt.setPayload(ipReplyPkt);
			ethReplyPkt.setSourceMACAddress(ethPkt.getDestinationMACAddress());
			ethReplyPkt.setDestinationMACAddress(ethPkt.getSourceMACAddress());
			SwitchCommands.sendPacket(sw, (short)port, ethReplyPkt);
		}
		else {
			log.info(String.format("TCP Handle SYN"));

			LoadBalancerInstance instance = instances.get(ipPayload.getDestinationAddress());

			int next_ip = instance.getNextHostIP();
			OFMatch outgoingMatchCriteria = this.getMatchCriteria(OFMatch.ETH_TYPE_IPV4, tcpPayload.getSourcePort(),
					tcpPayload.getDestinationPort(), IPv4.PROTOCOL_TCP, ipPayload.getSourceAddress(), ipPayload.getDestinationAddress());

			List<OFInstruction> outGoingInst = this.getFieldInstruction(this.getHostMACAddress(next_ip),
					OFOXMFieldType.ETH_DST, next_ip, OFOXMFieldType.IPV4_DST);

			SwitchCommands.installRule(sw, this.table, SwitchCommands.MAX_PRIORITY, outgoingMatchCriteria,
					outGoingInst, SwitchCommands.NO_TIMEOUT, IDLE_TIMEOUT);

			OFMatch incomingMatchCriteria = this.getMatchCriteria(OFMatch.ETH_TYPE_IPV4, tcpPayload.getDestinationPort(),
					tcpPayload.getSourcePort(), IPv4.PROTOCOL_TCP, ipPayload.getDestinationAddress(), ipPayload.getSourceAddress());

			List<OFInstruction> incomingInst = this.getFieldInstruction(instance.getVirtualMAC(),
					OFOXMFieldType.ETH_SRC, ipPayload.getDestinationAddress(), OFOXMFieldType.IPV4_SRC);

			SwitchCommands.installRule(sw, this.table, SwitchCommands.MAX_PRIORITY, incomingMatchCriteria,
					incomingInst, SwitchCommands.NO_TIMEOUT, IDLE_TIMEOUT);
		}
		return Command.CONTINUE;
	}
	/**
	 * Returns the MAC address for a host, given the host's IP address.
	 * @param hostIPAddress the host's IP address
	 * @return the hosts's MAC address, null if unknown
	 */
	private byte[] getHostMACAddress(int hostIPAddress)
	{
		Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(
				null, null, hostIPAddress, null, null);
		if (!iterator.hasNext())
		{ return null; }
		IDevice device = iterator.next();
		return MACAddress.valueOf(device.getMACAddress()).toBytes();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{ /* Nothing we need to do, since the switch is no longer active */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId)
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) 
	{ /* Nothing we need to do, since load balancer rules are port-agnostic */}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{ return null; }

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ return null; }

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> floodlightService =
	            new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) 
	{
		return (OFType.PACKET_IN == type 
				&& (name.equals(ArpServer.MODULE_NAME) 
					|| name.equals(DeviceManagerImpl.MODULE_NAME))); 
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) 
	{ return false; }
}

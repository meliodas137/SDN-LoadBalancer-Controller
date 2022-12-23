package edu.nyu.cs.sdn.apps.util;

import java.util.*;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.routing.Link;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class Edge {
    public long dest;
    public long destPort;
    public long srcPort;
    public long src;
    public Edge(long src, long srcPort, long dest, long desPort){
        this.dest = dest;
        this.src = src;
        this.srcPort = srcPort;
        this.destPort = desPort;
    };
}
/*This util file handles creation of graphs using the information about topology of the network.
* To find the shortest path, we are using a standard Dijkstra's routine
* but since there is no weight of the edges, it converts to a standard Breadth-First-Search*/
public class Dijkstras {
    private Map<Long, IOFSwitch> switches = new HashMap<Long, IOFSwitch>();
    private static Logger log = LoggerFactory.getLogger(Dijkstras.class.getSimpleName());
    private Collection<Link> links = Collections.EMPTY_SET;
    private Collection<Host> hosts = Collections.EMPTY_SET;
    private Map<Long, ArrayList<Edge>> switchGraph = new HashMap<Long, ArrayList<Edge>>();
    public Dijkstras(Map<Long, IOFSwitch> switches, Collection<Link> links, Collection<Host> hosts) {
//        log.info("Initialising the Dijkstras");
        this.switches = switches;
        this.links = links;
        this.hosts = hosts;
        this.createGraph();
    }

    public Dijkstras(){}
    private void createGraph(){
        this.switchGraph = new HashMap<Long, ArrayList<Edge>>();
        for(Map.Entry<Long, IOFSwitch> entry : this.switches.entrySet()) {
            this.switchGraph.put(entry.getKey(), new ArrayList<Edge>());
        }

        for(Iterator<Link> iterator = this.links.iterator(); iterator.hasNext();) {
            Link link = iterator.next();
            long src = link.getSrc(), srcPort = link.getSrcPort(), dest = link.getDst(), destPort = link.getDstPort();
            this.addEdge(src, dest, srcPort, destPort);
        }
    }

    public void addHostToSwitchRule(Host host, byte table){
        if(host.isAttachedToSwitch() && host.getPort() != null) {
//            log.info(String.format("Adding rule from host to switch %s", host.getSwitch()));
            SwitchCommands.installRule(host.getSwitch(), table, SwitchCommands.DEFAULT_PRIORITY,
                    this.getMatchCriteria(host), this.getInstructions(host.getPort()));
        }
    }
    private void addEdge(Long src, Long dest, Long srcPort, Long destPort){
        if(src == null || dest == null) return;

        Edge e1 = new Edge(src, srcPort, dest, destPort);
        Edge e2 = new Edge(dest, destPort, src, srcPort);
        this.switchGraph.get(src).add(e1);
        this.switchGraph.get(dest).add(e2);
    }
    public void findShortestPath(Host desthost, byte table){
//        log.info(String.format("Finding shortest path from host %s", desthost.getName()));
        if(!desthost.isAttachedToSwitch() || desthost.getPort() == null) return;
        Queue<Edge> q = new LinkedList<Edge>();
        Map<Long, Long> pred = new HashMap<Long, Long>();
        Long start = desthost.getSwitch().getId();
        OFMatch matchCriteria = this.getMatchCriteria(desthost);
        pred.put(start, start);
        for(Edge e : this.switchGraph.get(start)){
//	        log.info(String.format("Processing edge %s to %s", start, e.dest));
            q.add(e);
        }
        while(!q.isEmpty()) {
            Edge curr_e = q.remove();
//            log.info(String.format("While Processing edge %s to %s", curr_e.src, curr_e.dest));
            Long next_node = curr_e.dest;
            if(pred.containsKey(next_node)) continue;
            pred.put(next_node, curr_e.src);
            SwitchCommands.installRule(this.switches.get(curr_e.dest), table, SwitchCommands.DEFAULT_PRIORITY,
                    matchCriteria, this.getInstructions(curr_e.destPort));
            for(Edge e : this.switchGraph.get(next_node)) {
                if(!pred.containsKey(e.dest)) {
                    q.add(e);
                }
            }
        }
    }

    public OFMatch getMatchCriteria(Host hs){
        OFMatch matchCriteria = new OFMatch();
        matchCriteria.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
        matchCriteria.setDataLayerDestination(Ethernet.toByteArray(hs.getMACAddress()));
        return matchCriteria;
    }

    public List<OFInstruction> getInstructions(long port) {
        OFAction action = new OFActionOutput((short)port);
        OFInstruction inst = new OFInstructionApplyActions(Arrays.asList(action));
        return Arrays.asList(inst);
    }

}

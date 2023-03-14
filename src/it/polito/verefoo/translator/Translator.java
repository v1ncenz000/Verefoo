package it.polito.verefoo.translator;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;

import it.polito.verefoo.VerefooNormalizer;
import it.polito.verefoo.allocation.AllocationNode;
import it.polito.verefoo.functions.GenericFunction;
import it.polito.verefoo.functions.PacketFilter;
import it.polito.verefoo.graph.Flow;
import it.polito.verefoo.jaxb.*;
import it.polito.verefoo.jaxb.NodeConstraints.NodeMetrics;
import it.polito.verefoo.utils.PortInterval;
import it.polito.verefoo.utils.Tuple;

/**
 * This class implements a parser for Verefoo output (the z3 model), in order to
 * translate it into the correct XML
 */
public class Translator {
	protected org.apache.logging.log4j.Logger logger = LogManager.getLogger("mylog");
	protected String model;
	protected NFV nfv;
	protected NFV originalNfv;
	protected Graph g;
	protected VerefooNormalizer norm;
	protected List<Node> removedNodes;
	private Map<String, AllocationNode> allocationNodes;
	private Map<Integer, Flow> requirementsMap;

	/**
	 * Constructor
	 * 
	 * @param model The Verefoo output.
	 * @param nfv   The NFV model to complete.
	 * @param g     the specific network service graph that is considered
	 */
	public Translator(String model, NFV nfv, Graph g) {
		this.model = model;
		this.nfv = nfv;
		this.g = g;
	}

	public Translator(String model, NFV nfv, Graph g, Map<String, AllocationNode> allocationNodes, Map<Integer, Flow> requirementsMap) {
		this.model = model;
		this.nfv = nfv;
		this.g = g;
		this.allocationNodes = allocationNodes;
		this.requirementsMap = requirementsMap;
		this.removedNodes = new ArrayList<Node>();
	}

	/**
	 * Conversion function
	 * 
	 * @return an NFV object that contains the new information retrieved in the z3
	 *         model
	 */
	public NFV convert() {
		if (originalNfv.getHosts() != null)
			originalNfv.getHosts().getHost().forEach(this::searchHost);
		setAutoPlacement();
		setAutoConfig();
		removeOptionalNotUsed();
		return originalNfv;
	}

	/**
	 * Wraps the translation for all the VNFs that can be auto configurated by
	 * Verefoo
	 */
	public void setAutoConfig() {
		setPacketFilterAutoConfig();
	}

	/**
	 * Search in the model the deployed position of the nodes and updates the
	 * correspondent host object
	 * 
	 * @param host Physical Host
	 */
	public void searchHost(Host host) {
		List<String> nodesAlreadyDeployed = host.getNodeRef().stream().map(nr -> nr.getNode())
				.collect(Collectors.toList());
		g.getNode().forEach((node) -> {
			String tosearch = z3Translator.stringToSearchDeploymentCondition(node, host);
			Pattern pattern = Pattern.compile(tosearch);
			Matcher matcher = pattern.matcher(model);
			if (matcher.find()) {
				logger.debug(tosearch);
				host.setActive(true);
				NodeRefType nr = new NodeRefType();
				nr.setNode(node.getName());
				if (!nodesAlreadyDeployed.contains(node.getName())) {
					host.getNodeRef().add(nr);
					allocateResources(host, node.getName());
				}
			}
		});
	}

	/**
	 * Search for the destination of a specific auto-generated rule for a firewall
	 */
	private String firewallAutoConfigSearchDst(Node n, String nrOfRule) {
		List<String> nodes = g.getNode().stream().map(no -> no.getName()).collect(Collectors.toList());
		String tosearch = z3Translator.stringToSearchFwDestination(n, nrOfRule);
		Pattern patternDst = Pattern.compile(tosearch);
		Matcher matcherDst = patternDst.matcher(model);
		String nodeDstName = "";
		while (matcherDst.find()) {
			String matchDst = matcherDst.group();
			String dstRule = z3Translator.matchComplexAttribute(matchDst, z3Translator.Datatype.ip_constructor);
			tosearch = z3Translator.stringToSearchAddress(dstRule);
			Pattern patternNodeDst = Pattern.compile(tosearch);
			Matcher matcherNodeDst = patternNodeDst.matcher(model);

			boolean dstFound = false;
			while (matcherNodeDst.find()) {
				String match = matcherNodeDst.group();
				String nodeDst = z3Translator.matchNodeName(match);
				if (nodes.contains(nodeDst)) {
					nodeDstName = nodeDst;
					dstFound = true;
					break;
				}
			}
			if (!dstFound) {
				nodeDstName = dstRule;
			}

			nodeDstName = z3Translator.saneString(nodeDstName);
		}
		return nodeDstName;
	}

	/**
	 * Generalize the pattern matching of a variable declared as a DatatypeSort in
	 * the z3 model
	 * 
	 * @param tosearch the string to search
	 * @param datatype the type of the z3 variable
	 * @return the string that matches the pattern
	 */
	protected String firewallAutoConfigSearchComplexAttribute(String tosearch, z3Translator.Datatype datatype) {
		Pattern pattern = Pattern.compile(tosearch);
		Matcher matcher = pattern.matcher(model);
		String attribute = "null";
		while (matcher.find()) {
			String match = matcher.group();
			attribute = z3Translator.matchComplexAttribute(match, datatype);
		}
		return attribute;
	}

	/**
	 * Generalize the pattern matching of a variable declared as a primitive type
	 * (bool, int, etc) in the z3 model
	 */
	protected String firewallAutoConfigSearchPlainAttribute(String tosearch) {
		Pattern pattern = Pattern.compile(tosearch);
		Matcher matcher = pattern.matcher(model);
		String attribute = "null";
		while (matcher.find()) {
			String match = matcher.group();
			attribute = z3Translator.matchPlainAttribute(match);
		}
		return attribute;
	}

	/**
	 * Set the firewall auto-configurated rules in the XML according to the Verefoo
	 * output
	 */
	public void setPacketFilterAutoConfig() {
		List<Node> autoNodes = originalNfv.getGraphs().getGraph().stream().filter(graph -> graph.getId() == g.getId())
				.flatMap(graph -> graph.getNode().stream())
				.filter(n -> n.getFunctionalType() != null && n.getFunctionalType().equals(FunctionalTypes.FIREWALL)
						&& n.getConfiguration().getFirewall().getElements().isEmpty())
				.collect(Collectors.toList());
		List<String> nodes = g.getNode().stream().map(n -> n.getName()).collect(Collectors.toList());
		Map<String, String> nameToGroup = new HashMap<>();
		g.getNode().forEach(n -> {
			String name = n.getName();
			if (norm.getFlowGroups().containsKey(n.getName())) {
				name = norm.getFlowGroups().get(n.getName());

			}
			if (norm.getNetworkGroups().containsKey(name))
				name = norm.getNetworkGroups().get(name);
			nameToGroup.put(n.getName(), name);
		});

		autoNodes.forEach(n -> {
			List<Elements> listOfRules = new ArrayList<>();
			String defAction = firewallAutoConfigSearchPlainAttribute(
					z3Translator.stringToSearchFwAction(n, "default_action"));
			ActionTypes da = defAction.equals("true") ? ActionTypes.ALLOW : ActionTypes.DENY;
			n.getConfiguration().getFirewall().setDefaultAction(da);

			String tosearch = z3Translator.stringToSearchNode(n);
			Pattern pattern = Pattern.compile(tosearch);
			Matcher matcher = pattern.matcher(model);
			while (matcher.find()) {
				Elements e = new Elements();
				e.setSource("");
				e.setDestination("");
				String matchSrc = matcher.group();
				String srcRule = z3Translator.matchComplexAttribute(matchSrc, z3Translator.Datatype.ip_constructor);
				tosearch = z3Translator.stringToSearchAddress(srcRule);
				Pattern patternNodeScr = Pattern.compile(tosearch);
				Matcher matcherNodeScr = patternNodeScr.matcher(model);
				String nodeSrcName = "";
				boolean srcFound = false;
				while (matcherNodeScr.find()) {
					String match = matcherNodeScr.group();
					String nodeSrc = z3Translator.matchNodeName(match);
					if (nodes.contains(nodeSrc)) {
						nodeSrcName = nodeSrc;
						srcFound = true;
						break;
					}
				}
				if (!srcFound) {
					nodeSrcName = srcRule;
				}
				nodeSrcName = z3Translator.saneString(nodeSrcName);
				
				//if (nameToGroup.containsKey(nodeSrcName))
					//nodeSrcName = nameToGroup.get(nodeSrcName);
				e.setSource(nodeSrcName);
				String nrOfRule = z3Translator.matchNrOfRule(matchSrc);
				String nodeDstName = firewallAutoConfigSearchDst(n, nrOfRule);
				if (nameToGroup.containsKey(nodeDstName))
					nodeDstName = nameToGroup.get(nodeDstName);
				e.setDestination(nodeDstName);

				if (!e.getSource().equals("0.0.0.0") && !e.getDestination().equals("0.0.0.0")) {
					String src_port = firewallAutoConfigSearchComplexAttribute(
							z3Translator.stringToSearchFwPort(n, nrOfRule, "src"),
							z3Translator.Datatype.port_range_constructor);
					src_port = src_port.replace(" ", "-");
					if (src_port.equals("null"))
						src_port = new String("*");
					e.setSrcPort((new PortInterval(src_port).toString()));

					String dst_port = firewallAutoConfigSearchComplexAttribute(
							z3Translator.stringToSearchFwPort(n, nrOfRule, "dst"),
							z3Translator.Datatype.port_range_constructor);
					dst_port = dst_port.replace(" ", "-");
					if (dst_port.equals("null"))
						dst_port = new String("*");
					e.setDstPort((new PortInterval(dst_port).toString()));

					String action = firewallAutoConfigSearchPlainAttribute(
							z3Translator.stringToSearchFwAction(n, "action"));
					ActionTypes a = action.equals("true") ? ActionTypes.ALLOW : ActionTypes.DENY;
					e.setAction(a);

					String protocol = firewallAutoConfigSearchPlainAttribute(
							z3Translator.stringToSearchFwProtocol(n, nrOfRule));
					if (!protocol.equals("null") && Integer.parseInt(protocol) < 4
							&& !L4ProtocolTypes.values()[Integer.parseInt(protocol)].equals(L4ProtocolTypes.ANY))
						e.setProtocol(L4ProtocolTypes.values()[Integer.parseInt(protocol)]);
					else
						e.setProtocol(L4ProtocolTypes.ANY);
					listOfRules.add(e);
				}
			}
			List<Elements> finalRules = mergeRules(listOfRules);
			n.getConfiguration().getFirewall().getElements().addAll(finalRules);
		});

	}

	/**
	 * Merge the auto-generated rule by overlapping port intervals, first by source
	 * port interval and the by destination port interval
	 * 
	 * @param listOfRules list of rules to merge
	 * @return the list of firewall rules in an "elements" object
	 */
	private List<Elements> mergeRules(List<Elements> listOfRules) {
		HashMap<String, List<Elements>> rulesMapBySource = (HashMap<String, List<Elements>>) listOfRules.stream()
				.map(e -> new Tuple<Elements, PortInterval>(e, new PortInterval(e.getSrcPort())))
				.sorted(Comparator.comparing(t -> t._2.getEnd())).sorted(Comparator.comparing(t -> t._2.getStart()))
				.map(t -> t._1)
				.collect(Collectors.groupingBy(e -> e.getSource() + "_" + e.getDestination(), Collectors.toList()));
		List<Elements> finalRulesBySource = mergeRulesByMap(rulesMapBySource);
		HashMap<String, List<Elements>> rulesMapByDest = (HashMap<String, List<Elements>>) finalRulesBySource.stream()
				.map(e -> new Tuple<Elements, PortInterval>(e, new PortInterval(e.getDstPort())))
				.sorted(Comparator.comparing(t -> t._2.getEnd())).sorted(Comparator.comparing(t -> t._2.getStart()))
				.map(t -> t._1)
				.collect(Collectors.groupingBy(e -> e.getSource() + "_" + e.getDestination(), Collectors.toList()));
		List<Elements> finalRulesByDest = mergeRulesByMap(rulesMapByDest);
		return finalRulesByDest;
	}

	/**
	 * Merge the auto-generated rule by overlapping port intervals
	 * 
	 * @param rulesMap a data structure of sorted rules
	 */
	private List<Elements> mergeRulesByMap(HashMap<String, List<Elements>> rulesMap) {
		List<Elements> finalRules = new ArrayList<>();
		for (Entry<String, List<Elements>> rule : rulesMap.entrySet()) {
			String src = rule.getKey().substring(0, rule.getKey().indexOf("_"));
			String dst = rule.getKey().substring(rule.getKey().indexOf("_") + 1);
			Elements last = rule.getValue().get(0);
			PortInterval intervalSrc = new PortInterval(last.getSrcPort()),
					intervalDst = new PortInterval(last.getDstPort());
			int minSrc = intervalSrc.getStart(), maxSrc = intervalSrc.getEnd(), minDst = intervalDst.getStart(),
					maxDst = intervalDst.getEnd();
			boolean overlap = false;
			for (int i = 1; i < rule.getValue().size(); i++) {
				Elements e = rule.getValue().get(i);
				PortInterval lastSrcInterval = new PortInterval(last.getSrcPort()),
						currentSrcInterval = new PortInterval(e.getSrcPort());
				overlap = lastSrcInterval.overlapsWith(currentSrcInterval);
				if (!overlap) {
					finalRules.add(last);
					last = e;
					continue;
				}
				PortInterval lastDstInterval = new PortInterval(last.getDstPort()),
						currentDstInterval = new PortInterval(e.getDstPort());
				overlap &= lastDstInterval.overlapsWith(currentDstInterval);
				if (!overlap) {
					finalRules.add(last);
					last = e;
					continue;
				}
				overlap &= (last.getProtocol().equals(e.getProtocol()) || last.getProtocol().equals(L4ProtocolTypes.ANY)
						|| e.getProtocol().equals(L4ProtocolTypes.ANY));
				if (!overlap) {
					finalRules.add(last);
					last = e;
					continue;
				}
				minSrc = Math.min(lastSrcInterval.getStart(), currentSrcInterval.getStart());
				maxSrc = Math.max(lastSrcInterval.getEnd(), currentSrcInterval.getEnd());
				minDst = Math.min(lastDstInterval.getStart(), currentDstInterval.getStart());
				maxDst = Math.max(lastDstInterval.getEnd(), currentDstInterval.getEnd());

				Elements newRule = new Elements();
				newRule.setAction(last.getAction());
				newRule.setSource(src);
				newRule.setDestination(dst);
				newRule.setSrcPort((new PortInterval(minSrc + "-" + maxSrc)).toString());
				newRule.setDstPort((new PortInterval(minDst + "-" + maxDst)).toString());

				if (last.getProtocol().equals(e.getProtocol())) {
					newRule.setProtocol(last.getProtocol());
				} else {
					newRule.setProtocol(L4ProtocolTypes.ANY);
				}
				last = newRule;
			}
			finalRules.add(last);
		}
		return finalRules;
	}

	/**
	 * Remove not used optional network objects from the XML for the Verefoo output
	 */
	public void setAutoPlacement() {
		List<AllocationNode> usableNodes = allocationNodes.values().stream()
				.filter(n -> n.getNode().getConfiguration() == null).collect(Collectors.toList());
		usableNodes.forEach(allocationNode -> {
			String tosearch = z3Translator.stringToSeachNetworkObjectUsed(allocationNode.getNode());
			Pattern pattern = Pattern.compile(tosearch);
			Matcher matcher = pattern.matcher(model);

			while (matcher.find()) {
				Node n = originalNfv.getGraphs().getGraph().stream().filter(graph -> graph.getId() == g.getId())
						.flatMap(graph -> graph.getNode().stream())
						.filter(node -> node.getName().equals(allocationNode.getNode().getName())).findFirst()
						.orElse(null);

				if (n == null)
					continue;

				Configuration configuration = new Configuration();
				configuration.setName("AutoConf");
				n.setFunctionalType(FunctionalTypes.FIREWALL);
				Firewall f = new Firewall();

				GenericFunction no = allocationNode.getPlacedNF();
				if (no instanceof PacketFilter) {
					PacketFilter aclf = (PacketFilter) no;
					if (!aclf.isBlacklisting())
						f.setDefaultAction(ActionTypes.ALLOW);
					else
						f.setDefaultAction(ActionTypes.DENY);
				}

				configuration.setFirewall(f);
				n.setConfiguration(configuration);
			}

		});

		usableNodes.forEach(allocationNode -> {
			String tosearch = z3Translator.stringToSeachNetworkObjectNotUsed(allocationNode.getNode());
			Pattern pattern = Pattern.compile(tosearch);
			Matcher matcher = pattern.matcher(model);

			while (matcher.find()) {
				Node n = originalNfv.getGraphs().getGraph().stream().filter(graph -> graph.getId() == g.getId())
						.flatMap(graph -> graph.getNode().stream())
						.filter(node -> node.getName().equals(allocationNode.getNode().getName())).findFirst()
						.orElse(null);

				if (n == null)
					continue;

				Configuration configuration = new Configuration();
				configuration.setName("ForwardConf");
				n.setFunctionalType(FunctionalTypes.FORWARDER);
				Forwarder f = new Forwarder();
				f.setName("Forwarder");
				configuration.setForwarder(f);
				n.setConfiguration(configuration);
			}
		});

	}

	/**
	 * Reduces the host resources according to the node metrics
	 * 
	 * @param h        the host
	 * @param nodeName the name of the node that is deployed on the host
	 */
	public void allocateResources(Host h, String nodeName) {
		NodeMetrics reqResources = nfv.getConstraints().getNodeConstraints().getNodeMetrics().stream()
				.filter(nm -> nm.getNode().equals(nodeName)).findFirst().orElse(null);
		if (h.getMaxVNF() != null)
			h.setMaxVNF(h.getMaxVNF() - 1);
		if (reqResources == null)
			return;
		h.setDiskStorage(h.getDiskStorage() - reqResources.getReqStorage());
		h.setMemory(h.getMemory() - reqResources.getMemory());
	}

	/**
	 * Get the normalized version of the received service graph
	 * 
	 * @return the normalized version of the received service graph
	 */
	public VerefooNormalizer getNormalizer() {
		return norm;
	}

	/**
	 * Set the normalized version of the received service graph
	 * 
	 * @param norm the normalized version of the received service graph
	 */
	public void setNormalizer(VerefooNormalizer norm) {
		this.norm = norm;
		this.originalNfv = norm.getOriginalNfv();
	}

	/**
	 * Remove not used optional network objects from the XML for the Verefoo output
	 */
	
	public void removeOptionalNotUsed() {
		
		List<NodeMetrics> nodeMetrics = originalNfv.getConstraints().getNodeConstraints().getNodeMetrics().stream()
				.collect(Collectors.toList());

		List<AllocationNode> optionalNodes = allocationNodes.values().stream().filter(n -> {
			for (NodeMetrics nm : nodeMetrics) {
				if (n.getNode().getName().equals(nm.getNode()))
					return true;
			}
			return false;
		}).collect(Collectors.toList());
		
		optionalNodes.forEach(opNode -> {
			String tosearch = z3Translator.stringToSeachNetworkObjectNotUsed(opNode.getNode());
			Pattern pattern = Pattern.compile(tosearch);
			Matcher matcher = pattern.matcher(model);
			
			while (matcher.find()) {

				for(Flow sr : requirementsMap.values()) {
					List<AllocationNode> nodesPath = sr.getPath().getNodes();
					int opNodeIndex = -1;
					for(int i = 0; i < nodesPath.size(); i++) {
						if(nodesPath.get(i).getNode().getName().equals(opNode.getNode().getName()))
							opNodeIndex = i;	
					}
					if(opNodeIndex != -1) {
						
						String prevName = null;
						String nextName = null;
						
						for(int i = opNodeIndex-1; i >= 0; i--) {
							int iLambda = i;
							boolean alreadyRemoved = removedNodes.stream().anyMatch(rN -> rN.getName().equals(nodesPath.get(iLambda).getNode().getName()));
							if(!alreadyRemoved) {
								prevName = nodesPath.get(i).getNode().getName();
								break;
							}
						}
						
						for(int i = opNodeIndex+1; i < nodesPath.size(); i++) {
							int iLambda = i;
							boolean alreadyRemoved = removedNodes.stream().anyMatch(rN -> rN.getName().equals(nodesPath.get(iLambda).getNode().getName()));
							if(!alreadyRemoved) {
								nextName = nodesPath.get(i).getNode().getName();
								break;
							}
						}
						
						if(prevName != null && nextName != null) {
							
							String prevNameLambda = prevName;
							String nextNameLambda = nextName;
							
							Node prevNode = originalNfv.getGraphs().getGraph().stream()
									.filter(graph -> graph.getId() == g.getId()).flatMap(graph -> graph.getNode().stream())
									.filter(node -> node.getName().equals(prevNameLambda)).findFirst().orElse(null);

							List<Neighbour> neighboursPrec = prevNode.getNeighbour();
							neighboursPrec.removeIf(neigh -> neigh.getName().equals(opNode.getNode().getName()));
							boolean presentNext = neighboursPrec.stream()
									.anyMatch(neigh -> neigh.getName().equals(nextNameLambda));
							if (!presentNext) {
								Neighbour neigh = new Neighbour();
								neigh.setName(nextName);
								neighboursPrec.add(neigh);
							}
							

							Node nextNode = originalNfv.getGraphs().getGraph().stream()
									.filter(graph -> graph.getId() == g.getId()).flatMap(graph -> graph.getNode().stream())
									.filter(node -> node.getName().equals(nextNameLambda)).findFirst().orElse(null);
							List<Neighbour> neighboursNext = nextNode.getNeighbour();
							neighboursNext.removeIf(neigh -> neigh.getName().equals(opNode.getNode().getName()));
							boolean presentPrev = neighboursNext.stream()
									.anyMatch(neigh -> neigh.getName().equals(prevNameLambda));
							if (!presentPrev) {
								Neighbour neigh = new Neighbour();
								neigh.setName(prevName);
								neighboursNext.add(neigh);
							}
							
						}
						
					}
					
					
				}
				
				Graph graphWithOptional = originalNfv.getGraphs().getGraph().stream()
						.filter(graph -> graph.getId() == g.getId()).findFirst().orElse(null);
				List<Node> allNodes = graphWithOptional.getNode();
				allNodes.removeIf(node -> node.getName().equals(opNode.getNode().getName()));
				removedNodes.add(opNode.getNode());
				
			}
			
		});
	}
	

}
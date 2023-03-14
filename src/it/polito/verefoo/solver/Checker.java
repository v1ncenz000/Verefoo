/*******************************************************************************
 * Copyright (c) 2017 Politecnico di Torino and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 *******************************************************************************/
package it.polito.verefoo.solver;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Context;
import com.microsoft.z3.Model;
import com.microsoft.z3.Optimize;
import com.microsoft.z3.Params;
import com.microsoft.z3.Status;

import it.polito.verefoo.allocation.AllocationNode;
import it.polito.verefoo.graph.Flow;
import it.polito.verefoo.graph.SecurityRequirement;
import it.polito.verefoo.utils.VerificationResult;


/**
 * Various checks for specific properties in the network.
 *
 *
 */
	
public class Checker {
	public enum Prop {
	    ISOLATION,REACHABILITY
	}
	
	Context ctx;
	NetContext nctx;
	Optimize solver;
	public BoolExpr[] assertions={};
	public Status result;
	public Model model;
	private HashMap<String, AllocationNode> allocationNodes;
	private List<BoolExpr> constraintList;
	private long timeChecker;


	/**
	 * Public constructor of Checker class
	 * @param context it is the z3 context where assertions must be introduced into
	 * @param nctx it is the NetContext which stores basic z3 variables
	 * @param allocationNodes it is the map of allocation nodes of the Allocation Graph
	 */
	public Checker(Context context, NetContext nctx, HashMap<String,AllocationNode> allocationNodes) {
		this.ctx = context;
		this.nctx = nctx;
		this.allocationNodes = allocationNodes;
		this.solver = ctx.mkOptimize();
		this.constraintList =new ArrayList<BoolExpr>();
		
		// initial parameters
		Params p = ctx.mkParams();
		p.add("maxsat_engine", ctx.mkSymbol("wmax"));
		p.add("maxres.wmax", true  );
		p.add("timeout", 1800000);
		solver.setParameters(p);
	}
	
	
	/**
	 * Thus method adds hard and soft constraints in the solver
	 */
	public void addConstraints() {
		allocationNodes.values().forEach(node->node.addConstraints(solver));
		constraintList.forEach(boolExpr->this.solver.Add(boolExpr)); //adding hard constraints
		nctx.addConstraints(solver); //adding hard and soft constraints
	}
	

	/**
	 * This method starts the z3 solver to solve the MaxSMT problem
	 * @return
	 */
	public VerificationResult propertyCheck(){
		solver.Push();
		addConstraints();
		  long startTime = System.currentTimeMillis();

		result = this.solver.Check(); 
		long stopTime = System.currentTimeMillis();
	    long elapsedTime = stopTime - startTime;
	     timeChecker = elapsedTime;
	     System.out.println("single checker time " +timeChecker);
		model = (result == Status.SATISFIABLE) ? this.solver.getModel() : null;
		logAssertions();
		solver.Pop();
		return new VerificationResult(ctx, result, nctx, assertions, model);
	}
	
	public long getTimeChecker() {
		return timeChecker;
	}


	public void setTimeChecker(long timeChecker) {
		this.timeChecker = timeChecker;
	}


	/**
	 * This method prints the assertions of the z3 model in the log.
	 * old versions of z3 did not provide solver.getAssertions() method
	 * so if you want to use, it has to be commented
	 */
	private void logAssertions()  {	
		/*
		Logger logger = LogManager.getLogger("assertions");
		StringWriter stringWriter = new StringWriter();
		assertions = solver.getAssertions();
		Arrays.asList(assertions).forEach(t-> stringWriter.append(t+"\n\n"));
		if(model!=null){
			logger.debug("---------- Assertions: "+assertions.length);	
		}
		*/
	}


	
	/**
	 * This method is invoked by VerefooProxy to generate the z3 constraints for each security requirement
	 * @param sr It is the requirement that must be modeled in z3 language
	 * @param propType It is the type of the security requirement
	 */
	public void createRequirementConstraints(SecurityRequirement sr, Prop propType) {
		
		switch (propType) {
			case ISOLATION:
				createIsolationConstraints(sr);
				break;
			case REACHABILITY:
				createReachabilityConstraint(sr);
				break;
		}
	}


	/**
	 * This method generates the constraints for a reachability requirement
	 * @param sr It is the requirement that must be modeled in z3 language
	 * @param propType It is the type of the security requirement
	 */
	private void createReachabilityConstraint(SecurityRequirement sr) {
		
		List<BoolExpr> pathConstraints = new ArrayList<>();
		Map<Integer, Flow> allFlows = sr.getFlowsMap();
		
		for(Flow flow : allFlows.values()) {
			
			List<BoolExpr> singleConstraints = new ArrayList<>();
			for(AllocationNode node : flow.getPath().getNodes()) {
				singleConstraints.add(ctx.mkImplies(node.getPlacedNF().getUsed(), ctx.mkEq( (BoolExpr)nctx.deny.apply(node.getZ3Name(), ctx.mkInt(flow.getIdFlow())), ctx.mkFalse())));
			}
			

			BoolExpr[] arrayConstraints = new BoolExpr[singleConstraints.size()];
			BoolExpr finalConstraint = ctx.mkAnd(singleConstraints.toArray(arrayConstraints));
			pathConstraints.add(finalConstraint);
			
		}
		
	
		BoolExpr[] arrayConstraints = new BoolExpr[pathConstraints.size()];
		BoolExpr finalConstraint = ctx.mkOr(pathConstraints.toArray(arrayConstraints));
		constraintList.add(finalConstraint);
	}

	
	/**
	 * This method generates the constraints for an isolation requirement
	 * @param sr It is the requirement that must be modeled in z3 language
	 * @param propType It is the type of the security requirement
	 */
	private void createIsolationConstraints(SecurityRequirement sr) {
		
		List<BoolExpr> pathConstraints = new ArrayList<>();
		Map<Integer, Flow> allFlows = sr.getFlowsMap();
		
		for(Flow flow : allFlows.values()) {
			// for each flow
			List<BoolExpr> singleConstraints = new ArrayList<>();
			
			for(AllocationNode node : flow.getPath().getNodes()) {
				// for each now of the flow
				singleConstraints.add(ctx.mkAnd(node.getPlacedNF().getUsed(), (BoolExpr) nctx.deny.apply(node.getZ3Name(), ctx.mkInt(flow.getIdFlow()))));
			}
			
			BoolExpr[] arrayConstraints = new BoolExpr[singleConstraints.size()];
			BoolExpr finalConstraint = ctx.mkOr(singleConstraints.toArray(arrayConstraints));
			pathConstraints.add(finalConstraint);
		}
		
		
		BoolExpr[] arrayConstraints = new BoolExpr[pathConstraints.size()];
		BoolExpr finalConstraint = ctx.mkAnd(pathConstraints.toArray(arrayConstraints));
		constraintList.add(finalConstraint);
	}

}



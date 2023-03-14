package it.polito.verefoo.functions;

import java.util.ArrayList;
import java.util.List;

import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Context;
import com.microsoft.z3.DatatypeExpr;
import com.microsoft.z3.Expr;
import com.microsoft.z3.FuncDecl;
import com.microsoft.z3.IntExpr;
import com.microsoft.z3.Optimize;

import it.polito.verefoo.allocation.AllocationNode;
import it.polito.verefoo.graph.Flow;
import it.polito.verefoo.jaxb.Node;
import it.polito.verefoo.solver.NetContext;
import it.polito.verefoo.utils.PacketFilterRule;

/** Represents a Packet Filter with the associated Access Control List
 *
 */
public class DPI extends GenericFunction{

	FuncDecl filtering_function;
	ArrayList<PacketFilterRule> rules; 
	boolean autoConfigured;
	BoolExpr behaviour;
	FuncDecl rule_func;

	boolean blacklisting;
	boolean defaultActionSet;
	private String ipAddress;
	
	DatatypeExpr dpi;
	Expr defaultAction;
	int nRules;
	List<String> conditions;
	
	

	/**
	 * Public constructor for the DPI
	 * This is a version that simply compares integer hashes of strings.
	 * @param source It is the Allocation Node on which the dpi is put
	 * @param ctx It is the Z3 Context in which the model is generated
	 * @param nctx It is the NetContext object to which constraints are sent
	 */
	public DPI(AllocationNode source, Context ctx, NetContext nctx) {
		this.source = source;
		this.ctx = ctx;
		this.nctx = nctx;

		
		dpi = source.getZ3Name();
		ipAddress = source.getNode().getName();
		constraints = new ArrayList<BoolExpr>();
   		conditions = new ArrayList<>();
		isEndHost = false;

   		// true for blacklisting, false for whitelisting
   		// this is the default, but it can be changed
   		defaultActionSet = false;
   		
   		// function can be used or not, autoplace follows it
   		used = ctx.mkBoolConst(dpi+"_used");
		autoplace = false; 
		
		//function can be autoConfigured is z3 must establish the firewall filtering policy
		autoConfigured = false;
	}

	/**
	 * This method allows to generate the filtering rules for a manually configured DPI
	 */
	public void manualConfiguration(){
		
		constraints.add(ctx.mkEq(used, ctx.mkTrue()));
		
		Node n = source.getNode();
		n.getConfiguration().getDpi().getDpiElements().forEach(r -> conditions.add(r.getCondition()));

		
		/**
	     * This section allow the creation of Z3 variables for defaultAction and rules.
	    */
  		defaultAction = ctx.mkConst(dpi + "_manual_default_action", ctx.mkBoolSort());
  		Expr ruleAction = ctx.mkConst(dpi + "_manual_action", ctx.mkBoolSort());

  		constraints.add(ctx.mkEq(defaultAction, ctx.mkFalse()));
  		constraints.add(ctx.mkEq(ruleAction, ctx.mkTrue()));

	
  		/**
  		 * This sections generates all the constraints to satisfy reachability and isolation requirements.
  		 */
  		
  		for(Flow flow : source.getFlows().values()) {
  		
  			/*
  			 * deny(dpi, t) = (whitelisting(n) && !inSentenceList(t.body)) || (!whitelisting(n) && inSentenceList(t.body))
  			 * where
  			 * inSentenceList(t.body) is an or of comparisons between the hash of the body and the hash of each sentence by which the DPI is configured
  			 * inSentenceList(t.body) = (hash(t.Body) == hash(dpi.sentence1) || (hash(t.Body) == hash(dpi.sentence2) || ...
  			 * 
  			 */
  			BoolExpr decision;
  			if(flow.getCrossedTraffic(ipAddress).getBody().equals("null")) {
  				decision = blacklisting ? ctx.mkEq(nctx.deny.apply(source.getZ3Name(), ctx.mkInt(flow.getIdFlow())), ctx.mkFalse()) : ctx.mkEq(nctx.deny.apply(source.getZ3Name(), ctx.mkInt(flow.getIdFlow())), ctx.mkTrue()); 
  			}else {
  				String body = flow.getCrossedTraffic(ipAddress).getBody();
  				
  				BoolExpr z3condition = generateRulesCondition(body.hashCode());
  				
  				decision = blacklisting ?
  						ctx.mkEq(nctx.deny.apply(source.getZ3Name(), ctx.mkInt(flow.getIdFlow())), z3condition) :
  						ctx.mkEq(nctx.deny.apply(source.getZ3Name(), ctx.mkInt(flow.getIdFlow())), ctx.mkNot(z3condition));
  	
  			}
  			
  			constraints.add(decision);
  			
  			
  		}
		
	}

	/**
	 * This method generate the formula for the inSentenceList(t.body) predicate
	 * @param hashBody the integer hash of the traffic body
	 * @return the z3 condition
	 */
	private BoolExpr generateRulesCondition(int hashBody) {
		
		IntExpr z3HashBody = ctx.mkInt(hashBody);
		
		List<BoolExpr> exprList = new ArrayList<>();
		for(String condition : conditions) {
			IntExpr z3ToCompare = ctx.mkInt(condition.hashCode());
			exprList.add(ctx.mkEq(z3HashBody, z3ToCompare));
		}
		
		BoolExpr[] tmpArray = new BoolExpr[exprList.size()];
		return ctx.mkOr(exprList.toArray(tmpArray));
	}

	/**
	 * This method allows to know if autoconfiguration feature is used
	 *@return the value of autoconfigured boolean variable
	 */
	public boolean isAutoconfigured() {
		return autoConfigured;
	}
    
   	/**
	 * This method allows to know if autoplacement feature is used
	 *@return the value of autoplace boolean variable
	 */
	public boolean isAutoplace() {
		return autoplace;
	}


	/**
	 * This method allows to know if blacklisting is used
	 *@return the value of blacklisting boolean variable
	 */
 	public boolean isBlacklisting() {
		return blacklisting;
	}

 	/**
	 * This method allows to set autoconfigured variable
	 *@param autoconfigured Value to set
	 */
	public void setAutoconfigured(boolean autoconfigured) {
		this.autoConfigured = autoconfigured;
	}
	
	/**
	 * This method allows to set autoplace variable
	 *@param autoplace Value to set
	 */
	public void setAutoplace(boolean autoplace) {
		this.autoplace = autoplace;
	}
	
	/**
	 * This method allows to change the default behaviour of the packet_filter: blacklisting (true) or whitelisting (false)
	 * @param action The boolean is true for blacklisting, false for whitelisting.
	 */
	public void setDefaultAction(boolean action){
		this.blacklisting = action;
		defaultActionSet = true;
	}

	
	/**
	 * This method allows to wrap the method which adds the constraints inside Z3 solver
	 * @param solver Istance of Z3 solver
	 */
	@Override
	public void addContraints(Optimize solver) {
		BoolExpr[] constr = new BoolExpr[constraints.size()];
	    solver.Add(constraints.toArray(constr));
	}
}

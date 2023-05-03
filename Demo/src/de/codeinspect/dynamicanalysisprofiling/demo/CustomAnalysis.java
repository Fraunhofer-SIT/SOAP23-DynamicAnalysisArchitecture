package de.codeinspect.dynamicanalysisprofiling.demo;

import java.io.IOException;
import java.util.Collections;

import de.codeinspect.platforms.soot.analyses.FlowDroidAnalysis;
import de.codeinspect.platforms.soot.flowdroid.FlowDroidUtils;
import de.codeinspect.platforms.soot.flowdroid.sourcesSinks.CIStatementSourceSinkDefinition;
import de.codeinspect.soot.flowdroid.FlowDroidConfigurator.SinkPreset;
import de.codeinspect.soot.flowdroid.FlowDroidConfigurator.SourcePreset;
import de.codeinspect.soot.flowdroid.ISourceSinkContainer;
import de.codeinspect.soot.flowdroid.SimpleSourceSinkContainer;
import soot.Local;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.infoflow.sourcesSinks.definitions.AccessPathTuple;

/**
 * This class is used as a way to introduce custom source/sinks as well as to
 * ask for values, which get resolved in the dynamic analysis.
 * 
 * This class can be used to specifically ask for data flows. Note that this is
 * for demo purposes and it was not used in the evaluation of the paper.
 * 
 * @author Marc Miltenberger
 */
public class CustomAnalysis extends FlowDroidAnalysis {

	@Override
	public void start() throws Throwable {

	}

	@Override
	protected ISourceSinkContainer getSources() throws IOException {
		ISourceSinkContainer flowSinks = new SimpleSourceSinkContainer();

		// you can add some sinks based on presets
		flowSinks.addAll(FlowDroidUtils.getSources(SourcePreset.UNTRUSTED_OUTSIDE_WORLD));

		// you can also add custom sources and sinks
		for (SootClass c : Scene.v().getApplicationClasses()) {
			for (SootMethod m : c.getMethods()) {
				if (m.hasActiveBody()) {
					for (Unit d : m.retrieveActiveBody().getUnits()) {
						Stmt s = (Stmt) d;
						if (s.containsInvokeExpr()) {
							InvokeExpr inv = s.getInvokeExpr();
							if (inv.getMethod().getDeclaringClass().getName().equals("java.io.File")
									&& inv.getMethod().isConstructor() && inv instanceof InstanceInvokeExpr) {
								// File.<init> as source

								InstanceInvokeExpr iinv = (InstanceInvokeExpr) inv;
								CIStatementSourceSinkDefinition def = new CIStatementSourceSinkDefinition(s,
										(Local) iinv.getBase(),
										Collections.singleton(AccessPathTuple.getBlankSourceTuple()));
								flowSinks.add(def);
							}
						}

					}
				}
			}
		}
		return flowSinks;
	}

	@Override
	protected ISourceSinkContainer getSinks() throws IOException {
		return FlowDroidUtils.getSinks(SinkPreset.NETWORK);
	}

}

package de.codeinspect.dynamicanalysisprofiling.demo;

import java.util.LinkedHashSet;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.codeinspect.base.projects.AbstractCIProject;
import de.codeinspect.communication.admin.devices.CIDeviceConfig;
import de.codeinspect.dynamicvalues.analysisserver.devices.AbstractDeviceExecutionHandler;
import de.codeinspect.dynamicvalues.analysisserver.executors.IAndroidExecutorEventHandler;
import de.codeinspect.dynamicvalues.instrumentation.InstrumentationPlan;
import de.codeinspect.soot.CIScene;
import de.codeinspect.soot.taintTracking.dynamic.DynamicTaintManager;
import de.codeinspect.soot.taintTracking.dynamic.TaintPath;
import de.codeinspect.soot.taintTracking.dynamic.TaintSource;
import de.codeinspect.soot.utils.AnalysisUtils;
import soot.jimple.Stmt;

/**
 * This class handles the main part of the evaluation. It gets informed by VUSC
 * when the dynamic analysis begins/ends/has errors.
 * 
 * @author Marc Miltenberger
 */
public class AndroidExecutorEventHandler implements IAndroidExecutorEventHandler {

	private static final Logger logger = LogManager.getLogger(AndroidExecutorEventHandler.class);

	@Override
	public void onException(AbstractCIProject project, CIDeviceConfig device, Exception e) {
		String str = "An exception occurred in " + project + " using " + device + "\n"
				+ ExceptionUtils.getStackTrace(e);
		logger.error(str);
	}

	@Override
	public void afterExecution(AbstractCIProject project, CIDeviceConfig device,
			InstrumentationPlan instrumentationPlan, AbstractDeviceExecutionHandler executionHandler) {
		CIScene.v().allowLocalNames = true;
		String dynamicCG = CIScene.v().getDynamicCallgraph().toString();
		logger.info("### dynamic callgraph ###");
		logger.info(dynamicCG);

		logger.info("### dynamic dataflow/tainting ###");
		DynamicTaintManager dtm = CIScene.v().getDynamicTaintManager();
		for (TaintSource source : dtm.getSources()) {
			for (TaintPath path : dtm.getPathsForSource(source.getStmt())) {
				logger.info("--------");
				logger.info(path.getSource());
				for (Stmt e : new LinkedHashSet<>(path.getStmtsOnPath())) {
					logger.info(AnalysisUtils.getMethod(e) + ": " + e);
				}
				logger.info(path.getSink());
			}
		}

		// dynamic values can be found in ValueRuntimeValueNotifier
	}

	@Override
	public void beforeBuild(AbstractCIProject project, CIDeviceConfig device) {
	}

	@Override
	public void afterBuild(AbstractCIProject project, CIDeviceConfig device, InstrumentationPlan instrumentationPlan) {
	}

	@Override
	public void beforeExecution(AbstractCIProject arg0, CIDeviceConfig arg1, InstrumentationPlan arg2,
			AbstractDeviceExecutionHandler arg3) {

	}

}

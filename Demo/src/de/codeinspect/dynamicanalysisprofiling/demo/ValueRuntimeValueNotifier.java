package de.codeinspect.dynamicanalysisprofiling.demo;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.codeinspect.dynamicvalues.base.TraceEvent;
import de.codeinspect.dynamicvalues.base.ValueTraceEvent;
import de.codeinspect.dynamicvalues.base.extractionHandlers.AbstractParameterData;
import de.codeinspect.dynamicvalues.base.extractionHandlers.IExtractionHandlerData;
import de.codeinspect.dynamicvalues.extraction.IRuntimeValueNotifier;
import de.codeinspect.dynamicvalues.extraction.LoggingPointTraceEventAssoc;
import de.codeinspect.dynamicvalues.extraction.Run;
import de.codeinspect.soot.CIScene;

/**
 * This class is used as a hook to get informed when the app sends events to
 * VUSC.
 * 
 * @author Marc Miltenberger
 */
public class ValueRuntimeValueNotifier implements IRuntimeValueNotifier {
	private final static Logger logger = LogManager.getLogger(ValueRuntimeValueNotifier.class);

	@Override
	public void notify(Run run, List<LoggingPointTraceEventAssoc> lpvte) {
		// we want local names to have more descriptive information
		CIScene.v().allowLocalNames = true;

		for (LoggingPointTraceEventAssoc p : lpvte) {
			TraceEvent te = p.getTraceEvent();
			if (te instanceof ValueTraceEvent) {
				ValueTraceEvent vt = (ValueTraceEvent) te;

				StringBuilder sb = new StringBuilder(String.format("Runtime value found at %s in %s:\n",
						p.getLoggingPoint().getStmt(), p.getLoggingPoint().getSootMethod().getSignature()));
				for (IExtractionHandlerData handlerData : vt.getExtractionHandlerData()) {
					if (handlerData instanceof AbstractParameterData<?>) {
						AbstractParameterData<Object> paramData = (AbstractParameterData<Object>) handlerData;

						// Base object
						if (paramData.getBaseObjectValue() != null) {
							String s = (String) paramData.getBaseObjectValue();
							sb.append("Base: ").append(s).append("\n");

						}

						// Parameter values
						if (paramData.getParameterValues() != null) {
							int idx = 0;
							for (Object i : paramData.getParameterValues()) {
								if (i != null) {
									sb.append("Parameter").append(idx).append(": ").append(i).append("\n");
								}
								idx++;
							}
						}

						// Return value
						if (paramData.getReturnValue() != null) {
							sb.append("Return value: ").append(paramData.getReturnValue()).append("\n");
						}
					}
				}

				logger.info(sb.toString().trim());
			}
		}
	}

}

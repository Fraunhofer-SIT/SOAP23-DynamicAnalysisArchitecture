package de.codeinspect.dynamicanalysisprofiling.eval;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;

import org.apache.commons.io.output.NullOutputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.common.base.Joiner;

import de.codeinspect.dynamicvalues.base.TraceEvent;
import de.codeinspect.dynamicvalues.base.kryo.KryoEventTraceDevice;
import de.codeinspect.dynamicvalues.extraction.IRuntimeValueNotifier;
import de.codeinspect.dynamicvalues.extraction.LoggingPointTraceEventAssoc;
import de.codeinspect.dynamicvalues.extraction.Run;
import de.codeinspect.dynamicvalues.serialization.kryo.io.Output;
import de.codeinspect.platforms.soot.values.LoggingPoint;
import de.codeinspect.soot.CIScene;
import de.codeinspect.soot.SootInstanceBase;
import de.codeinspect.soot.SootInstanceBase.SootOperation;

/**
 * This class is used as a hook to get informed when the app sends events to
 * VUSC.
 * 
 * These events get collected and written out to disk for evaluation purposes.
 * 
 * @author Marc Miltenberger
 */
public class GlobalEvalRuntimeValueNotifier implements IRuntimeValueNotifier {
	private final static Logger logger = LogManager.getLogger(GlobalEvalRuntimeValueNotifier.class);
	protected static final int TRACEEVENTSIZE;

	static de.codeinspect.dynamicvalues.serialization.kryo.Kryo kryo = KryoEventTraceDevice.createKryo();
	static {

		kryo.setRegistrationRequired(false);
		kryo.setClassLoader(Thread.currentThread().getContextClassLoader());
		TRACEEVENTSIZE = getSize(new TraceEvent(1, 1, 1, 1));

	}

	private static int getSize(TraceEvent te) {
		Output o = new Output(new NullOutputStream());
		kryo.writeClassAndObject(o, te);
		return o.position();
	}

	private static class EventList {

		private Run run;
		private List<LoggingPointTraceEventAssoc> lpvte;
		private SootInstanceBase inst;

		public EventList(SootInstanceBase inst, Run run, List<LoggingPointTraceEventAssoc> lpvte) {
			this.inst = inst;
			this.run = run;
			this.lpvte = lpvte;
		}

	}

	private static LinkedBlockingDeque<EventList> QUEUE = new LinkedBlockingDeque<>();

	static {
		Thread thrEval = new Thread(new Runnable() {

			@Override
			public void run() {
				SootInstanceBase.cleanThreadLocal();
				final Encoder enc = Base64.getEncoder();
				while (true) {
					try {
						EventList l = QUEUE.poll(365 * 100, TimeUnit.DAYS);
						Map<Run, List<EventList>> ml = new IdentityHashMap<>();
						while (!QUEUE.isEmpty()) {
							EventList p = QUEUE.poll();
							List<EventList> res = ml.get(p.run);
							if (res == null) {
								res = new ArrayList<>();
								ml.put(p.run, res);
							}
							res.add(p);
						}
						for (Entry<Run, List<EventList>> ll : ml.entrySet()) {
							Run r = ll.getKey();

							File fdir = r.project.getCIProjectDir().getActualFile();
							File f = new File(fdir, "EventMetadata.txt");

							try (FileOutputStream fos = new FileOutputStream(f, true);
									PrintWriter pw = new PrintWriter(new BufferedOutputStream(fos, 8192 * 16))) {
								final List<EventList> currentrun = ll.getValue();
								ll.getValue().get(0).inst.doSootOperation(new SootOperation() {

									@Override
									public void doSootOperation() throws Exception {
										CIScene.v().allowLocalNames = false;
										// s = le + " events for " + l.run.project.getName();
										// logger.info("Got " + s);
										int ic = 0;
										for (EventList l : currentrun) {
											for (LoggingPointTraceEventAssoc p : l.lpvte) {
												TraceEvent te = p.getTraceEvent();
												write(pw, te.getID());
												write(pw, te.getTimestamp());
												write(pw, te.getProcessId());
												write(pw, te.getThreadId());
												int sz;
												if (te.getClass() == TraceEvent.class)
													sz = TRACEEVENTSIZE;
												else
													sz = getSize(te);
												write(pw, sz);
												LoggingPoint lp = p.getLoggingPoint();
												write(pw, enc.encodeToString(lp.toString().getBytes()));
												List<String> cn = lp.getExtractionHandlerClassNames();
												if (cn != null)
													Joiner.on(',').appendTo(pw, cn);
												pw.append('|');
												write(pw, enc.encodeToString(lp.getStmt().toString().getBytes()));
												write(pw, enc
														.encodeToString(lp.getSootMethod().getSignature().getBytes()));
												pw.println(lp.getUniqueIdentifier());
												ic++;
											}
										}
										logger.info(
												"Finished writing " + ic + " events for " + l.run.project.getName());
									}
								});

							}
						}
					} catch (Exception e) {
						e.printStackTrace();
						logger.error("An error occurred on writing out event list", e);
					}
				}
			}

			private void write(PrintWriter pw, Object o) {
				pw.append(o.toString());
				pw.append('|');
			}

		});
		thrEval.setName("Global Eval Runtime Value Notifier");
		thrEval.setDaemon(true);
		thrEval.start();
	}

	@Override
	public void notify(Run run, List<LoggingPointTraceEventAssoc> lpvte) {
		EventList l = new EventList(SootInstanceBase.getCurrentSootInstance(), run, lpvte);
		QUEUE.add(l);
	}

}

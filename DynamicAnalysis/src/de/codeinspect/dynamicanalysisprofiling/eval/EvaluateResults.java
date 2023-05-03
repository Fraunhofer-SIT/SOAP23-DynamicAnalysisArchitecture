package de.codeinspect.dynamicanalysisprofiling.eval;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.List;
import java.util.Locale;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.GZIPInputStream;

import org.apache.commons.io.IOUtils;

import com.esotericsoftware.kryo.io.Input;

import de.codeinspect.base.utils.ParallelBase;
import de.codeinspect.base.utils.ParallelBase.ParallelOperation;
import de.codeinspect.evaluation.EnumConverter;
import de.codeinspect.evaluation.IConverter;
import de.codeinspect.evaluation.IIntegerDataRow;
import de.codeinspect.evaluation.IntegerMultiRows;

public class EvaluateResults {
	static final Decoder dec = Base64.getDecoder();

	private static final EnumConverter CONVERTER_EVENT_STATS = new EnumConverter(PerEventStatistics.class);
	private static final EnumConverter CONVERTER_STATS = new EnumConverter(PerEventTypeStatistics.class);

	private static NumberFormat NUM_INST = NumberFormat.getNumberInstance(Locale.US);

	static enum PerAppStatistics {
		NumberOfEvents("Number of events");

		private String str;

		PerAppStatistics(String string) {
			this.str = string;
		}

		@Override
		public String toString() {
			return str;
		}
	}

	static enum NumberStatistics {
		Number("Number");

		private String str;

		NumberStatistics(String string) {
			this.str = string;
		}

		@Override
		public String toString() {
			return str;
		}
	}

	static enum PerEventStatistics {
		Size("Size");

		private String str;

		PerEventStatistics(String string) {
			this.str = string;
		}

		@Override
		public String toString() {
			return str;
		}
	}

	static enum PerEventTypeStatistics {
		Taint("Taint"), CG("Callgraph"), Value("Value");

		private String str;

		PerEventTypeStatistics(String string) {
			this.str = string;
		}

		@Override
		public String toString() {
			return str;
		}
	}

	public static void main(String[] args) throws IOException {
		File base = new File(args[0]);
		List<File> d = new ArrayList<>();
		for (File a : base.listFiles()) {
			if (!a.isDirectory())
				continue;
			d.add(a);
		}
		IntegerMultiRows<PerAppStatistics> perAppStats = new IntegerMultiRows<>();
		IntegerMultiRows<PerEventStatistics> perEventStats = new IntegerMultiRows<>();
		IntegerMultiRows<PerEventTypeStatistics> perEventTypeStatsSizes = new IntegerMultiRows<>();
		IntegerMultiRows<PerEventTypeStatistics> perEventTypeStats = new IntegerMultiRows<>();
		AtomicInteger appsWithResults = new AtomicInteger();
		// ParallelBase.NUM_CORES = 1;
		AtomicInteger anr = new AtomicInteger();
		ParallelBase.For(d, new ParallelOperation<File>() {

			@Override
			public boolean perform(File r, int progress, int max) {
				try {
					IntegerMultiRows<PerEventStatistics> perEventStatsInApp;
					IntegerMultiRows<PerEventTypeStatistics> perEventTypeStatsInApp;
					File tmpSer = new File(r, "EventMetadata" + r.length() + ".statsser");
					File lc = new File(r, "LogCat.txt");
					if (lc.exists()) {
						try (FileInputStream fis = new FileInputStream(lc)) {
							List<String> s = IOUtils.readLines(fis);

							for (String p : s) {
								if (p.contains("because it is not responsive")) {
									anr.incrementAndGet();
									break;
								}
							}
						}
					}
					perEventStatsInApp = new IntegerMultiRows<>();
					perEventTypeStatsInApp = new IntegerMultiRows<>();
					InputStream is = openEventStream(r);
					if (is != null) {

						try (BufferedReader br = new BufferedReader(new InputStreamReader(is))) {
							while (true) {
								String l = br.readLine();
								if (l == null || l.isEmpty())
									break;
								String[] p = l.split("\\|");
								String timestamp = p[1];
								boolean isCGEvent = true;
								int eventsize = Integer.parseInt(p[4]);
								if (!timestamp.equals("0")) {
									// Only Value events have a timestamp.
									isCGEvent = false;
								} else
									perEventTypeStatsInApp.add(PerEventTypeStatistics.CG, eventsize);
								if (!isCGEvent) {
									String extractionHandlerClassNames = p[6];
									switch (extractionHandlerClassNames) {
									case "de.codeinspect.dynamicvalues.android.extractionHandlers.taintTracking.TaintSourceHandler":
									case "de.codeinspect.dynamicvalues.android.extractionHandlers.taintTracking.TaintPathHandler":
									case "de.codeinspect.dynamicvalues.android.extractionHandlers.taintTracking.TaintTransferHandler":
										perEventTypeStatsInApp.add(PerEventTypeStatistics.Taint, eventsize);
										break;
									case "de.codeinspect.dynamicvalues.base.extractionHandlers.dynamiccg.DynamicSpecialRuntimeExtractionHandler":
										perEventTypeStatsInApp.add(PerEventTypeStatistics.CG, eventsize);
										break;

									case "":
										perEventTypeStatsInApp.add(PerEventTypeStatistics.Value, eventsize);
										break;
									default:
										throw new RuntimeException(extractionHandlerClassNames);
									}
								}
								perEventStatsInApp.add(PerEventStatistics.Size, eventsize);
							}

						}
						is.close();
					} else
						return false;

					try (FileInputStream fis = new FileInputStream(tmpSer); Input i = new Input(fis)) {

						synchronized (appsWithResults) {
							perEventStatsInApp.fillMissingEntriesWithZero((Iterable) CONVERTER_EVENT_STATS);
							perEventTypeStatsInApp.fillMissingEntriesWithZero((Iterable) CONVERTER_STATS);
							perEventStats.mergeFrom(perEventStatsInApp);
							perEventTypeStatsSizes.mergeFrom(perEventTypeStatsInApp);

							int tc = 0;
							for (Entry<PerEventTypeStatistics, IIntegerDataRow> t : perEventTypeStatsInApp) {
								perEventTypeStats.add(t.getKey(), (int) t.getValue().getSize());
								tc += (int) t.getValue().getSize();
							}
							appsWithResults.incrementAndGet();
						}
					}
					int numOfEventsInApp = (int) perEventStatsInApp.getDataRow(PerEventStatistics.Size).getSize();
					perAppStats.add(PerAppStatistics.NumberOfEvents, numOfEventsInApp);
				} catch (Exception e) {
					e.printStackTrace();
				}
				return false;
			}
		});
		perAppStats.verifyAllRowsHaveSameSize();
		perEventStats.verifyAllRowsHaveSameSize();

		System.out.println("We have " + appsWithResults + " apps with results.");
		System.out.println("Per app stats");
		System.out.println(perAppStats.toString());
		System.out.println();
		System.out.println("Event stats");
		System.out.println(perEventStats.toString());
		System.out.println();
		System.out.println("Per event type  size stats");
		System.out.println(perEventTypeStatsSizes);
		System.out.println("Per event type stats");
		System.out.println(perEventTypeStats);
		NUM_INST.setMaximumFractionDigits(2);

		System.out.println(perAppStats.toLatexVariablesString("Apps", NUM_INST));
		System.out.println(perEventStats.toLatexVariablesString("Events", NUM_INST));
		System.out.println(perEventTypeStatsSizes.toLatexVariablesString("Event type sizes", NUM_INST));
		System.out.println(perEventTypeStats.toLatexVariablesString("Event types", NUM_INST));

	}

	private static String de(String string) {
		return new String(dec.decode(string));
	}

	private static InputStream openEventStream(File r) throws IOException {
		File res = new File(r, "EventMetadata.txt");
		if (res.exists())
			return new FileInputStream(res);
		File resT = new File(r, "EventMetadata.txt.gz");
		if (resT.exists())
			return new GZIPInputStream(new FileInputStream(resT));

		return null;
	}

}

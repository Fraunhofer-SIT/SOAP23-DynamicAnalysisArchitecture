package de.codeinspect.dynamicanalysisprofiling.eval;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPOutputStream;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.codeinspect.base.projects.AbstractCIProject;
import de.codeinspect.communication.admin.devices.CIDeviceConfig;
import de.codeinspect.dfarm.device.DFarmCIDevice;
import de.codeinspect.dynamicvalues.analysisserver.devices.AbstractDeviceExecutionHandler;
import de.codeinspect.dynamicvalues.analysisserver.executors.IAndroidExecutorEventHandler;
import de.codeinspect.dynamicvalues.instrumentation.InstrumentationPlan;
import de.codeinspect.graphics.AbstractImage;
import de.codeinspect.platforms.android.devices.CommandExecuteException;
import de.codeinspect.platforms.android.devices.ICIAndroidDevice;
import de.codeinspect.platforms.base.devices.ICIDevice;
import de.fraunhofer.sit.beast.client.api.DevicesApi;
import okhttp3.Call;
import okhttp3.Response;
import okio.Timeout;

/**
 * This class handles the main part of the evaluation. It gets informed by VUSC
 * when the dynamic analysis begins/ends/has errors.
 * 
 * @author Marc Miltenberger
 */
public class AndroidExecutorEventHandler implements IAndroidExecutorEventHandler {

	private volatile boolean stop;

	private static final Logger logger = LogManager.getLogger(AndroidExecutorEventHandler.class);
	private FileOutputStream logs;

	@Override
	public void onException(AbstractCIProject project, CIDeviceConfig device, Exception e) {
		File error = new File(project.getCIProjectDir().getActualFile(), "ErrorOccurred.txt");
		stop = true;
		try {
			String str = "An exception occurred in " + project + " using " + device + "\n"
					+ ExceptionUtils.getStackTrace(e);
			logger.error(str);
			FileUtils.write(error, str);
		} catch (IOException e1) {
			logger.error(e1);
		}
		try {
			logs.close();
		} catch (IOException e1) {
			logger.error(e1);
		}
	}

	@Override
	public void beforeBuild(AbstractCIProject project, CIDeviceConfig device) {
	}

	@Override
	public void afterBuild(AbstractCIProject project, CIDeviceConfig device, InstrumentationPlan instrumentationPlan) {
	}

	@Override
	public void beforeExecution(AbstractCIProject project, CIDeviceConfig device,
			InstrumentationPlan instrumentationPlan, AbstractDeviceExecutionHandler executionHandler) {
		stop = false;
		File log = new File(project.getCIProjectDir().getActualFile(), "LogCat.txt");
		try {
			logs = new FileOutputStream(log);
			ICIDevice dev = executionHandler.getCiDevice();
			ICIAndroidDevice a = (ICIAndroidDevice) dev.createInstance(device);
			Thread thrLogcat = new Thread() {
				@Override
				public void run() {
					try {
						if (a instanceof DFarmCIDevice) {
							DFarmCIDevice cid = (DFarmCIDevice) a;
							int devID = cid.getDeviceInformation().getID();

							DevicesApi devicesApi = new DevicesApi(cid.getClient());
							while (!stop) {
								try {
									Call d = devicesApi.getDeviceLogCall(devID, null, null);

									Timeout t = d.timeout();
									t.deadline(100, TimeUnit.HOURS);
									try (Response c = d.execute()) {

										try (BufferedReader dd = new BufferedReader(c.body().charStream())) {
											while (!stop) {
												String line = dd.readLine();
												if (line == null)
													break;
												logs.write(line.getBytes());
												logs.write('\n');
											}
										}
									}
								} catch (Exception e) {
									if (stop)
										return;
									logger.error("Could not retrieve logcat", e);
									onException(project, device, e);
								}
							}
						} else
							a.executeShellCommand("logcat", logs);
					} catch (CommandExecuteException e) {
						onException(project, device, e);
					}
				}
			};
			thrLogcat.setName("LogCat " + project + " - " + device);
			thrLogcat.setDaemon(true);
			thrLogcat.start();

			Thread thrLScreenshots = new Thread() {
				@Override
				public void run() {
					int x = 0;
					while (!stop) {
						try {
							Thread.sleep(20000);
						} catch (InterruptedException e) {
						}
						try {
							AbstractImage t = a.takeScreenshot();
							if (t != null) {
								x++;
								byte[] b = t.getImageData();
								File fs = new File(project.getCIProjectDir().getActualFile(),
										"Screenshot" + x + "." + t.getFileFormat().getDefaultExtension());
								FileUtils.writeByteArrayToFile(fs, b);
							}
						} catch (Exception e) {
							// Not that important anyways...
						}
					}
				}
			};
			thrLScreenshots.setName("Screenshot " + project + " - " + device);
			thrLScreenshots.setDaemon(true);
			thrLScreenshots.start();
		} catch (Exception e) {
			onException(project, device, e);
		}
	}

	@Override
	public void afterExecution(AbstractCIProject project, CIDeviceConfig device,
			InstrumentationPlan instrumentationPlan, AbstractDeviceExecutionHandler executionHandler) {
		try {
			stop = true;
			logs.close();
			File fdir = project.getCIProjectDir().getActualFile();
			File f = new File(fdir, "EventMetadata.txt");
			if (f.exists()) {
				File fz = new File(fdir, "EventMetadata.txt.gz");
				if (!fz.exists()) {
					try (GZIPOutputStream gz = new GZIPOutputStream(new FileOutputStream(fz));
							FileInputStream fin = new FileInputStream(f)) {
						IOUtils.copyLarge(fin, gz);
						fin.close();
						gz.close();
					} catch (Exception ex) {
						logger.error("Could not write out gzip stream", ex);
						fz.delete();
					}
				}
			}
		} catch (IOException e) {
			logger.error(e);
		}
	}

}

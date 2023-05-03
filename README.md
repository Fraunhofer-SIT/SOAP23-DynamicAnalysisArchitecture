This repository is part of the SOAP 2023 paper ``Extensible and Scalable Architecture for Hybrid Analysis``

# Dependencies
The code uses the commercial vulnerability binary scanner VUSC as a basis. In essence, this repository contains plug-ins for the VUSC scanner.
In order to run the dynamic analyses, you need a VUSC server. Contact the folks at CyWare (https://secure-software.io/) for an academic license.

# Code

This repository contains code for two plug-ins:
##  ```de.codeinspect.dynamicanalysisprofiling.demo```

A sample plug-in which can be used as a basis to set a custom set of sources/sinks and to ask for specific values.
This plug-in prints more information than the evaluation plug-in and can be used as a basis for a real-world analysis.

## ```de.codeinspect.dynamicanalysisprofiling.eval```

This Code used for the evaluation. It profiles the events and writes out the event data to files, which can get rather large. it uses the vulnerability analyses of VUSC to determine the used sources/sinks for the data flow analysis and requested values. This project is used to obtain metadata about the events (number and size).


# Apps
To obtain our original set of apps, you can query AndroZoo with the SHA256 hashes of the apps (45 GB total). You can find the sha-256-sums in ```apps-sha256sums.txt```.
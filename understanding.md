## THIS IS A DETAILED IDS DOCUMENT FOR OTHERS TO UNDERSTAND THE ARCHITECTURE AND WORKING OF MY IDS FURTHER IN MAINTAINING THE IDS.


I have made an IDS for network and host IDS which raises an alert when there is a match with its observation against known-bad patterns.
The known bad patterns are signatures rules and thresholds.

# Hybrid IDS which has Network and Host IDS.

Network ids = sniffs live traffic with scapy[python library] 

Host ids = it tails logs for integrity checks of the files and brute-force attempts.

        Integrity Checks Are done by checking their sha 256 hash of critical files which can be configured along the persons needs for me i made it for linux[ex./etc/passwd]

# Architecture : Hexagonal Ports and Adapters pattern.

**NIDS module** = takes live look for traffic and looks if there are any problems or issues such as port scans , syn,icmp floods dos attacks on ports that can be manipulated or exploited.

**HIDS module** = manages and looks after logs and hash integrity checks.

**Signature engine** = The detection logic and rule definitions are complete seperate so that new rules can be added without touching the logic. Hence can be futher upgraded if and when in need. 

**Unified Logger** = This is the all in one logger that shows output of the ids to the user colour coded for the severity.

**why ports and adapters achitechture? :** = the detector is feeded with strings and dictionary rather than files which is done by a function in log_monitor.py and sniffer.py 


# HIDS: Host IDS

**Log Monitoring and Brute-force Detection:** Because we are using the port and adapter architecture the following are the details and code's requirement as to why it was needed.

    --The Adapter = tail_file() is the function that works as adapter in HIDS which is located in log_monitor.py

    --Data Extraction = The class which is defined to take in strings or dict takes in and matches them to regex value if the flag is raises the target's ip and target's  user.

    --Stateful Tracking = It adds the failed attempt timestamps to a collections.deque sliding window, discarding older events to calculate the rate of failure.

    --Correlated Alerts = It flags standard SSH_BRUTEFORCE attacks, but it also correlates events by tracking if an IP successfully logs in immediately after a string of  failures, escalating the alert to SUCCESSFUL_LOGIN_AFTER_FAILURES.

**File integrity Monitoring:** Checks if the integrity of a certain file has been compromised or not by checking its hash value.

    --The Baselining = The important files or the files that are configured to be checked have their hash(SHA-256) be stored in json baseline file.

    --Memory Efficiency = The hash of the file is done in chunks of 8kb() to avoid crashes as the files memory might be large.In file_integrity.py there is function hash_file in which there is a certain line f.read(8192) which makes it possible.

    --Granular Alerting = This checks the file's state periodically and alerts if there are any transitions. The hardcoded alterations or transitions are as follows : FILE_CREATED , FILE_MODIFIED & FILE_DELETED giving the analyst a precise context for further actions.

**Suspicious Process Scanning:** This is for scanning the currently active process id's , usernames and commands or command line arguments.

    --System Polling = Main file is process_monitor.py and the important library used is psutil to periodically scan for active process id's , usernames and command line arguments.

    --Rule Matching = It checks for running software for suspicious process names that are set in signatures.py to catch the popular red team tools.

    --False positive Prevention = Before checking for a match it delibrately splits process names into individual tokens so that innocent process are not misunderstood triggering a false positive alarm.

# NIDS: Network IDS

**Packet Capture and Normalization:** Packet is captured and looked within for malicious activity and after scanning the packet is immediately dumped so that no memory leaks or crashes take place.

    --Live Sniffing = Uses the sniffy() function in sniffer.py and crucially drops or discards the packet using a key note store=false avoiding crashes.

    --Normalization = This strips away the heavy packet captured by scappy and takes in only crucial information like src_ip , protocol , ports , flags , etc.

    --Protocol Decoding = During normalization routing data is manually extracted and further after bitwise operations are conducted it converts the tcp flags in strings.

**The Detection Engine for NIDS:** For Stateful and Stateless attacks.
    
    --Fan-out Processing = The NidsEngine takes packets and normalizes it into a simple dictionary and feeds it simultaneously to five different detectors in which each detector has its own task to worry about. 

    --Sliding Windows(Stateful) = A queue is setted up in code to store the timestamps of the packet keyed by IP so that the detectors detect a flood and warn but in volume based attack the timestamps will cause a memory leak and crash hence the queue drops the timestamps which are stale with O(1).

    --Matchers(Stateless) = Attacks which are not volume based like Malicious ports or ARP spoofing , hence they dont need to drop the volume timestamps so that the timestamps keyed with ip remain and can be used as evidence.

        As arp spoofing is a critical threat because of arp protocol's trust in metaphor , as the protocols trusts any machine and gives out mac addresses like candy when the ids detects that a machine having the ip of a certain device requests it again , it is also techinically a stateful attack.

    --De-duplication: To prevent a sustained 5-minute port scan from generating 10,000 duplicate logs, the detectors group alerts using a time bucket (now // self.window) so the SOC analyst only sees one clean alert per time window.


# Directory Structure 

**ROOT**

    --main.py = The entry point , reads the config , launches the logger and HIDS & NIDS monitors in their own background threads.

    --config.yaml = seperating this was a crucial element so that i can deploy the ids without altering the security rules.

**CORE**

    --init.py = This is to tell the python interpreter that this directory is to be treated as a module or package and hence old python wouldn't recognize this as a valid place to import code from. A safe side if the ids is to runned in the older versions. 

    --env = A python environment was also created while testing in kali so that the scappy was installed and a python environment was created for dependency isolation and overall protecting the kali OS.

    --pycache = It is created as a speed booster as python in a interpreted language hence making quick complilation hence making the program start up faster.

    --logger.py = The single point for all alerts this guarantees that every alert in the system is formatted identically colored by severity and safely written to disk.

**hids**

    --log_monitor.py = Contains the tail_file adapter for live logs and sshbruteforce detector logic.

    --file_integrity.py = Handles the file integrity and checks 8kb hashes chunks comparing it to a baseline SHA-256 hash.

    --process_monitor.py = Uses psutil library to scan for active processes and command-line arguments.

    --signatures.py = Holds the REGEX patterns and suspicious processes list.

**nids** 

    --sniffer.py = Adapter that imports scappy , captures raw packets and normalizes it and strips it down to its important details resulting in a short memory usage.

    --detectors.py = Contains the LOGIC for stateless and stateful classes , there are 5 detectors in this 5 classes and 5 functions of the same that evaluate the dictionaries using sliding windows and baselines.

    signatures.py = The DATA holds the rules definitions for the logic to implement and functions to implement the same.

**tests**

    --test_detectors.py = We decoupled the logic from adapters using the architecture.

**logs**

    --ids_alerts.log = ids_alerts.log is a log file that keeps the logs and dumps after it becomes stale.

    --fim_baseline.json = stores the baseline SHA-256 hash of the files to check for integrity.


# Concurrency Model 

    --main.py = runs each monitor with threads

    --daemon=True = when main thread exits the other threads die rather than hanging the process.

    --readline() = for I/O using GIL

    --multiprocessing = would add IPC(inter process communication) complexity which will be extremely un-necessary hence making new process and assigning new memory chunks making the tool bloated and we dont want that.

# Alert Severity Classification

    --Severity is not dynamic its hardcoded to make the tool light and a local one.

__Medium__ = ICMP_FLOOD , Suspicious Process , File_Created

__High__ = Port_Scan , Malicious_Port , File_Modified , SSH_Bruteforce

__Critical__ = SYN_FLOOD , ARP_SPOOF , File_Deleted , Successful_Login_After_Failures

    Successful_Login_After_Failures = This is a function/class to detect when a brute-force attack was launched and it was successful. 

This Maps loosely into Cyber Kill Chain model as for reconnaissance -> weaponization -> delivery -> exploitation -> and further on.

# Limitations of this IDS 

**Signature-based only** = No anomaly detection , attacks that are not within the set rules are not detected.

**In-memory state , no persistence** = A restart loses all of the attack history because it uses sliding window and dequeue objects in RAM.

**No Alerting System** = Alerts go to the terminal screen in which the ids is running so the screen needs to be monitored at all times for further de-escaltion of events or attacks.

**Static Severity Checks** = Preset Severity based on past experience of attacks.

**Polling Based System** = Right know the file is checked after every 0.5 seconds and its not very efficient in production , in production there is a feature (for linux) [inotify] which makes so that when the file is modified the system is notified.

# Conclusion : A project based IDS for upgrading resume.

Hybrid IDS designed to catch known and popular attacks but demonstrate's Hexagonal Ports and Adapters based architecture not for PRODUCTION USE.
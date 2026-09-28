# RunMRU Entry Contains Suspicious PowerShell or LOLBin Execution


## Description


Identifies potentially suspicious commands executed through the **Windows Run dialog (Win+R)** by monitoring registry modifications to the **RunMRU** key.


The query detects commands entered into the Run dialog that reference PowerShell, command shells, scripting interpreters, and Living-off-the-Land Binaries (LOLBins) commonly abused by threat actors for payload execution, download-and-execute activity, persistence, and defense evasion.


This detection was inspired by investigation activity where a malicious PowerShell command executed from the Run dialog was recovered from the RunMRU registry artifact, enabling reconstruction of the execution chain and user activity.


## MITRE ATT&CK Mapping


- **Tactic:** Execution

- **Technique:** T1059 - Command and Scripting Interpreter


- **Tactic:** Defense Evasion

- **Technique:** T1218 - System Binary Proxy Execution


- **Tactic:** User Execution

- **Technique:** T1204 - User Execution


> **Mapping Note:** Not all commands recorded in the RunMRU registry key are malicious. The detection should be reviewed in context with process creation, network activity, parent-child process relationships, and user activity. Commands involving PowerShell, script interpreters, or LOLBins executed via the Run dialog may indicate user-assisted malware execution, ClickFix-style attacks, or hands-on-keyboard activity.


## Query


```kql

let Executables = dynamic([
    "powershell",
    "pwsh",
    "cmd",
    "curl",
    "mshta",
    "msiexec",
    "wscript",
    "cscript",
    "rundll32",
    "regsvr32"
]);
DeviceRegistryEvents
| where RegistryKey endswith @"\Explorer\RunMRU"
| where ActionType == "RegistryValueSet"
| where RegistryValueType == "String"
| where RegistryValueName != "MRUList"
| where RegistryValueData has_any (Executables)
| project
    Timestamp,
    DeviceName,
    DeviceId,
    InitiatingProcessAccountName,
    RegistryValueName,
    RegistryValueData
| order by Timestamp desc

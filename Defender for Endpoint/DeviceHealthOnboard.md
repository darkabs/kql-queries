# Devices Not Onboarded to Microsoft Defender for Endpoint

## Description

Identifies applicable devices that are not compliant with the Microsoft Defender for Endpoint onboarding configuration.

This query can be used to identify endpoint visibility gaps where devices are not properly onboarded to Microsoft Defender for Endpoint.

## MITRE ATT&CK Mapping

- **Tactic:** Defense Evasion
- **Technique:** T1562 - Impair Defenses
- **Sub-technique:** T1562.001 - Disable or Modify Tools

> **Mapping Note:** This query identifies a security control gap rather than directly detecting adversary behavior. A device that is not onboarded to Microsoft Defender for Endpoint may reduce endpoint monitoring and detection visibility, which can support defense evasion.

## Query

```kql
let devices = dynamic([]); //provide list of devices

DeviceTvmSecureConfigurationAssessment
| where DeviceName has_any (devices)
    or DeviceId has_any (devices)
| where ConfigurationId == "scid-20000"
| where ConfigurationSubcategory == "Onboard Devices"
| where IsApplicable == true
| where IsCompliant == false
| summarize LastCheck = max(Timestamp)
    by DeviceName, DeviceId, IsCompliant, ConfigurationSubcategory
| order by LastCheck desc

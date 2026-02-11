# 🖥️ Virtual-Machine-Brute-Forcing


# ➡️ Explanation
When entities (local or remote users, usually) attempt to log into a virtual machine, a log will be created on the local machine and then forwarded to Microsoft Defender for Endpoint under the DeviceLogonEvents table. These logs are then forwarded to the Log Analytics Workspace being used by Microsoft Sentinel, our SIEM. Within Sentinel, we will define an alert to trigger when the same entity fails to log into the same VM a given number of times within a certain time period. (i.e. 10 failed logons or more per 5 hours).

# ➡️ Part 1: Create Alert Rule (Brute Force Attempt Detection)
Design a Sentinel Scheduled Query Rule within Log Analytics that will discover when the same remote IP address has failed to log in to the same local host (Azure VM) 10 times or more within the last 5 hours

Use the DeviceLogonEvents table.
KQL Query Spoiler

<h4/>KQL Query: 👇


DeviceLogonEvents

| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)

| summarize EventCount = count() by RemoteIP, DeviceName

| where EventCount >= 10

| order by EventCount

<h3>Once your query is good, create the Schedule Query Rule in: Sentinel → Analytics → Schedule Query Rule

---
<br/>

# ➡️ Analytics Rule Settings:
  <br/>
  
- Enable the Rule
- Use ChatGPT to set Mitre ATT&CK Framework Categories based on the query
- Run query every 4 hours
- Lookup data for last 5 hours (can define in query)
- Stop running query after alert is generated == Yes
- Configure Entity Mappings for the Remote IP and DeviceName
- Automatically create an Incident if the rule is triggered
- Group all alerts into a single Incident per 24 hours
- Stop running query after alert is generated (24 hours)

---
# ➡️ Part 2: Trigger Alert to Create Incident
Trigger the rule manually to create an incident. If the necessary logs to trigger the rule don’t exist, create the logs by failing to log into the machine an adequate number of times.

Don’t get confused between the [Configuration → Analytics] and [Threat Management → Incidents] sections.

---
# ➡️ Part 3: Work Incident
- <h3/>Work your incident to completion and close it out, in accordance with the NIST 800-61: Incident Response Lifecycle

<h4/>Preparation

- Document roles, responsibilities, and procedures.
- Ensure tools, systems, and training are in place.
---
<h4/>▶️Detection and Analysis

- Identify and validate the incident.
- Observe the incident and assign it to yourself, set the status to Active
- Investigate the Incident by Actions → Investigate (sometimes takes time for entities to appear)
- Gather relevant evidence and assess impact.
- Observe the different entity mappings and take notes:
- The Brute Force Detection - >VM name< incident was triggered from 6 different IP addresses against 2 different hosts. <Lists Hosts and IPs>
- Check to make sure none of the IP addresses attempting to brute force the machine actually logged in. (Hint: It’s possible to build this into the query to only trigger for apparent successful brute forces)
- Record Findings
- Containment, Eradication, and Recovery
- Isolate affected systems to prevent further damage.
- In real life if this was a serious threat, we would isolate your machine with Defender for Endpoint
- Conduct an AV scan
---
<h4/>▶️Containment, Eradication, and Recovery

- Isolate affected systems to prevent further damage.
- In real life if this was a serious threat, we would isolate your machine with Defender for Endpoint
- Conduct an AV scan


<h4/>KQL Query: 👇

- let TargetDevice = "VM machine"; // Replace with target VM
- let SuspectIP = "example: 89.116.158.44"; // Replace with suspect IP

DeviceLogonEvents

| where ActionType == "LogonSuccess"

| where DeviceName == TargetDevice and RemoteIP == SuspectIP

| order by TimeGenerated desc

---
<h4/>For the lab, create or update the Network Security Group (NSG) attached to your Virtual Machine to prevent any traffic except your local PC from reaching the VM, and record in your notes:

- NSG was locked down to prevent RDP attempts from the public internet.
- Corporate policy was proposed to require this for all VMs going forward. (this can be done with Azure Policy)

<h4/>Remove the threat and restore systems to normal.

- Brute force was not successful, so no threats related to this incident.

<h4/>Post-Incident Activities

- Document findings and lessons learned.
- Record your notes within the incident.
- Update policies and tools to prevent recurrence.
- In real life, we would probably make a company policy for hardening the VMs to not allow completely wide open NSGs. This can be done with Azure Policy, but we won’t do anything for now. Just acknowledge it

# Closure

- Review and confirm incident resolution.
- Review/observe your notes for the incident.
- Finalize reporting and close the case.
- Close out the Incident within Sentinel as a “True Positive”

---
# 🏁 Part 4: Cleanup (BE EXTREMELY CAREFUL HERE)

- In Sentinel → Threat Management → Incidents, filter for closed incidents and delete YOUR incident
- In Sentinel → Configuration → Analytics, delete YOUR analytics rule.
- Be extremely careful to only delete YOUR Incident and Analytics Rule. Do not screw this up and delete someone else's, because it’s possible. Search by your name to narrow them down if you have to.





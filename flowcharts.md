# ICS Honeypot Brute-force Attack & CTI Response Flow

## Attack Scenario: Brute-force against ICS Honeypot

```mermaid
flowchart TD
  A[Brute-force attempt on ICS honeypot from unknown IP]
  B{Is IP internal or whitelisted?}
  C[Honeypot logs IP, port, protocol]
  D[Reputation checked via CTI platform]
  E{Is reputation malicious?}
  F[Trigger internal incident response playbook]
  G[Generate Snort deny rule: drop 179.43.180.106 any -> any any]
  H[Add IP to iptables drop list: -A INPUT -s 179.43.180.106/32 -p tcp -m state --state NEW -j REJECT]
  I[Notify SOC / IR team]
  J[Send alert to analyst dashboard]
  K[Trigger external CTI sharing playbook]
  L[Create new org in MISP if needed]
  M[Publish IOC as public indicator]
  N[Share to CTI platforms TAXII/MISP Federation]
  O[Generate other custom firewall rule]

  A --> B
  B -- No --> C --> D --> E
  E -- Yes --> F --> I --> J --> G
  J --> H
  J --> O
  F --> K --> L --> M --> N
```


> **Generate SNORT detection alerts:**
- Detect repeated SSH connection attempts :
  ```
  alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"ICS Brute-force SSH Login Attempt"; flow:to_server,established; detection_filter:track by_src, count 5, seconds 60; sid:1001001; rev:1;)
  ```
- Detect VNC access attempts to SCADA HMI :
  ```
  alert tcp $EXTERNAL_NET any -> $HOME_NET 5900 (msg:"ICS Brute-force VNC Access to HMI"; flow:to_server,established; detection_filter:track by_src, count 5, seconds 60; sid:1001002; rev:1;)
  ```
- General ICS HMI web login attempts  :
  ```
  alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"ICS Web Login Brute-force"; flow:to_server,established; content:"Authorization: Basic"; nocase; http_header; detection_filter:track by_src, count 10, seconds 60; sid:1001003; rev:1;)
  ```

```mermaid
sequenceDiagram
  participant Attacker
  participant Honeypot
  participant CTI
  participant SOC
  participant Firewall
  participant Snort
  participant MISP

  Attacker->>Honeypot: Brute-force login attempts (SSH/Modbus)
  Honeypot->>CTI: Query IP reputation
  CTI-->>Honeypot: Returns "malicious"
  Honeypot->>SOC: Trigger alert with IP, timestamp
  SOC->>Snort: Add dynamic deny rule
  SOC->>Firewall: Append DROP rule in iptables
  SOC->>MISP: Push IP as new IOC
  MISP->>CTI: Share indicator via public feed
  SOC->>Snort: Generate SNORT detection alerts
  ```


```mermaid
graph TB
  subgraph Detection
    D1[Unusual login attempts on ICS interface]
    D2[IP not recognized in asset inventory]
    D3[Reputation check = blacklisted]
  end

  subgraph Internal_Response
    R1[Create Snort drop rule]
    R2[Block IP in iptables]
    R3[Alert SOC analyst]
    R4[Enrich IOC with honeypot logs]
    R5[Generate SNORT detection alerts]
  end

  subgraph External_Response
    E1[Login to MISP]
    E2[Create new event: ICS brute-force]
    E3[Attach IP, port, timestamp]
    E4[Mark TLP:WHITE and share publicly]
    E5[Enable MISP Federation or TAXII push]
  end

  D1 --> D2 --> D3 --> R3 --> R1 --> R2 --> R4 --> R5  --> E1 --> E2 --> E3 --> E4 --> E5
```

### Attack Scenario: Unauthorized Modbus Write Detected

```mermaid
flowchart TD
  A[Honeypot receives Modbus write command]
  B{Source IP internal or external?}
  C[Log Modbus function code, address]
  D[Trigger anomaly alert]
  E[Query IP & fingerprint against CTI]
  F{Malicious confirmed?}
  G[Trigger local response]
  H[Add to Snort & iptables blocklist]
  I[Send to analyst dashboard]
  J[Export PCAP & logs to MISP]
  K[Tag with TTP: ICS Control Attempt]

  A --> B --> C --> D --> E --> F
  F -- Yes --> G --> H --> I --> J --> K
```



## 🧠 3. Suspicious IP Scanning Multiple ICS Ports
```mermaid
flowchart TD
  A[Multiple connection attempts on ICS ports : 502, 161, 20000]
  B[Detected by honeypot]
  C[Check IP against CTI]
  D{Known scanner?}
  E[Log and escalate alert]
  F[Block IP internally]
  G[Create scan behavior tag in MISP]
  H[Share public feed]

  A --> B --> C --> D
  D -- Yes --> E --> F --> G --> H
```

## 🧠 4. Lateral Movement Detected in ICS Subnet

```mermaid
graph TB
  A1[Compromised HMI device sends SMB/WinRM traffic]
  A2[Multiple machines accessed in short time]
  A3[Honeypot detects unusual peer enumeration]
  A4[Triggered alert: lateral movement]
  A5[SOC confirms unauthorized pivoting]
  A6[Quarantine original device]
  A7[Log all endpoints touched]
  A8[Push event to MISP]
  A9[Tag as lateral_movement & update TTPs]

  A1 --> A2 --> A3 --> A4 --> A5 --> A6 --> A7 --> A8 --> A9
```

## 🧠 5. Download of Suspicious ICS Payload from Internet

```mermaid
sequenceDiagram
  participant ICS_Host
  participant Proxy
  participant Firewall
  participant CTI
  participant MISP

  ICS_Host->>Proxy: Download file.exe from suspicious domain
  Proxy->>Firewall: Log outbound connection
  Firewall->>CTI: Check domain & hash
  CTI-->>Firewall: Malicious - APT related
  Firewall->>MISP: Upload hash, domain, metadata
  MISP-->>Analysts: IOC shared with community
```



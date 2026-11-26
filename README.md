#### Local AI SysAdmin & SecOps Agent (Open WebUI + MikroTik + Linux)

A lightweight, self-hosted Python Tool (paramiko) and strict operational system prompt for **Open WebUI** that gives a local LLM controlled SSH access to **MikroTik RouterOS** devices and **Linux VDS/bare-metal servers**. 

Instead of pasting sensitive firewall rules, logs, and IP addresses into third-party cloud APIs, everything runs 100% locally on your own hardware via **Ollama** and **Open WebUI**. 

#### Key Features

* **Zero Cloud Leakage:** All inference, SSH execution, and log analysis stay inside your local network.
* **MikroTik RouterOS CLI Safety:** Automatically enforces terse, without-paging, and count-only flags on large queries so the SSH session never hangs on firewall address-lists with 2,000+ entries.
* **Cross-Server ASN & CIDR Verification:** Rather than guessing /24 masks for suspicious IPs on MikroTik, the agent runs a batch whois lookup on a Linux node to identify the actual announced CIDR prefix and ASN owner, flagging overly broad ranges (such as /15 cloud or carrier blocks).
* **Human-in-the-Loop Guardrails:** Strictly prohibits write operations (modifying routes, firewall rules, address lists, or system configs) until the model prints the exact CLI commands, explains the blast radius, and receives explicit user confirmation.
* **Standardized Audit Trail:** Enforces uniform comments (YYYY-MM-DD | Owner/ASN | Source) on every newly added firewall entry.
* **Local IMAP Postmaster & DMARC Auditing (Optional):** Connects to a local mail server in READ-ONLY mode to unpack .xml/.gz/.zip DMARC reports and summarize spoofing attempts or backup logs.

#### Architecture


#### Quick Start

#### 1. Create a Restricted ai-ops User on Target Nodes

**On Linux servers:** 

bash

sudo useradd -m -s /bin/bash ai-ops
sudo mkdir -p /home/ai-ops/.ssh
echo "YOUR_ED25519_PUBLIC_KEY" | sudo tee /home/ai-ops/.ssh/authorized_keys
sudo chmod 700 /home/ai-ops/.ssh && sudo chmod 600 /home/ai-ops/.ssh/authorized_keys
sudo chown -R ai-ops:ai-ops /home/ai-ops/.ssh


**On MikroTik RouterOS:** 

1. Create a restricted group (e.g., ai-ops-group) with ssh,read,write,test policies (avoid full or sensitive unless required).
2. Create user ai-ops assigned to that group and import your id_ed25519.pub key under **System -> Users -> SSH Keys**.

#### 2. Install the Tool in Open WebUI

1. Place your private key (id_ed25519) inside the Open WebUI data volume (e.g., /app/backend/data/id_ed25519) with chmod 600.
2. Go to **Workspace -> Tools -> Create Tool** in Open WebUI and paste the contents of ai_sysadmin_tool.py.
3. Configure your server IPs and IMAP settings via the tool's **Valves** UI.
4. Create a custom model profile in **Workspace -> Models**, paste system_prompt.md into the System Prompt, enable the tool, and set **Function Calling** to Native.

#### License

MIT License — feel free to adapt, extend, and harden for your own homelab or infrastructure.

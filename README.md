# Wireshark MCP Server

> An MCP server that enables AI assistants to interact with Wireshark's
> command-line tools for automated network traffic capture and analysis.

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/Protocol-MCP-purple.svg)](https://modelcontextprotocol.io/)
[![Wireshark](https://img.shields.io/badge/Wireshark-tshark-blue.svg)](https://www.wireshark.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 📚 Documentation

### Lab Report

A detailed report covering the installation, configuration,
troubleshooting, and verification of the Wireshark MCP Server.

📄 [Read the MCP Wireshark Lab Report](docs/MCP_Wireshark_Lab_Report.pdf)

## Overview

Wireshark MCP Server connects AI assistants with Wireshark's command-line
analysis tools including `tshark`, `dumpcap`, `capinfos`, and `mergecap`.

The goal is to allow an AI assistant to perform network traffic analysis
through structured MCP tools instead of requiring the user to manually
execute multiple Wireshark commands.

## 🔄 How It Works

The Wireshark MCP Server acts as a bridge between an AI assistant and
Wireshark's command-line analysis tools.

```text
┌───────────────────────┐
│     AI Assistant      │
│   Claude Desktop      │
└───────────┬───────────┘
            │
            │ MCP / JSON-RPC
            ▼
┌───────────────────────┐
│  Wireshark MCP Server │
│        Python         │
└───────────┬───────────┘
            │
            ▼
┌────────────────────────────────────────┐
│       Wireshark CLI Tools              │
│                                        │
│ tshark │ dumpcap │ capinfos │ mergecap │
└───────────┬────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────┐
│       Network / PCAP / PCAPNG       │
│                                     │
│ Live Traffic     Capture Files      │
└───────────┬─────────────────────────┘
            │
            ▼
┌───────────────────────┐
│   Structured Results  │
│   Packet / Protocol   │
│   Endpoint / Stream   │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│     AI Analysis       │
│ Explanation / Summary │
│ Troubleshooting       │
└───────────────────────┘

---

## 🎯 Project Goals

The project aims to provide an AI-accessible interface for:

- Live packet capture
- PCAP analysis
- Display-filter validation
- Protocol hierarchy analysis
- Endpoint analysis
- Conversation analysis
- TCP/UDP stream following
- Packet inspection
- Capture metadata extraction
- Packet export
- Capture file merging

---

## 🧰 Technologies

| Technology | Purpose |
|---|---|
| Python | MCP server implementation |
| Model Context Protocol | AI ↔ tool communication |
| Wireshark | Packet analysis |
| tshark | CLI packet analyzer |
| dumpcap | Packet capture |
| capinfos | Capture metadata |
| mergecap | PCAP merging |
| Claude Desktop | MCP client |

---

## ✨ Features

### Capture

- List network interfaces
- Start live captures
- Stop captures
- Monitor active captures
- Perform short quick captures

### PCAP Analysis

- Read PCAP/PCAPNG files
- Inspect individual packets
- Analyze protocol hierarchy
- Analyze conversations
- Analyze endpoints
- Follow network streams

### Filtering

- Validate Wireshark display filters
- Apply filters to packet analysis
- Export filtered packets

### File Operations

- List generated capture files
- Merge multiple capture files
- Retrieve capture metadata

---

## 🔧 MCP Tools

| Tool | Description |
|---|---|
| `list_interfaces` | List available network interfaces |
| `get_interface_statistics` | Retrieve interface traffic statistics |
| `start_live_capture` | Start a background packet capture |
| `get_capture_status` | Check capture status |
| `list_active_captures` | List running captures |
| `stop_live_capture` | Stop an active capture |
| `quick_capture` | Perform a short packet capture |
| `read_pcap_file` | Read and analyze PCAP files |
| `get_packet_details` | Retrieve detailed packet information |
| `get_protocol_hierarchy` | Analyze protocol distribution |
| `get_conversations` | Analyze network conversations |
| `get_endpoints` | Analyze network endpoints |
| `follow_stream` | Follow TCP/UDP/HTTP/TLS streams |
| `get_capture_summary` | Retrieve capture metadata |
| `export_filtered_packets` | Export filtered packets |
| `merge_capture_files` | Merge capture files |
| `list_capture_files` | List generated captures |
| `validate_display_filter` | Validate Wireshark display filters |

---

## 💻 Installation

```

### 1. Clone the repository

```bash
git clone https://github.com/dhruvjaiswal-98/wireshark-mcp-server.git
cd wireshark-mcp-server

``` 
### 2.  Install Wireshark
```
Wireshark must be installed on the host system.
Verify:
tshark --version
dumpcap --version
capinfos --version
```

### 3. Install Python dependencies
```
pip install -r requirements.txt

```
### 4. Run the MCP server
python server.py
```

🤖 Claude Desktop Configuration
Add the MCP server to your Claude Desktop configuration.
Example:
{
  "mcpServers": {
    "wireshark": {
      "command": "python",
      "args": [
        "/absolute/path/to/server.py"
      ]
    }
  }
}
Restart Claude Desktop after changing the configuration.


```

### 5. Add a "How It Works" section

This is particularly important for **your cybersecurity portfolio**.

```markdown
## 🔄 How It Works

1. The user sends a network-analysis request to the AI assistant.
2. The AI assistant determines which MCP tool is required.
3. The MCP client sends a structured request to the Wireshark MCP server.
4. The MCP server validates the requested operation.
5. The server executes the appropriate Wireshark CLI utility.
6. Wireshark processes the packet capture or live traffic.
7. The MCP server converts the result into structured output.
8. The AI assistant interprets the result and provides an explanation.

```
### 🧪 Example Prompts
```
Once connected, you can ask:
Interface discovery
List my available network interfaces.

Packet capture
Capture traffic for 15 seconds and summarize the protocols observed.

DNS analysis
Analyze this PCAP and list all DNS queries.

HTTP analysis
Find HTTP traffic and summarize the hosts contacted.

TCP analysis
Show the top TCP conversations sorted by bytes.

Troubleshooting
Analyze this PCAP and identify unusual retransmissions or connection failures.

Security analysis
Analyze this capture for suspicious network behavior and explain your findings.

```
### 🔐 Security Considerations

```
This project executes Wireshark command-line utilities on the local system.
Because packet capture can expose sensitive information:
- Only capture traffic on systems/networks you are authorized to monitor.
- Avoid uploading sensitive PCAP files to third-party services.
- Be careful when following streams containing credentials or personal data.
- Restrict access to generated capture files.
- Do not use packet capture capabilities against systems without authorization.
This project is intended for:
- Security labs
- Network troubleshooting
- CTF environments
- Authorized security testing
- Educational purposes

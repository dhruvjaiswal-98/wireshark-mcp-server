#!/usr/bin/env python3
"""
Wireshark MCP Server
=====================

An MCP (Model Context Protocol) server that exposes Wireshark/tshark
functionality to Claude (or any MCP client).

It does NOT shell out to a GUI — everything is driven through the
`tshark`, `dumpcap`, and `capinfos` command-line utilities that ship
with Wireshark, so it works headlessly on servers/containers as well
as desktops.

Capabilities:
  - Enumerate network interfaces
  - Start / stop / monitor live packet captures (background processes)
  - Do a short, blocking "quick capture" and get parsed JSON packets back
  - Read and filter existing .pcap/.pcapng files
  - Get protocol hierarchy statistics
  - Get conversations / endpoints statistics
  - Inspect a single packet in full detail
  - Follow a TCP/UDP/HTTP stream
  - Get high-level capture file info (capinfos)
  - Export a filtered subset of a capture to a new file

Requirements:
  - Wireshark / tshark installed and on PATH (`tshark`, `dumpcap`, `capinfos`)
  - Python packages: mcp (`pip install mcp`)
  - Packet capture permissions:
      Linux : either run as root, or grant the capture group/capabilities:
              sudo usermod -a -G wireshark $USER
              sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)
      macOS : install ChmodBPF (comes with Wireshark installer)
      Windows: install/run with Npcap, run as Administrator if needed

Usage with Claude Desktop (claude_desktop_config.json):
{
  "mcpServers": {
    "wireshark": {
      "command": "python3",
      "args": ["/absolute/path/to/server.py"]
    }
  }
}
"""

import asyncio
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from mcp.server import MCPServer

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

TSHARK_BIN = shutil.which("tshark") or "tshark"
DUMPCAP_BIN = shutil.which("dumpcap") or "dumpcap"
CAPINFOS_BIN = shutil.which("capinfos") or "capinfos"
MERGECAP_BIN = shutil.which("mergecap") or "mergecap"

# Directory where captures started by this server are stored by default.
CAPTURE_DIR = os.environ.get("WIRESHARK_MCP_CAPTURE_DIR") or os.path.join(
    tempfile.gettempdir(), "wireshark_mcp_captures"
)
os.makedirs(CAPTURE_DIR, exist_ok=True)

# Safety caps so a "live capture" or "read pcap" call can't hang forever
# or dump gigabytes of JSON into the model's context window.
MAX_CAPTURE_DURATION_SECONDS = 3600
MAX_QUICK_CAPTURE_DURATION_SECONDS = 120
MAX_PACKETS_RETURNED = 500
DEFAULT_PACKETS_RETURNED = 100

mcp = MCPServer("wireshark")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _check_binary(path: str, name: str) -> Optional[str]:
    """Return an error string if the binary isn't available, else None."""
    if shutil.which(path) is None and not os.path.isfile(path):
        return (
            f"'{name}' was not found on PATH. Install Wireshark "
            f"(which bundles tshark/dumpcap/capinfos) and make sure it's "
            f"on your PATH, or set the {name.upper()}_BIN environment "
            f"appropriately."
        )
    return None


def _run(cmd: list[str], timeout: Optional[float] = None) -> dict[str, Any]:
    """Run a command synchronously and capture its output."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "returncode": -1,
            "stdout": e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or ""),
            "stderr": f"Command timed out after {timeout}s",
        }
    except FileNotFoundError:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": f"Binary not found: {cmd[0]}",
        }


def _safe_path_in_capture_dir(filename: str) -> str:
    """Resolve a filename to a path inside CAPTURE_DIR, preventing traversal."""
    base = os.path.basename(filename)
    return os.path.join(CAPTURE_DIR, base)


def _resolve_capture_file(path: str) -> str:
    """
    Allow callers to pass either a bare filename (assumed to live in
    CAPTURE_DIR) or a full/relative path to an arbitrary pcap file.
    """
    if os.path.isabs(path) or os.path.sep in path:
        return path
    candidate = _safe_path_in_capture_dir(path)
    if os.path.exists(candidate):
        return candidate
    return path


# --------------------------------------------------------------------------
# Background capture process tracking
# --------------------------------------------------------------------------

@dataclass
class CaptureJob:
    id: str
    interface: str
    filter: str
    output_file: str
    process: subprocess.Popen
    started_at: float
    duration: Optional[int] = None
    packet_count_limit: Optional[int] = None
    stopped: bool = False
    stopped_at: Optional[float] = None


_active_captures: dict[str, CaptureJob] = {}


def _capture_job_status(job: CaptureJob) -> dict[str, Any]:
    running = job.process.poll() is None and not job.stopped
    size = os.path.getsize(job.output_file) if os.path.exists(job.output_file) else 0
    return {
        "capture_id": job.id,
        "interface": job.interface,
        "filter": job.filter or None,
        "output_file": job.output_file,
        "running": running,
        "elapsed_seconds": round(time.time() - job.started_at, 1),
        "duration_limit_seconds": job.duration,
        "packet_count_limit": job.packet_count_limit,
        "capture_file_size_bytes": size,
    }


# --------------------------------------------------------------------------
# Tools: Interfaces
# --------------------------------------------------------------------------

@mcp.tool()
def list_interfaces() -> str:
    """
    List all network interfaces available for packet capture, as seen by
    tshark (equivalent to `tshark -D`). Use this first to find the
    interface name/number to pass to start_live_capture / quick_capture.
    """
    err = _check_binary(TSHARK_BIN, "tshark")
    if err:
        return json.dumps({"error": err})

    result = _run([TSHARK_BIN, "-D"])
    if result["returncode"] != 0:
        return json.dumps({"error": result["stderr"] or "Failed to list interfaces"})

    interfaces = []
    for line in result["stdout"].splitlines():
        line = line.strip()
        if not line:
            continue
        # Format: "1. eth0" or "3. \\Device\\NPF_{...} (Ethernet)"
        try:
            idx, rest = line.split(".", 1)
            interfaces.append({"index": idx.strip(), "name": rest.strip()})
        except ValueError:
            interfaces.append({"raw": line})

    return json.dumps({"interfaces": interfaces}, indent=2)


@mcp.tool()
def get_interface_statistics(duration_seconds: int = 3) -> str:
    """
    Capture brief per-interface traffic statistics (packet counts) over a
    short window, equivalent to `tshark -z io,phs` style interface stats
    (`tshark -D` + `dumpcap -D -S`). Useful for figuring out which
    interface actually has live traffic before starting a real capture.

    Args:
        duration_seconds: how many seconds to sample traffic counters for
            (capped at 15).
    """
    err = _check_binary(TSHARK_BIN, "tshark")
    if err:
        return json.dumps({"error": err})

    duration_seconds = max(1, min(duration_seconds, 15))
    result = _run([TSHARK_BIN, "-D"])
    if result["returncode"] != 0:
        return json.dumps({"error": result["stderr"]})

    stats = []
    for line in result["stdout"].splitlines():
        line = line.strip()
        if not line or "." not in line:
            continue
        idx, rest = line.split(".", 1)
        iface_name = rest.strip().split(" ")[0]
        count_result = _run(
            [TSHARK_BIN, "-i", iface_name, "-a", f"duration:{duration_seconds}", "-q", "-z", "io,stat,0"],
            timeout=duration_seconds + 10,
        )
        stats.append(
            {
                "interface": iface_name,
                "sample_output": count_result["stdout"].strip() or count_result["stderr"].strip(),
            }
        )
    return json.dumps({"duration_seconds": duration_seconds, "stats": stats}, indent=2)


# --------------------------------------------------------------------------
# Tools: Live capture (background, long-running)
# --------------------------------------------------------------------------

@mcp.tool()
def start_live_capture(
    interface: str,
    capture_filter: str = "",
    duration_seconds: Optional[int] = 60,
    packet_count: Optional[int] = None,
    output_filename: Optional[str] = None,
) -> str:
    """
    Start a live packet capture in the background using dumpcap/tshark.
    Returns immediately with a capture_id you can poll with
    get_capture_status, and read once finished with read_pcap_file /
    get_capture_summary / stop_live_capture.

    Args:
        interface: interface name or index (from list_interfaces), e.g. "eth0" or "1".
        capture_filter: a BPF capture filter, e.g. "tcp port 443" or "host 10.0.0.5".
            This is applied at capture time (like Wireshark's "Capture Filter" field).
        duration_seconds: auto-stop after this many seconds (max 3600). Set to
            None together with packet_count if you want count-based stopping only.
        packet_count: auto-stop after this many packets are captured.
        output_filename: optional filename (no path) for the .pcapng file;
            a name is generated if omitted. Stored under the server's capture dir.

    Returns:
        JSON with capture_id, output_file path, and initial status.
    """
    err = _check_binary(DUMPCAP_BIN, "dumpcap") or _check_binary(TSHARK_BIN, "tshark")
    if err:
        return json.dumps({"error": err})

    if duration_seconds is not None:
        duration_seconds = max(1, min(duration_seconds, MAX_CAPTURE_DURATION_SECONDS))

    capture_id = uuid.uuid4().hex[:12]
    filename = output_filename or f"capture_{capture_id}.pcapng"
    output_file = _safe_path_in_capture_dir(filename)

    # Prefer dumpcap (lower overhead, designed for capture); fall back to tshark.
    use_dumpcap = shutil.which(DUMPCAP_BIN) is not None

    cmd: list[str]
    if use_dumpcap:
        cmd = [DUMPCAP_BIN, "-i", interface, "-w", output_file]
        if capture_filter:
            cmd += ["-f", capture_filter]
        if duration_seconds:
            cmd += ["-a", f"duration:{duration_seconds}"]
        if packet_count:
            cmd += ["-c", str(packet_count)]
    else:
        cmd = [TSHARK_BIN, "-i", interface, "-w", output_file]
        if capture_filter:
            cmd += ["-f", capture_filter]
        if duration_seconds:
            cmd += ["-a", f"duration:{duration_seconds}"]
        if packet_count:
            cmd += ["-c", str(packet_count)]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        return json.dumps({"error": f"Could not launch capture binary: {cmd[0]}"})

    # Give it a beat to fail fast on bad interface/permission errors.
    time.sleep(0.5)
    if proc.poll() is not None and proc.returncode != 0:
        _, stderr = proc.communicate()
        return json.dumps(
            {
                "error": "Capture process exited immediately — check interface name and permissions.",
                "details": stderr.strip(),
            }
        )

    job = CaptureJob(
        id=capture_id,
        interface=interface,
        filter=capture_filter,
        output_file=output_file,
        process=proc,
        started_at=time.time(),
        duration=duration_seconds,
        packet_count_limit=packet_count,
    )
    _active_captures[capture_id] = job

    return json.dumps({"started": True, "status": _capture_job_status(job)}, indent=2)


@mcp.tool()
def get_capture_status(capture_id: str) -> str:
    """
    Check the status of a background capture started with start_live_capture
    (running/stopped, elapsed time, current file size).
    """
    job = _active_captures.get(capture_id)
    if not job:
        return json.dumps({"error": f"No active or known capture with id '{capture_id}'"})
    return json.dumps(_capture_job_status(job), indent=2)


@mcp.tool()
def list_active_captures() -> str:
    """List all background captures started this session, with their status."""
    return json.dumps(
        {"captures": [_capture_job_status(j) for j in _active_captures.values()]}, indent=2
    )


@mcp.tool()
def stop_live_capture(capture_id: str) -> str:
    """
    Stop a running background capture started with start_live_capture.
    The partially/fully captured .pcapng file remains on disk and can be
    analyzed with read_pcap_file, get_protocol_hierarchy, etc.
    """
    job = _active_captures.get(capture_id)
    if not job:
        return json.dumps({"error": f"No active or known capture with id '{capture_id}'"})

    if job.process.poll() is None:
        try:
            job.process.send_signal(signal.SIGTERM)
            job.process.wait(timeout=5)
        except Exception:
            job.process.kill()
    job.stopped = True
    job.stopped_at = time.time()

    return json.dumps({"stopped": True, "status": _capture_job_status(job)}, indent=2)


@mcp.tool()
def quick_capture(
    interface: str,
    duration_seconds: int = 10,
    capture_filter: str = "",
    display_filter: str = "",
    max_packets: int = DEFAULT_PACKETS_RETURNED,
) -> str:
    """
    Do a short BLOCKING live capture and return parsed packets as JSON
    directly in the response (no need to poll status or read a file
    afterward). Best for quick "what's happening on the wire right now"
    questions. For anything longer than ~2 minutes, use start_live_capture
    instead.

    Args:
        interface: interface name or index (from list_interfaces).
        duration_seconds: how long to capture (max 120).
        capture_filter: BPF capture filter (applied while capturing), e.g. "tcp port 80".
        display_filter: Wireshark display filter (applied while parsing
            output), e.g. "http.request or dns".
        max_packets: cap on number of packets returned (max 500).
    """
    err = _check_binary(TSHARK_BIN, "tshark")
    if err:
        return json.dumps({"error": err})

    duration_seconds = max(1, min(duration_seconds, MAX_QUICK_CAPTURE_DURATION_SECONDS))
    max_packets = max(1, min(max_packets, MAX_PACKETS_RETURNED))

    cmd = [TSHARK_BIN, "-i", interface, "-a", f"duration:{duration_seconds}", "-T", "json"]
    if capture_filter:
        cmd += ["-f", capture_filter]
    if display_filter:
        cmd += ["-Y", display_filter]

    result = _run(cmd, timeout=duration_seconds + 15)
    if result["returncode"] not in (0, None) and not result["stdout"].strip():
        return json.dumps({"error": result["stderr"] or "Capture failed", "returncode": result["returncode"]})

    try:
        packets = json.loads(result["stdout"]) if result["stdout"].strip() else []
    except json.JSONDecodeError:
        return json.dumps({"error": "Failed to parse tshark JSON output", "raw_stderr": result["stderr"]})

    truncated = len(packets) > max_packets
    packets = packets[:max_packets]
    simplified = [_simplify_packet(p) for p in packets]

    return json.dumps(
        {
            "interface": interface,
            "duration_seconds": duration_seconds,
            "capture_filter": capture_filter or None,
            "display_filter": display_filter or None,
            "packet_count": len(simplified),
            "truncated": truncated,
            "packets": simplified,
        },
        indent=2,
    )


# --------------------------------------------------------------------------
# Tools: Reading / analyzing existing capture files
# --------------------------------------------------------------------------

def _simplify_packet(packet_json: dict) -> dict:
    """Flatten tshark's verbose per-packet JSON into a compact summary."""
    try:
        layers = packet_json["_source"]["layers"]
    except (KeyError, TypeError):
        return {"raw": packet_json}

    frame = layers.get("frame", {})
    ip = layers.get("ip", layers.get("ipv6", {}))
    tcp = layers.get("tcp", {})
    udp = layers.get("udp", {})

    summary = {
        "number": frame.get("frame.number"),
        "time": frame.get("frame.time"),
        "length": frame.get("frame.len"),
        "protocols": frame.get("frame.protocols"),
        "src_ip": ip.get("ip.src") or ip.get("ipv6.src"),
        "dst_ip": ip.get("ip.dst") or ip.get("ipv6.dst"),
    }
    if tcp:
        summary["transport"] = "tcp"
        summary["src_port"] = tcp.get("tcp.srcport")
        summary["dst_port"] = tcp.get("tcp.dstport")
        summary["tcp_flags"] = tcp.get("tcp.flags.str")
    elif udp:
        summary["transport"] = "udp"
        summary["src_port"] = udp.get("udp.srcport")
        summary["dst_port"] = udp.get("udp.dstport")

    for proto_key, label in (("http", "http"), ("dns", "dns"), ("tls", "tls")):
        if proto_key in layers:
            summary[label] = layers[proto_key]

    return summary


@mcp.tool()
def read_pcap_file(
    file_path: str,
    display_filter: str = "",
    max_packets: int = DEFAULT_PACKETS_RETURNED,
    start_packet: int = 1,
) -> str:
    """
    Read and parse an existing capture file (.pcap/.pcapng), optionally
    applying a Wireshark display filter. Returns simplified per-packet
    summaries (time, addresses, ports, protocol stack). For full detail
    on one packet use get_packet_details.

    Args:
        file_path: path to the capture file, or a bare filename previously
            produced by this server (start_live_capture / quick_capture output).
        display_filter: Wireshark display filter syntax, e.g. "tcp.port == 443",
            "http", "ip.addr == 10.0.0.5 && dns".
        max_packets: max number of packets to return (max 500).
        start_packet: 1-based packet index to start returning from (for paging
            through large captures).
    """
    err = _check_binary(TSHARK_BIN, "tshark")
    if err:
        return json.dumps({"error": err})

    resolved = _resolve_capture_file(file_path)
    if not os.path.exists(resolved):
        return json.dumps({"error": f"File not found: {resolved}"})

    max_packets = max(1, min(max_packets, MAX_PACKETS_RETURNED))

    cmd = [TSHARK_BIN, "-r", resolved, "-T", "json"]
    if display_filter:
        cmd += ["-Y", display_filter]

    result = _run(cmd, timeout=120)
    if result["returncode"] not in (0, None):
        return json.dumps({"error": result["stderr"] or "Failed to read capture file"})

    try:
        packets = json.loads(result["stdout"]) if result["stdout"].strip() else []
    except json.JSONDecodeError:
        return json.dumps({"error": "Failed to parse tshark JSON output"})

    total = len(packets)
    start_idx = max(0, start_packet - 1)
    page = packets[start_idx : start_idx + max_packets]
    simplified = [_simplify_packet(p) for p in page]

    return json.dumps(
        {
            "file": resolved,
            "display_filter": display_filter or None,
            "total_matching_packets": total,
            "returned_count": len(simplified),
            "start_packet": start_packet,
            "packets": simplified,
        },
        indent=2,
    )


@mcp.tool()
def get_packet_details(file_path: str, packet_number: int, display_filter: str = "") -> str:
    """
    Get the FULL decoded detail (every protocol layer and field, like
    Wireshark's packet detail pane) for one specific packet in a capture
    file.

    Args:
        file_path: path or bare filename of the capture file.
        packet_number: the frame number as shown in Wireshark / read_pcap_file
            (1-based).
        display_filter: optional display filter narrowing which packets are
            indexed before picking packet_number (leave blank to use raw frame numbers).
    """
    err = _check_binary(TSHARK_BIN, "tshark")
    if err:
        return json.dumps({"error": err})

    resolved = _resolve_capture_file(file_path)
    if not os.path.exists(resolved):
        return json.dumps({"error": f"File not found: {resolved}"})

    combined_filter = f"frame.number == {packet_number}"
    if display_filter:
        combined_filter = f"({display_filter}) && {combined_filter}"

    cmd = [TSHARK_BIN, "-r", resolved, "-Y", combined_filter, "-T", "json", "-x"]
    result = _run(cmd, timeout=60)
    if result["returncode"] not in (0, None):
        return json.dumps({"error": result["stderr"] or "Failed to read packet"})

    try:
        packets = json.loads(result["stdout"]) if result["stdout"].strip() else []
    except json.JSONDecodeError:
        return json.dumps({"error": "Failed to parse tshark JSON output"})

    if not packets:
        return json.dumps({"error": f"Packet {packet_number} not found (with given filter)"})

    return json.dumps({"file": resolved, "packet": packets[0]}, indent=2)


@mcp.tool()
def get_protocol_hierarchy(file_path: str) -> str:
    """
    Get protocol hierarchy statistics for a capture file — the same as
    Wireshark's Statistics > Protocol Hierarchy. Shows what percentage of
    traffic is TCP/UDP/HTTP/DNS/TLS/etc and packet/byte counts per protocol.
    """
    err = _check_binary(TSHARK_BIN, "tshark")
    if err:
        return json.dumps({"error": err})

    resolved = _resolve_capture_file(file_path)
    if not os.path.exists(resolved):
        return json.dumps({"error": f"File not found: {resolved}"})

    result = _run([TSHARK_BIN, "-r", resolved, "-q", "-z", "io,phs"], timeout=120)
    if result["returncode"] not in (0, None):
        return json.dumps({"error": result["stderr"] or "Failed to compute protocol hierarchy"})

    return json.dumps({"file": resolved, "protocol_hierarchy": result["stdout"]}, indent=2)


@mcp.tool()
def get_conversations(file_path: str, protocol: str = "tcp") -> str:
    """
    Get conversation statistics (who talked to whom) for a capture file —
    equivalent to Wireshark's Statistics > Conversations.

    Args:
        file_path: path or bare filename of the capture file.
        protocol: one of "eth", "ip", "tcp", "udp" (which conversation table to compute).
    """
    err = _check_binary(TSHARK_BIN, "tshark")
    if err:
        return json.dumps({"error": err})

    resolved = _resolve_capture_file(file_path)
    if not os.path.exists(resolved):
        return json.dumps({"error": f"File not found: {resolved}"})

    protocol = protocol.lower().strip()
    if protocol not in {"eth", "ip", "tcp", "udp"}:
        return json.dumps({"error": "protocol must be one of: eth, ip, tcp, udp"})

    result = _run([TSHARK_BIN, "-r", resolved, "-q", "-z", f"conv,{protocol}"], timeout=120)
    if result["returncode"] not in (0, None):
        return json.dumps({"error": result["stderr"] or "Failed to compute conversations"})

    return json.dumps({"file": resolved, "protocol": protocol, "conversations": result["stdout"]}, indent=2)


@mcp.tool()
def get_endpoints(file_path: str, protocol: str = "ip") -> str:
    """
    Get endpoint statistics (traffic totals per address) for a capture
    file — equivalent to Wireshark's Statistics > Endpoints.

    Args:
        file_path: path or bare filename of the capture file.
        protocol: one of "eth", "ip", "tcp", "udp".
    """
    err = _check_binary(TSHARK_BIN, "tshark")
    if err:
        return json.dumps({"error": err})

    resolved = _resolve_capture_file(file_path)
    if not os.path.exists(resolved):
        return json.dumps({"error": f"File not found: {resolved}"})

    protocol = protocol.lower().strip()
    if protocol not in {"eth", "ip", "tcp", "udp"}:
        return json.dumps({"error": "protocol must be one of: eth, ip, tcp, udp"})

    result = _run([TSHARK_BIN, "-r", resolved, "-q", "-z", f"endpoints,{protocol}"], timeout=120)
    if result["returncode"] not in (0, None):
        return json.dumps({"error": result["stderr"] or "Failed to compute endpoints"})

    return json.dumps({"file": resolved, "protocol": protocol, "endpoints": result["stdout"]}, indent=2)


@mcp.tool()
def follow_stream(file_path: str, protocol: str, stream_index: int) -> str:
    """
    Follow a TCP/UDP/HTTP/TLS stream and return its reassembled payload as
    text — equivalent to Wireshark's "Follow > TCP/UDP/HTTP Stream".

    Args:
        file_path: path or bare filename of the capture file.
        protocol: one of "tcp", "udp", "http", "tls".
        stream_index: the stream number (found via tcp.stream / udp.stream
            fields in read_pcap_file / get_packet_details output).
    """
    err = _check_binary(TSHARK_BIN, "tshark")
    if err:
        return json.dumps({"error": err})

    resolved = _resolve_capture_file(file_path)
    if not os.path.exists(resolved):
        return json.dumps({"error": f"File not found: {resolved}"})

    protocol = protocol.lower().strip()
    if protocol not in {"tcp", "udp", "http", "tls"}:
        return json.dumps({"error": "protocol must be one of: tcp, udp, http, tls"})

    result = _run(
        [TSHARK_BIN, "-r", resolved, "-q", "-z", f"follow,{protocol},ascii,{stream_index}"],
        timeout=60,
    )
    if result["returncode"] not in (0, None):
        return json.dumps({"error": result["stderr"] or "Failed to follow stream"})

    return json.dumps(
        {"file": resolved, "protocol": protocol, "stream_index": stream_index, "stream_data": result["stdout"]},
        indent=2,
    )


@mcp.tool()
def get_capture_summary(file_path: str) -> str:
    """
    Get high-level metadata about a capture file (duration, packet count,
    total bytes, average packet rate, capture start/end time, link type)
    — equivalent to `capinfos`.
    """
    err = _check_binary(CAPINFOS_BIN, "capinfos")
    if err:
        return json.dumps({"error": err})

    resolved = _resolve_capture_file(file_path)
    if not os.path.exists(resolved):
        return json.dumps({"error": f"File not found: {resolved}"})

    result = _run([CAPINFOS_BIN, resolved], timeout=60)
    if result["returncode"] not in (0, None):
        return json.dumps({"error": result["stderr"] or "capinfos failed"})

    return json.dumps({"file": resolved, "summary": result["stdout"]}, indent=2)


@mcp.tool()
def export_filtered_packets(file_path: str, display_filter: str, output_filename: str) -> str:
    """
    Export only the packets matching a display filter from an existing
    capture into a new, smaller .pcapng file — equivalent to Wireshark's
    File > Export Specified Packets with a display filter applied.

    Args:
        file_path: source capture file (path or bare filename).
        display_filter: Wireshark display filter, e.g. "dns || tls.handshake".
        output_filename: filename (no path) for the resulting file, stored
            in the server's capture directory.
    """
    err = _check_binary(TSHARK_BIN, "tshark")
    if err:
        return json.dumps({"error": err})

    resolved = _resolve_capture_file(file_path)
    if not os.path.exists(resolved):
        return json.dumps({"error": f"File not found: {resolved}"})

    out_path = _safe_path_in_capture_dir(output_filename)
    result = _run(
        [TSHARK_BIN, "-r", resolved, "-Y", display_filter, "-w", out_path],
        timeout=180,
    )
    if result["returncode"] not in (0, None):
        return json.dumps({"error": result["stderr"] or "Export failed"})

    if not os.path.exists(out_path):
        return json.dumps({"error": "Export produced no output file"})

    return json.dumps(
        {"exported": True, "output_file": out_path, "size_bytes": os.path.getsize(out_path)}, indent=2
    )


@mcp.tool()
def merge_capture_files(file_paths: list[str], output_filename: str) -> str:
    """
    Merge multiple capture files (in chronological order by packet
    timestamp) into a single .pcapng file, equivalent to `mergecap`.

    Args:
        file_paths: list of paths/bare filenames to merge.
        output_filename: filename (no path) for the merged output file.
    """
    err = _check_binary(MERGECAP_BIN, "mergecap")
    if err:
        return json.dumps({"error": err})

    resolved_paths = [_resolve_capture_file(p) for p in file_paths]
    missing = [p for p in resolved_paths if not os.path.exists(p)]
    if missing:
        return json.dumps({"error": f"File(s) not found: {missing}"})

    out_path = _safe_path_in_capture_dir(output_filename)
    result = _run([MERGECAP_BIN, "-w", out_path] + resolved_paths, timeout=180)
    if result["returncode"] not in (0, None):
        return json.dumps({"error": result["stderr"] or "Merge failed"})

    return json.dumps(
        {"merged": True, "output_file": out_path, "size_bytes": os.path.getsize(out_path)}, indent=2
    )


@mcp.tool()
def list_capture_files() -> str:
    """
    List all capture files currently stored in this server's capture
    directory (from prior start_live_capture / quick_capture / export /
    merge operations), with size and modified time.
    """
    files = []
    for name in sorted(os.listdir(CAPTURE_DIR)):
        full = os.path.join(CAPTURE_DIR, name)
        if os.path.isfile(full):
            files.append(
                {
                    "filename": name,
                    "path": full,
                    "size_bytes": os.path.getsize(full),
                    "modified": time.ctime(os.path.getmtime(full)),
                }
            )
    return json.dumps({"capture_dir": CAPTURE_DIR, "files": files}, indent=2)


@mcp.tool()
def validate_display_filter(display_filter: str) -> str:
    """
    Validate a Wireshark display filter's syntax without capturing or
    reading any data — equivalent to the green/red validity check in
    Wireshark's filter bar. Useful to sanity-check a filter before using
    it in read_pcap_file / quick_capture / export_filtered_packets.
    """
    err = _check_binary(TSHARK_BIN, "tshark")
    if err:
        return json.dumps({"error": err})

    result = _run([TSHARK_BIN, "-Y", display_filter, "-r", os.devnull], timeout=15)
    # tshark will complain about the empty/invalid "file" (/dev/null isn't a
    # capture) but will complain differently (and immediately) if the
    # *filter* itself is malformed. We check stderr for filter-specific errors.
    stderr = result["stderr"] or ""
    if "Filter" in stderr and ("syntax" in stderr.lower() or "not a valid" in stderr.lower()):
        return json.dumps({"valid": False, "error": stderr.strip()})

    return json.dumps({"valid": True})


# --------------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()  # defaults to stdio transport, which Claude Desktop uses

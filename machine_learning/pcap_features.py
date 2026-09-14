from collections import defaultdict
from statistics import mean

from scapy.all import IP, TCP, UDP, rdpcap


def extract_flows(pcap_path):
    """
    Extract bidirectional TCP/UDP network flows from a PCAP.

    The first packet establishes the original flow direction:
    source -> destination.
    """

    packets = rdpcap(pcap_path)

    flows = defaultdict(
        lambda: {
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "protocol": None,
            "first_seen": None,
            "last_seen": None,
            "forward_packets": [],
            "reverse_packets": [],
        }
    )

    for packet in packets:
        if IP not in packet:
            continue

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            protocol = "tcp"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "udp"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        else:
            continue

        endpoint_a = (src_ip, src_port)
        endpoint_b = (dst_ip, dst_port)

        if endpoint_a <= endpoint_b:
            flow_key = (
                endpoint_a,
                endpoint_b,
                protocol
            )
        else:
            flow_key = (
                endpoint_b,
                endpoint_a,
                protocol
            )

        timestamp = float(packet.time)
        packet_length = len(packet)

        packet_info = {
            "timestamp": timestamp,
            "length": packet_length,
            "ttl": packet[IP].ttl,
            "window": packet[TCP].window
            if TCP in packet else 0,
            "seq": packet[TCP].seq
            if TCP in packet else 0,
            "flags": str(packet[TCP].flags)
            if TCP in packet else "",
        }

        flow = flows[flow_key]

        if flow["first_seen"] is None:
            flow["src_ip"] = src_ip
            flow["dst_ip"] = dst_ip
            flow["src_port"] = src_port
            flow["dst_port"] = dst_port
            flow["protocol"] = protocol
            flow["first_seen"] = timestamp

            flow["forward_packets"].append(packet_info)

        else:
            if (
                src_ip == flow["src_ip"]
                and dst_ip == flow["dst_ip"]
                and src_port == flow["src_port"]
                and dst_port == flow["dst_port"]
            ):
                flow["forward_packets"].append(packet_info)

            else:
                flow["reverse_packets"].append(packet_info)

        flow["last_seen"] = timestamp

    return flows


def calculate_intervals(packets):
    """
    Calculate time intervals between consecutive packets.
    """

    if len(packets) < 2:
        return []

    timestamps = [
        packet["timestamp"]
        for packet in packets
    ]

    return [
        timestamps[i] - timestamps[i - 1]
        for i in range(1, len(timestamps))
    ]


def calculate_jitter(intervals):
    """
    Calculate standard deviation of packet intervals.
    """

    if len(intervals) < 2:
        return 0.0

    average = mean(intervals)

    variance = sum(
        (interval - average) ** 2
        for interval in intervals
    ) / len(intervals)

    return variance ** 0.5


def calculate_tcp_features(forward, reverse):
    """
    Calculate TCP handshake timing features.

    Returns:
        tcprtt
        synack
        ackdat
    """

    if not forward or not reverse:
        return 0.0, 0.0, 0.0

    syn_time = None
    synack_time = None
    ack_time = None

    for packet in forward:
        flags = packet["flags"]

        if "S" in flags and "A" not in flags:
            syn_time = packet["timestamp"]
            break

    if syn_time is not None:
        for packet in reverse:
            flags = packet["flags"]

            if "S" in flags and "A" in flags:
                synack_time = packet["timestamp"]
                break

    if synack_time is not None:
        for packet in forward:
            flags = packet["flags"]

            if "A" in flags and "S" not in flags:
                if packet["timestamp"] >= synack_time:
                    ack_time = packet["timestamp"]
                    break

    if syn_time is None or synack_time is None:
        return 0.0, 0.0, 0.0

    synack = synack_time - syn_time
    tcprtt = synack

    if ack_time is not None:
        ackdat = ack_time - synack_time
    else:
        ackdat = 0.0

    return tcprtt, synack, ackdat


def calculate_connection_counts(results):
    """
    Calculate connection-count features across all flows.

    These are practical PCAP-derived approximations of the
    corresponding UNSW-NB15 count features.
    """

    for flow in results:

        src_ip = flow["src_ip"]
        dst_ip = flow["dst_ip"]
        dst_port = flow["dst_port"]
        src_port = flow["src_port"]
        protocol = flow["protocol"]
        sttl = flow["sttl"]

        flow["ct_srv_src"] = sum(
            1
            for other in results
            if (
                other["src_ip"] == src_ip
                and other["dst_port"] == dst_port
                and other["protocol"] == protocol
            )
        )

        flow["ct_state_ttl"] = sum(
            1
            for other in results
            if (
                other["protocol"] == protocol
                and other["sttl"] == sttl
            )
        )

        flow["ct_dst_ltm"] = sum(
            1
            for other in results
            if other["dst_ip"] == dst_ip
        )

        flow["ct_src_dport_ltm"] = sum(
            1
            for other in results
            if (
                other["src_ip"] == src_ip
                and other["dst_port"] == dst_port
            )
        )

        flow["ct_dst_sport_ltm"] = sum(
            1
            for other in results
            if (
                other["dst_ip"] == dst_ip
                and other["src_port"] == src_port
            )
        )

        flow["ct_dst_src_ltm"] = sum(
            1
            for other in results
            if (
                other["src_ip"] == src_ip
                and other["dst_ip"] == dst_ip
            )
        )


def summarize_flows(flows):
    """
    Convert extracted flows into ML-friendly flow summaries.
    """

    results = []

    for flow in flows.values():

        forward = flow["forward_packets"]
        reverse = flow["reverse_packets"]

        all_packets = forward + reverse
        all_packets.sort(
            key=lambda packet: packet["timestamp"]
        )

        duration = (
            flow["last_seen"] - flow["first_seen"]
        )

        src_packets = len(forward)
        dst_packets = len(reverse)

        src_bytes = sum(
            packet["length"]
            for packet in forward
        )

        dst_bytes = sum(
            packet["length"]
            for packet in reverse
        )

        total_packets = (
            src_packets + dst_packets
        )

        total_bytes = (
            src_bytes + dst_bytes
        )

        if duration > 0:
            packet_rate = total_packets / duration
            byte_rate = total_bytes / duration

            rate = total_packets / duration
            sload = (src_bytes * 8) / duration
            dload = (dst_bytes * 8) / duration

        else:
            packet_rate = 0.0
            byte_rate = 0.0

            rate = 0.0
            sload = 0.0
            dload = 0.0

        packet_sizes = [
            packet["length"]
            for packet in all_packets
        ]

        if packet_sizes:
            average_packet_size = (
                sum(packet_sizes)
                / len(packet_sizes)
            )
        else:
            average_packet_size = 0.0

        intervals = calculate_intervals(
            all_packets
        )

        if intervals:
            average_interval = (
                sum(intervals)
                / len(intervals)
            )
        else:
            average_interval = 0.0

        source_intervals = calculate_intervals(
            forward
        )

        destination_intervals = calculate_intervals(
            reverse
        )

        if source_intervals:
            sinpkt = (
                sum(source_intervals)
                / len(source_intervals)
            )
        else:
            sinpkt = 0.0

        if destination_intervals:
            dinpkt = (
                sum(destination_intervals)
                / len(destination_intervals)
            )
        else:
            dinpkt = 0.0

        sjit = calculate_jitter(
            source_intervals
        )

        djit = calculate_jitter(
            destination_intervals
        )

        # --------------------------------------------------
        # UNSW-NB15 TTL / TCP features
        # --------------------------------------------------

        sttl = (
            forward[0]["ttl"]
            if forward else 0
        )

        dttl = (
            reverse[0]["ttl"]
            if reverse else 0
        )

        swin = (
            forward[0]["window"]
            if forward else 0
        )

        dwin = (
            reverse[0]["window"]
            if reverse else 0
        )

        if forward and flow["protocol"] == "tcp":
            stcpb = forward[0]["seq"]
        else:
            stcpb = 0

        if reverse and flow["protocol"] == "tcp":
            dtcpb = reverse[0]["seq"]
        else:
            dtcpb = 0

        # --------------------------------------------------
        # UNSW-NB15 TCP handshake features
        # --------------------------------------------------

        if flow["protocol"] == "tcp":
            tcprtt, synack, ackdat = calculate_tcp_features(
                forward,
                reverse
            )
        else:
            tcprtt = 0.0
            synack = 0.0
            ackdat = 0.0

        results.append({
            "src_ip": flow["src_ip"],
            "dst_ip": flow["dst_ip"],
            "src_port": flow["src_port"],
            "dst_port": flow["dst_port"],
            "protocol": flow["protocol"],

            "duration": duration,

            "src_packets": src_packets,
            "dst_packets": dst_packets,

            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,

            "total_packets": total_packets,
            "total_bytes": total_bytes,

            "packet_rate": packet_rate,
            "byte_rate": byte_rate,

            "rate": rate,
            "sload": sload,
            "dload": dload,

            "average_packet_size": average_packet_size,
            "average_interval": average_interval,

            "sinpkt": sinpkt,
            "dinpkt": dinpkt,

            "sjit": sjit,
            "djit": djit,

            "sttl": sttl,
            "dttl": dttl,

            "swin": swin,
            "dwin": dwin,

            "stcpb": stcpb,
            "dtcpb": dtcpb,

            "tcprtt": tcprtt,
            "synack": synack,
            "ackdat": ackdat,
        })

    calculate_connection_counts(results)

    return results

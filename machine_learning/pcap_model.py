import pandas as pd


PCAP_FEATURES = [
    "duration",
    "src_packets",
    "dst_packets",
    "src_bytes",
    "dst_bytes",
    "rate",
    "sload",
    "dload",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
    "sttl",
    "dttl",
    "swin",
    "dwin",
    "stcpb",
    "dtcpb",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
]


def flows_to_dataframe(flows):
    """
    Convert summarized PCAP flows into a DataFrame
    containing only features suitable for the PCAP ML model.
    """

    dataframe = pd.DataFrame(flows)

    if dataframe.empty:
        return pd.DataFrame(columns=PCAP_FEATURES)

    missing_features = [
        feature
        for feature in PCAP_FEATURES
        if feature not in dataframe.columns
    ]

    if missing_features:
        raise ValueError(
            "Missing PCAP features: "
            + ", ".join(missing_features)
        )

    return dataframe[PCAP_FEATURES].copy()


def validate_pcap_features(dataframe):
    """
    Validate that a DataFrame contains all required
    PCAP model features.
    """

    missing_features = [
        feature
        for feature in PCAP_FEATURES
        if feature not in dataframe.columns
    ]

    return missing_features

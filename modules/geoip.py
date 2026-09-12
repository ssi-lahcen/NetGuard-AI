"""
==================================================
NetGuard-AI
GeoIP Enrichment Module
==================================================

Maps IP addresses to geographic information
using a local CSV database.

Author:
    Lahcen Elkadi
"""

import ipaddress

from functools import lru_cache

import pandas as pd

from config import DATA_DIR


# ==================================================
# Configuration
# ==================================================

GEOIP_DATABASE = DATA_DIR / "countries.csv"


# ==================================================
# Load GeoIP Database
# ==================================================

@lru_cache(maxsize=1)
def load_geoip_database() -> pd.DataFrame:
    """
    Load the local GeoIP database once and cache it.
    """

    if not GEOIP_DATABASE.exists():

        raise FileNotFoundError(
            f"GeoIP database not found: {GEOIP_DATABASE}"
        )

    dataframe = pd.read_csv(
        GEOIP_DATABASE
    )

    required_columns = [
        "ip",
        "country",
        "city"
    ]

    for column in required_columns:

        if column not in dataframe.columns:

            raise ValueError(
                f"Missing required column: {column}"
            )

    # --------------------------------------------------
    # Check for duplicate IP addresses
    # --------------------------------------------------

    if dataframe["ip"].duplicated().any():

        duplicates = dataframe[
            dataframe["ip"].duplicated(
                keep=False
            )
        ]

        raise ValueError(
            "Duplicate IP addresses found in GeoIP database:\n"
            f"{duplicates}"
        )

    return dataframe


# ==================================================
# Build GeoIP Lookup
# ==================================================

def build_geoip_lookup(
    dataframe: pd.DataFrame
) -> dict:
    """
    Build a fast IP → geographic information lookup.
    """

    return (
        dataframe
        .set_index("ip")[["country", "city"]]
        .to_dict("index")
    )


# ==================================================
# IP Classification
# ==================================================

def classify_ip(
    ip_address: str
) -> str:
    """
    Classify an IP address.
    """

    if not ip_address:

        return "Invalid"

    ip_address = str(
        ip_address
    ).strip()

    if not ip_address:

        return "Invalid"

    try:

        ip = ipaddress.ip_address(
            ip_address
        )

    except ValueError:

        return "Invalid"

    if ip.is_private:

        return "Private"

    if ip.is_loopback:

        return "Loopback"

    if ip.is_link_local:

        return "Link-Local"

    if ip.is_multicast:

        return "Multicast"

    if ip.is_unspecified:

        return "Unspecified"

    return "Public"


# ==================================================
# IP Lookup
# ==================================================

def lookup_ip(
    ip_address: str,
    lookup: dict
) -> dict:
    """
    Look up geographic information using
    the IP lookup dictionary.
    """

    if not ip_address:

        return {
            "ip": ip_address,
            "country": "Invalid",
            "city": "Invalid"
        }

    ip_address = str(
        ip_address
    ).strip()

    ip_type = classify_ip(
        ip_address
    )

    # --------------------------------------------------
    # Invalid IP address
    # --------------------------------------------------

    if ip_type == "Invalid":

        return {
            "ip": ip_address,
            "country": "Invalid",
            "city": "Invalid"
        }

    # --------------------------------------------------
    # Database lookup
    # --------------------------------------------------

    result = lookup.get(
        ip_address
    )

    # --------------------------------------------------
    # IP not present in database
    # --------------------------------------------------

    if result is None:

        if ip_type == "Private":

            return {
                "ip": ip_address,
                "country": "Private",
                "city": "Local Network"
            }

        return {
            "ip": ip_address,
            "country": "Unknown",
            "city": "Unknown"
        }

    # --------------------------------------------------
    # Return geographic information
    # --------------------------------------------------

    return {
        "ip": ip_address,
        "country": result["country"],
        "city": result["city"]
    }


# ==================================================
# Enrich Single IP
# ==================================================

def enrich_ip(
    ip_address: str
) -> dict:
    """
    Enrich an IP address using the local GeoIP database.
    """

    database = load_geoip_database()

    lookup = build_geoip_lookup(
        database
    )

    return lookup_ip(
        ip_address,
        lookup
    )


# ==================================================
# Enrich Network DataFrame
# ==================================================

def enrich_dataframe(
    dataframe: pd.DataFrame
) -> pd.DataFrame:
    """
    Add geographic information for source and
    destination IP addresses.
    """

    dataframe = dataframe.copy()

    # --------------------------------------------------
    # Load database and build lookup
    # --------------------------------------------------

    geoip_database = load_geoip_database()

    geoip_lookup = build_geoip_lookup(
        geoip_database
    )

    source_geoip = {}
    destination_geoip = {}

    # --------------------------------------------------
    # Lookup source IP addresses
    # --------------------------------------------------

    for ip_address in dataframe["src_ip"].unique():

        source_geoip[ip_address] = lookup_ip(
            ip_address,
            geoip_lookup
        )

    # --------------------------------------------------
    # Lookup destination IP addresses
    # --------------------------------------------------

    for ip_address in dataframe["dst_ip"].unique():

        destination_geoip[ip_address] = lookup_ip(
            ip_address,
            geoip_lookup
        )

    # --------------------------------------------------
    # Add source geographic information
    # --------------------------------------------------

    dataframe["src_country"] = dataframe["src_ip"].map(
        lambda ip: source_geoip[ip]["country"]
    )

    dataframe["src_city"] = dataframe["src_ip"].map(
        lambda ip: source_geoip[ip]["city"]
    )

    # --------------------------------------------------
    # Add destination geographic information
    # --------------------------------------------------

    dataframe["dst_country"] = dataframe["dst_ip"].map(
        lambda ip: destination_geoip[ip]["country"]
    )

    dataframe["dst_city"] = dataframe["dst_ip"].map(
        lambda ip: destination_geoip[ip]["city"]
    )

    return dataframe


# ==================================================
# Temporary Test
# ==================================================

if __name__ == "__main__":

    print("GeoIP Database")
    print("------------------------------")
"""
==================================================
NetGuard-AI
GeoIP Enrichment Module
==================================================

Maps IP addresses to geographic information
using a local CSV database.

Author:
    Lahcen Elkadi
"""
import ipaddress

from functools import lru_cache
 
import pandas as pd

from config import DATA_DIR


# ==================================================
# Configuration
# ==================================================

GEOIP_DATABASE = DATA_DIR / "countries.csv"


# ==================================================
# Load GeoIP Database
# ==================================================

@lru_cache(maxsize=1)
def load_geoip_database() -> pd.DataFrame:
    """
    Load the local GeoIP database once and cache it.
    """

    if not GEOIP_DATABASE.exists():

        raise FileNotFoundError(
            f"GeoIP database not found: {GEOIP_DATABASE}"
        )

    dataframe = pd.read_csv(
        GEOIP_DATABASE
    )

    required_columns = [
        "ip",
        "country",
        "city"
    ]

    for column in required_columns:

        if column not in dataframe.columns:

            raise ValueError(
                f"Missing required column: {column}"
            )
    if dataframe["ip"].duplicated().any():
        duplicates = dataframe[
            dataframe["ip"].duplicated(
                keep=False
            )
        ]
        raise ValueError(
                "Duplicate IP addresses found in GeoIP database:\n"
                f"{duplicates}"
        )
        
    return dataframe

def build_geoip_lookup(
    dataframe: pd.DataFrame
) -> dict:
    """
    Build a fast IP → geographic information lookup.
    """

    return (
        dataframe
        .set_index("ip")[["country", "city"]]
        .to_dict("index")
    )
# ==================================================
# IP Lookup
# ==================================================
def lookup_ip(
    ip_address: str,
    lookup: dict
) -> dict:
    """
    Look up geographic information using
    the IP lookup dictionary.
    """

    if not ip_address:

        return {
            "ip": ip_address,
            "country": "Invalid",
            "city": "Invalid"
        }

    ip_address = str(
        ip_address
    ).strip()

    ip_type = classify_ip(
        ip_address
    )

    if ip_type == "Invalid":

        return {
            "ip": ip_address,
            "country": "Invalid",
            "city": "Invalid"
        }

    result = lookup.get(
        ip_address
    )

    if result is None:

        if ip_type == "Private":

            return {
                "ip": ip_address,
                "country": "Private",
                "city": "Local Network"
            }

        return {
            "ip": ip_address,
            "country": "Unknown",
            "city": "Unknown"
        }

    return {
        "ip": ip_address,
        "country": result["country"],
        "city": result["city"]
    }
# ==================================================
# IP Classification
# ==================================================

def classify_ip(
    ip_address: str
) -> str:
    """
    Classify an IP address.
    """

    if not ip_address:

        return "Invalid"

    ip_address = str(
        ip_address
    ).strip()

    if not ip_address:

        return "Invalid"

    try:

        ip = ipaddress.ip_address(
            ip_address
        )

    except ValueError:

        return "Invalid"

    if ip.is_private:

        return "Private"

    if ip.is_loopback:

        return "Loopback"

    if ip.is_link_local:

        return "Link-Local"

    if ip.is_multicast:

        return "Multicast"

    if ip.is_unspecified:

        return "Unspecified"

    return "Public"
# ==================================================
# GeoIP Enrichment
# ==================================================
def enrich_ip(
    ip_address: str
) -> dict:
    """
    Enrich an IP address using the local GeoIP database.
    """

    database = load_geoip_database()

    lookup = build_geoip_lookup(
        database
    )

    return lookup_ip(
        ip_address,
        lookup
    )
# ==================================================
# Enrich Network DataFrame
# ==================================================

def enrich_dataframe(
    dataframe: pd.DataFrame
) -> pd.DataFrame:
    """
    Add geographic information for source and
    destination IP addresses.
    """

    dataframe = dataframe.copy()

    geoip_database = load_geoip_database()
    geoip_lookup = build_geoip_lookup(
	geoip_database
    )

    source_geoip = {}
    destination_geoip = {}

    # --------------------------------------------------
    # Lookup source IP addresses
    # --------------------------------------------------

    for ip_address in dataframe["src_ip"].unique():

        source_geoip[ip_address] = lookup_ip(
            ip_address,
            geoip_database
        )

    # --------------------------------------------------
    # Lookup destination IP addresses
    # --------------------------------------------------

    for ip_address in dataframe["dst_ip"].unique():

        destination_geoip[ip_address] = lookup_ip(
            ip_address,
            geoip_database
        )

    # --------------------------------------------------
    # Add source geographic information
    # --------------------------------------------------

    dataframe["src_country"] = dataframe["src_ip"].map(
        lambda ip: source_geoip[ip]["country"]
    )

    dataframe["src_city"] = dataframe["src_ip"].map(
        lambda ip: source_geoip[ip]["city"]
    )

    # --------------------------------------------------
    # Add destination geographic information
    # --------------------------------------------------

    dataframe["dst_country"] = dataframe["dst_ip"].map(
        lambda ip: destination_geoip[ip]["country"]
    )

    dataframe["dst_city"] = dataframe["dst_ip"].map(
        lambda ip: destination_geoip[ip]["city"]
    )

    return dataframe


# ==================================================
# Temporary Test
# ==================================================

if __name__ == "__main__":

    print("GeoIP Database")
    print("------------------------------")

    database = load_geoip_database()

    print(database)

    print()
    print("IP Lookup Test")
    print("------------------------------")

    test_ips = [
        "45.77.12.8",
        "192.168.1.5",
        "123.123.123.123"
    ]

    for ip_address in test_ips:

        print(
            enrich_ip(ip_address)
        )



    database = load_geoip_database()

    print(database)

    print()
    print("IP Lookup Test")
    print("------------------------------")

    test_ips = [
        "45.77.12.8",
        "192.168.1.5",
        "123.123.123.123"
    ]

    for ip_address in test_ips:

        print(
            enrich_ip(ip_address)
        )
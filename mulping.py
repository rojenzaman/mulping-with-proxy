#!/usr/bin/env python3

import os
import sys
import json
import argparse
import subprocess

from time import time
from random import randint, choice

# Constants for Operating Systems
UNIX = "UNIX"
WINDOWS = "WINDOWS"

ON_WINDOWS = False
ON_UNIX = False

# Determine the operating system
if "linux" in sys.platform or "darwin" in sys.platform:
    ON_UNIX = True
elif "win" in sys.platform:
    ON_WINDOWS = True
else:
    print("Unknown OS, assuming UNIX based")
    ON_UNIX = True

def failure(err):
    print(err, file=sys.stderr)
    sys.exit(1)

# Mullvad API Endpoint and Relay Data File Paths
RELAYS_LINK = "https://api.mullvad.net/www/relays/all/"
RELAYS_FILE_UNIX = "/tmp/mulpingData"

if ON_UNIX:
    RELAYS_FILE = RELAYS_FILE_UNIX
    DEFAULT_TIMEOUT = 10  # seconds
else:
    RELAYS_FILE = f"C:\\Users\\{os.getlogin()}\\AppData\\Local\\Temp\\mulpingData"
    DEFAULT_TIMEOUT = 10000  # milliseconds

TIMESTAMP_INDEX = 0

# Relay Attributes
HOSTNAME = "hostname"
TYPE = "type"
ACTIVE = "active"
COUNTRY_CODE = "country_code"
COUNTRY_NAME = "country_name"
CITY_CODE = "city_code"
CITY_NAME = "city_name"
IPV4 = "ipv4_addr_in"
IPV6 = "ipv6_addr_in"
PROVIDER = "provider"
BANDWIDTH = "network_port_speed"
OWNED = "owned"
STBOOT = "stboot"
RTT = "round_trip_time"

# Relay Types
WIREGUARD = "wireguard"
OPENVPN = "openvpn"
BRIDGE = "bridge"

# List of Proxies to Use
PROXIES = [
    "socks5h://192.168.1.100:1082",
    "socks5h://192.168.1.100:1080"
]

#############################
# Relay Filtering Utilities #
#############################

# Returns a function that checks if attribute 'a' in relay 'r' equals 'v'
eqAttr = lambda a: (lambda v: (lambda r: a in r and r[a] == v))

# Returns a function that checks if attribute 'a' in relay 'r' does not equal 'v'
neqAttr = lambda a: (lambda v: (lambda r: a in r and r[a] != v))

# Returns a function that checks if attribute 'a' in relay 'r' is greater than or equal to 'v'
geqAttr = lambda a: (lambda v: (lambda r: a in r and r[a] >= v))

# Returns a function that checks if relay 'r' matches at least one condition in 'filters'
filterOr = lambda filters: (lambda r: any(f(r) for f in filters))

# Returns a function that checks if relay 'r' matches all conditions in 'filters'
filterAnd = lambda filters: (lambda r: all(f(r) for f in filters))

# Generates and adds an aggregate filter to 'filters'
def getFilter(source, getSubFilter, aggregator, filters):
    conditions = list(map(getSubFilter, source))
    newFilter = aggregator(conditions)
    filters.append(newFilter)

#########################
# Relays Data Retrieval #
#########################

def fetchRelays():
    print("Fetching relays... ", end="")
    sys.stdout.flush()

    import requests  # Imported here to reduce initial load time

    # Select a random proxy from the list
    selected_proxy = choice(PROXIES)
    proxies = {
        'http': selected_proxy,
        'https': selected_proxy
    }

    try:
        response = requests.get(RELAYS_LINK, proxies=proxies, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        relays = response.json()
    except Exception as e:
        failure(f"Could not fetch relays: {e}")

    # Insert timestamp for caching
    relays.insert(TIMESTAMP_INDEX, time())
    try:
        with open(RELAYS_FILE, "w") as f:
            json.dump(relays, f)
    except Exception as e:
        failure(f"Could not write relays to file: {e}")

    # Remove timestamp before returning
    del relays[TIMESTAMP_INDEX]

    print("done!\n")
    return relays

def loadRelays():
    try:
        with open(RELAYS_FILE, "r") as f:
            relays = json.load(f)
    except Exception:
        raise Exception("Failed to read relay data file.")

    if not isinstance(relays[TIMESTAMP_INDEX], (float, int)):
        raise Exception("Invalid relay data format.")

    # If data is older than 12 hours, refresh
    if time() - relays[TIMESTAMP_INDEX] >= 43200:
        raise Exception("Relay data is outdated.")

    # Remove timestamp before returning
    del relays[TIMESTAMP_INDEX]

    return relays

def getRelays():
    if os.path.isfile(RELAYS_FILE):
        try:
            relays = loadRelays()
        except:
            relays = fetchRelays()
    else:
        relays = fetchRelays()
    return relays

##################
# Ping Utilities #
##################

def parsePing(pingOutput, platform=UNIX):
    lines = pingOutput.splitlines()
    lines = [line for line in lines if line.strip() != ""]

    resultsLine = lines[-1]
    try:
        if platform == UNIX:
            # Example: rtt min/avg/max/mdev = 0.026/0.026/0.026/0.000 ms
            resultsLine = resultsLine.split("=")[-1].strip()
            rtts = [float(v) for v in resultsLine.split(" ")[0].split("/")]
        else:
            # Example: Minimum = 0ms, Maximum = 0ms, Average = 0ms
            rtts = []
            parts = resultsLine.split(",")
            for part in parts:
                value = part.split("=")[-1].strip().replace("ms", "")
                rtts.append(float(value))
    except:
        return None, None, None

    return rtts[0], rtts[1], rtts[2]

def ping(addr, count, timeout=DEFAULT_TIMEOUT, ipv6=False):
    try:
        if ON_UNIX:
            # Example: ping 0.0.0.0 -nqc 1 -W 10
            pingCommand = ["ping", addr, "-nqc", str(count), "-W", str(timeout)]
        else:
            # Example: ping 0.0.0.0 -n 1 -w 10000
            pingCommand = ["ping", addr, "-n", str(count), "-w", str(timeout)]

        if ipv6:
            pingCommand.append("-6")

        pingProcess = subprocess.run(pingCommand, capture_output=True)
    except Exception:
        failure("The `ping` program could not be called")

    if pingProcess.returncode != 0:
        return None, None, None

    return parsePing(pingProcess.stdout.decode(), platform=UNIX if ON_UNIX else WINDOWS)

#####################
# Mullvad Utilities #
#####################

def mullvadChangeRelay(hostname):
    try:
        mullvadProcess = subprocess.run(["mullvad", "relay", "set", "location", hostname])
        if mullvadProcess.returncode != 0:
            raise Exception("Mullvad relay change failed.")
    except Exception as e:
        failure(f"An error occurred while changing the Mullvad relay to {hostname}: {e}")

######################
# Printing Utilities #
######################

noFormat = lambda i: i
noPrint = lambda *_: None

relayTypeFormat = {
    WIREGUARD: "WireGuard",
    OPENVPN: "OpenVPN",
    BRIDGE: "Bridge"
}

ITEMS_FORMAT = {
    HOSTNAME: noFormat,
    IPV4: noFormat,
    IPV6: noFormat,
    COUNTRY_CODE: noFormat,
    CITY_CODE: noFormat,
    PROVIDER: noFormat,
    RTT: lambda rtt: f"{rtt:.3f}ms",
    OWNED: lambda o: "Owned" if o else "Rented",
    BANDWIDTH: lambda b: f"{b} Gbps",
    COUNTRY_NAME: noFormat,
    CITY_NAME: noFormat,
    STBOOT: lambda s: "RAM" if s else "Disk",
    TYPE: lambda t: relayTypeFormat.get(t, "Unknown")
}

ITEMS_IDS = {
    "h": HOSTNAME,
    "4": IPV4,
    "6": IPV6,
    "c": COUNTRY_CODE,
    "C": CITY_CODE,
    "p": PROVIDER,
    "l": RTT,
    "O": OWNED,
    "b": BANDWIDTH,
    "cf": COUNTRY_NAME,
    "Cf": CITY_NAME,
    "s": STBOOT,
    "t": TYPE
}

attributesShort = [HOSTNAME, RTT]
attributesLong = [HOSTNAME, RTT, COUNTRY_NAME, CITY_NAME, PROVIDER, OWNED, STBOOT]

def getAttributes(formatList):
    attributes = []
    for identifier in formatList:
        if identifier not in ITEMS_IDS:
            failure(f"Unknown attribute identifier: {identifier}")
        attributes.append(ITEMS_IDS[identifier])
    return attributes

def getSpacing(relays, items):
    spaces = {}
    for item in items:
        if item == RTT:
            spaces[item] = 10  # Fixed spacing for RTT
            continue
        max_length = max(len(ITEMS_FORMAT[item](relay.get(item, ""))) for relay in relays)
        spaces[item] = max_length
    return spaces

def getSpacingList(items, spacing):
    return [spacing.get(item, None) for item in items]

def printBox(items, start, end, middle, line_char):
    if not items:
        return

    box = start
    for width in items:
        box += line_char * (width + 2) + middle
    box = box.rstrip(middle) + end
    print(box)

def printLine(relay, attributes, itemsSpaces, wall):
    line = f"{wall}"
    for attribute in attributes:
        if attribute not in ITEMS_FORMAT:
            failure("Unknown attribute received by printing function")
        value = relay.get(attribute, "error")
        if value is None:
            value = "error"
        formatted = ITEMS_FORMAT[attribute](value)
        line += f" {formatted:{itemsSpaces[attribute]}} {wall}"
    print(line)

########
# Main #
########

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="mulping",
        description="Batch ping utility for Mullvad VPN (unaffiliated)",
    )

    relayConditions = [
        neqAttr(TYPE)(BRIDGE),
        eqAttr(ACTIVE)(True)
    ]

    parser.add_argument("-c", "--country", action="store", help="Only select servers located in the specified countries", nargs="+", metavar="country_code")
    parser.add_argument("-cn", "--country-not", action="store", help="Exclude servers located in the specified countries", nargs="+", metavar="country_code")
    parser.add_argument("-C", "--city", action="store", help="Only select servers located in the specified cities", nargs="+", metavar="city_code")
    parser.add_argument("-Cn", "--city-not", action="store", help="Exclude servers located in the specified cities", nargs="+", metavar="city_code")
    parser.add_argument("-H", "--hostname", action="store", help="Only select the specified servers", nargs="+", metavar="hostname")
    parser.add_argument("-Hn", "--hostname-not", action="store", help="Exclude the specified servers", nargs="+", metavar="hostname")
    parser.add_argument("-p", "--provider", action="store", help="Only select servers using the specified providers", nargs="+", metavar="provider")
    parser.add_argument("-pn", "--provider-not", action="store", help="Exclude servers using the specified providers", nargs="+", metavar="provider")
    parser.add_argument("-w", "--wireguard", action="store_true", help="Only select WireGuard servers")
    parser.add_argument("-o", "--openvpn", action="store_true", help="Only select OpenVPN servers")
    parser.add_argument("-s", "--stboot", action="store_true", help="Only select stboot servers")
    parser.add_argument("-O", "--owned", action="store_true", help="Only select servers owned by Mullvad")
    parser.add_argument("-b", "--bandwidth", action="store", help="Only select servers with at least the specified bandwidth speed (Gbps)", metavar="bandwidth")

    parser.add_argument("-v", "--verbose", action="store_true", help="Show more relay attributes in the results")
    parser.add_argument("-f", "--format", action="store", help="Specify the relay attributes to display in the results", nargs="+", metavar="identifier")
    parser.add_argument("-q", "--quiet", action="store_true", help="Don't display relay results box")
    parser.add_argument("-d", "--descending", action="store_true", help="Show results in descending order of latency")

    parser.add_argument("-np", "--no-ping", action="store_true", help="Don't perform ping, just display available relays based on other arguments")
    parser.add_argument("-t", "--timeout", action="store", help="Maximum time to wait for each ping response", metavar="timeout")
    parser.add_argument("-6", "--ipv6", action="store_true", help="Use IPv6 to ping servers (requires IPv6 connectivity on both ends)")

    parser.add_argument("-u", "--use", action="store_true", help="Change Mullvad relay to use the lowest latency server tested")
    parser.add_argument("-r", "--random", action="store_true", help="Change Mullvad relay to use a random server from the available options based on other arguments")

    args = parser.parse_args()

    formatPingError = lambda arg: f"Use a format that includes latency to use the {arg} option"
    flagPingError = lambda arg: f"The '-np/--no-ping' option cannot be used with the {arg} option"

    ######################
    # Arguments Handling #
    ######################

    if args.format:
        attributes = getAttributes(args.format)
    else:
        attributes = attributesLong if args.verbose else attributesShort

    pingRequested = RTT in attributes

    if not pingRequested:
        if args.use:
            failure(formatPingError("'-u'/'--use'"))
        if args.descending:
            failure(formatPingError("'-d'/'--descending'"))

    if args.no_ping:
        if args.use:
            failure(flagPingError("'-u'/'--use'"))
        if args.descending:
            failure(flagPingError("'-d'/'--descending'"))

        while RTT in attributes:
            attributes.remove(RTT)

        pingRequested = False

    # Apply filters based on arguments
    if args.country:
        getFilter(args.country, eqAttr(COUNTRY_CODE), filterOr, relayConditions)
    if args.country_not:
        getFilter(args.country_not, neqAttr(COUNTRY_CODE), filterAnd, relayConditions)

    if args.city:
        if len(args.city) % 2 != 0:
            failure("City filter requires pairs of country_code and city_code")
        cities = list(zip(args.city[::2], args.city[1::2]))

        # Function to check if relay is in the specified city
        def inCity(cityTuple):
            return lambda r: eqAttr(COUNTRY_CODE)(cityTuple[0])(r) and eqAttr(CITY_CODE)(cityTuple[1])(r)

        getFilter(cities, inCity, filterOr, relayConditions)

    if args.city_not:
        if len(args.city_not) % 2 != 0:
            failure("City-not filter requires pairs of country_code and city_code")
        notCities = list(zip(args.city_not[::2], args.city_not[1::2]))

        # Function to check if relay is not in the specified city
        def notInCity(cityTuple):
            return lambda r: not (eqAttr(COUNTRY_CODE)(cityTuple[0])(r) and eqAttr(CITY_CODE)(cityTuple[1])(r))

        getFilter(notCities, notInCity, filterAnd, relayConditions)

    if args.hostname:
        getFilter(args.hostname, eqAttr(HOSTNAME), filterOr, relayConditions)
    if args.hostname_not:
        getFilter(args.hostname_not, neqAttr(HOSTNAME), filterAnd, relayConditions)

    if args.provider:
        getFilter(args.provider, eqAttr(PROVIDER), filterOr, relayConditions)
    if args.provider_not:
        getFilter(args.provider_not, neqAttr(PROVIDER), filterAnd, relayConditions)

    if args.bandwidth:
        try:
            bandwidth_value = float(args.bandwidth)
            relayConditions.append(geqAttr(BANDWIDTH)(bandwidth_value))
        except:
            failure("Error: The bandwidth option must be a number")

    if args.wireguard:
        relayConditions.append(eqAttr(TYPE)(WIREGUARD))
    if args.openvpn:
        relayConditions.append(eqAttr(TYPE)(OPENVPN))
    if args.stboot:
        relayConditions.append(eqAttr(STBOOT)(True))
    if args.owned:
        relayConditions.append(eqAttr(OWNED)(True))
    if args.ipv6:
        relayConditions.append(lambda r: IPV6 in r and r[IPV6] is not None)

    # Set timeout
    if args.timeout is None:
        timeout = DEFAULT_TIMEOUT
    else:
        try:
            timeout = float(args.timeout) / 1000 if ON_UNIX else float(args.timeout)
        except:
            failure("Error: Timeout must be a number")

    # Determine IP version to use for ping
    IP = IPV6 if args.ipv6 else IPV4

    # Determine printing behavior based on quiet and descending flags
    boxLivePrint = noPrint if args.quiet or args.descending else printBox
    lineLivePrint = noPrint if args.quiet or args.descending else printLine

    #############
    # Main Logic #
    #############

    relays = list(filter(filterAnd(relayConditions), getRelays()))

    if not relays:
        failure("No relays match the specified conditions.")

    itemsSpaces = getSpacing(relays, attributes)

    # Print the header box
    boxLivePrint(getSpacingList(attributes, itemsSpaces), "┌", "┐", "┬", "─")
    for index, relay in enumerate(relays):
        hostname = relay.get(HOSTNAME, "Unknown")
        address = relay.get(IP, "Unknown")

        if pingRequested:
            _, rtt, _ = ping(address, 1, timeout=timeout, ipv6=args.ipv6)
            relays[index][RTT] = rtt

        lineLivePrint(relay, attributes, itemsSpaces, "│")
    boxLivePrint(getSpacingList(attributes, itemsSpaces), "└", "┘", "┴", "─")
    if not args.quiet and not args.descending:
        print()

    ####################
    # Final Operations #
    ####################

    nonReachableRelays = list(filter(eqAttr(RTT)(None), relays))
    reachableRelays = list(filter(neqAttr(RTT)(None), relays))

    if args.descending:
        # Sort reachable relays by descending latency
        descendingRelays = nonReachableRelays + sorted(reachableRelays, key=lambda r: r[RTT], reverse=True)

        if descendingRelays:
            printBox(getSpacingList(attributes, itemsSpaces), "┌", "┐", "┬", "─")
            for relay in descendingRelays:
                printLine(relay, attributes, itemsSpaces, "│")
            printBox(getSpacingList(attributes, itemsSpaces), "└", "┘", "┴", "─")
            print()

    if not reachableRelays and pingRequested:
        failure("No relay could be reached.")

    if pingRequested:
        lowestLatency = min(reachableRelays, key=lambda r: r[RTT])
        maxLatency = max(reachableRelays, key=lambda r: r[RTT])

        print(f"Highest latency host: {maxLatency[HOSTNAME]} ({maxLatency[RTT]}ms)")
        print(f"Lowest latency host: {lowestLatency[HOSTNAME]} ({lowestLatency[RTT]}ms)")

    if args.use:
        print("\nSelecting the lowest latency server...")
        mullvadChangeRelay(lowestLatency[HOSTNAME])
        sys.exit(0)

    if args.random:
        print("\nSelecting a random server...")
        # Choose relay pool based on whether latency testing was performed
        randomRelayPool = relays if not pingRequested else reachableRelays
        if not randomRelayPool:
            failure("No reachable relays available for random selection.")
        selected_relay = choice(randomRelayPool)
        mullvadChangeRelay(selected_relay[HOSTNAME])
        sys.exit(0)

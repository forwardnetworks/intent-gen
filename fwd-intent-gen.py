"""
Usage:
  fwd-intent-gen.py run <appserver> <input> <snapshot> <queryId> [--batch=<batch_size>]
  fwd-intent-gen.py check <appserver> <input> <snapshot> [--csv]

Options:
  -h --help             Show this help message
  --batch=<batch_size>  Configure batch size [default: 300]
  --csv                 "Dump into CSV file for import"
"""

import math
import socket
import sys
import pandas as pd
import argparse
import aiohttp
import asyncio
import json
import os
from docopt import docopt
from openpyxl.styles import Font
from openpyxl import load_workbook


# Utilities


def remove_columns_df(df, columns):
    return df.drop(columns, axis=1)


def update_font(f):
    workbook = load_workbook(f)
    worksheet = workbook.active
    font = Font(size=14)  # Set font size to 14
    for row in worksheet.iter_rows():
        for cell in row:
            cell.font = font
    workbook.save(f)


def remove_columns(data, columns_to_remove):
    new_data = []
    for item in data:
        new_item = item.copy()
        for column in columns_to_remove:
            new_item.pop(column)
        new_data.append(new_item)
    return new_data


def resolve_ip_to_domain(ip_address):
    try:
        domain_name = socket.gethostbyaddr(ip_address)[0]
        return domain_name
    except socket.herror as e:
        return ip_address


#

options = {
    "intent": "PREFER_DELIVERED",
    "maxCandidates": 5000,
    "maxResults": 1,
    "maxReturnPathResults": 1,
    "maxSeconds": 30,
    "maxOverallSeconds": 300,
    "includeNetworkFunctions": False,
}

# Get the username and password from environment variables.
username = os.getenv("FWD_USER")
password = os.getenv("FWD_PASSWORD")

if not username or not password:
    print("Please provide both FWD_USER and FWD_PASSWORD.")
    sys.exit()

headers_seq = {
    "Accept": "application/json-seq",
    "Content-Type": "application/json",
}

headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
}


forwardingOutcomes = {
    "DELIVERED": {
        "description": "Traffic was delivered to destination IP’s discovered location(s).",
        "remedy": "None",
    },
    "NOT_DELIVERED": {
        "description": "No available paths found for query",
        "remedy": "This error may indicate that the source or destination address could not be found in the model. Check the source and destination address using Forward Enterprise search. The address may be incorrect or the address cannot be located.",
    },
    "DELIVERED_TO_INCORRECT_LOCATION": {
        "description": "Traffic was delivered out of some edge ports. However, traffic did not reach the expected delivery locations based on destination IP’s discovered locations. One scenario where this occurs is when a device in the middle of the actual path from source IP to destination IP is not configured for collection in the Forward platform. For example, suppose the actual device path is A -> B -> C, and only devices A and C are part of the snapshot in the Forward platform. In this case, the path would show traffic exiting device A at some edge port, but since destination IP is discovered to reside at device C, traffic is delivered to an incorrect location.",
        "remedy": " This error should not happen on a fully modeled network, the result_df is indicating there is a high chance there is a missing device in the Forward Enteprise Model. Leverage the pathsURL to diagnose where the last hop device and interface is, Forward Enterprise will report any missing devices as indicated by CDP/LLDP. Work with your teams to assess what device is missing and add to the model",
    },
    "BLACKHOLE": {
        "description": "Traffic was implicitly dropped at the last hop, since the device had no matching rule. For example, if a router does not have a default route, traffic to any IP that is not in the routing table gets blackholed.",
        "remedy": "This error should not typically happen on a production network, it indicates that there is missing information for the device to forward traffic to another device. Leverage the queryURL to investigate using the Forward Enterprise platform to understand why there is no next-hop to forward traffic to.",
    },
    "DROPPED": {
        "description": "Traffic was explicitly dropped at the last hop, e.g. by a null route.",
        "remedy": "Check the last hop device to ensure there is a route to the destination",
    },
    "INADMISSIBLE": {
        "description": "Traffic was not admitted into the network. The first hop interface does not accept the traffic, e.g. incoming traffic had a vlan tag 10 while the ingress interface is an access interface that only permits traffic with vlan tag 20.",
        "remedy": "This error may indicate an incorrect assumption about the where to originate the source of the check.",
    },
    "UNREACHABLE": {
        "description": "ARP/NDP resolution failed along the path resulting in traffic not getting delivered to the intended destination.",
        "remedy": "This error may indicate missing state in the model or state that has aged out due to inactivity. Use the queryURL to identify the next-hop and identify if that device is missing necessary reachability information",
    },
    "LOOP": {
        "description": "Traffic entered a forwarding loop.",
        "remedy": "This error should be rare but can happen if improper static routes are defined with a default gateway. Use the queryURL to examine the path to determine which device has the incorrect route configuration",
    },
}
securityOutcomes = {
    "PERMITTED": {
        "description": "All ACLs along the path permitted traffic to flow through.",
        "remedy": "None",
    },
    "DENIED": {
        "description": "Traffic was dropped by ACLs at some hop along the path. Note that the ACL drop may not always occur at the last hop since search results are computed in permit all mode.",
        "remedy": "Traffic is denied by a security policy. Update the ACL or firewall policy to allow communications and retest",
    },
    "UNKNOWN": {
        "description": "No path has been found for this search so a security outcome is reported as UNKNOWN",
        "remedy": "This error may indicate that the source or destination address could not be found in the model. Check the source and destination address using Forward Enterprise search. The address may be incorrect or the address cannot be located.",
    },
}


def return_firstlast_hop(df):
    for index, row in df.iterrows():
        hops = row["hops"]
        if len(hops) > 0:
            firsthop = hops[0]
            lasthop = hops[-1]
            first_hop_device_name = firsthop.get("deviceName")
            first_hop_deviceType = firsthop.get("deviceType")
            last_hop_device_name = lasthop.get("deviceName")
            last_hop_deviceType = lasthop.get("deviceType")
            df.at[index, "firstHopDevice"] = first_hop_device_name
            df.at[index, "firstHopDeviceType"] = first_hop_deviceType
            df.at[index, "lastHopDevice"] = last_hop_device_name
            df.at[index, "lastHopDeviceType"] = last_hop_deviceType
            df.at[index, "lastHopEgressIntf"] = lasthop.get("egressInterface")
            if "egressInterface" in lasthop:
                df.at[index, "lastHopEgressIntf"] = lasthop["egressInterface"]

            else:
                df.at[index, "lastHopEgressIntf"] = None
    return remove_columns_df(df, ["hops"])


def addForwardingOutcomes(result):
    result_df = pd.DataFrame(result)

    # Add new columns to the DataFrame
    result_df["forwardDescription"] = ""
    result_df["forwardRemedy"] = ""
    result_df["securityDescription"] = ""
    result_df["securityRemedy"] = ""

    # Loop through each row in the DataFrame
    for index, row in result_df.iterrows():
        forwarding_outcome = row["forwardingOutcome"]
        security_outcome = row["securityOutcome"]

        # Check if the forwarding outcome exists in the forwardingOutcomes dictionary
        if forwarding_outcome in forwardingOutcomes:
            description = forwardingOutcomes[forwarding_outcome]["description"]
            remedy = forwardingOutcomes[forwarding_outcome]["remedy"]

            result_df.at[index, "forwardDescription"] = description
            result_df.at[index, "forwardRemedy"] = remedy

        if security_outcome in securityOutcomes:
            description = securityOutcomes[security_outcome]["description"]
            remedy = securityOutcomes[security_outcome]["remedy"]
            result_df.at[index, "securityDescription"] = description
            result_df.at[index, "securityRemedy"] = remedy

    return result_df


def check_info_paths(data):
    for element in data:
        info = element.get("info", {})
        paths = info.get("paths", [])
        element["pathCount"] = len(paths)

        srcIpLocationType = element.get("srcIpLocationType", "UNKNOWN")
        dstIpLocationType = element.get("dstIpLocationType", "UNKNOWN")

        if not paths:
            paths = [
                {
                    "forwardingOutcome": "NOT_DELIVERED",
                    "securityOutcome": "UNKNOWN",
                    "hops": [],
                }
            ]

        element["forwardHops"] = len(paths[0].get("hops", []))
        element["info"] = {"paths": paths}
        element["srcIpLocationType"] = srcIpLocationType
        element["dstIpLocationType"] = dstIpLocationType

        return_path_info = element.get("returnPathInfo", {})
        return_paths = return_path_info.get("paths", [])

        if return_paths:
            element["returnHops"] = len(return_paths[0].get("hops", []))
            element["returnPathCount"] = len(return_paths)
            # print(f'-> {element["returnHops"]} -> {return_paths}')

        else:
            element["returnPathCount"] = len(return_paths)
            element["returnHops"] = 0
            return_paths = [
                {
                    "forwardingOutcome": "NOT_DELIVERED",
                    "securityOutcome": "UNKNOWN",
                    "hops": [],
                }
            ]
        # print(f'{element["returnHops"]} -> {return_paths}')
        element["returnPathInfo"] = {"paths": return_paths}

    return data


def parse_subnets(data):
    parsed_data = []
    for item in data:
        try:
            # print(f"Item->{item}")
            origin = item["origin"]
            if origin == "HOST":
                parsed_data.append(
                    {
                        "address": item["address"],
                        "origin": "HOST",
                        "description": "Host Interface",
                        "status": "VALID",
                        "data": item["hosts"],
                    }
                )
            elif origin == "INTERFACE":
                parsed_data.append(
                    {
                        "address": item["address"],
                        "origin": "INTERFACE",
                        "description": "Device Interface",
                        "status": "VALID",
                        "data": item["interfaces"],
                    }
                )
            elif origin == "INTERFACE_ATTACHED_SUBNET":
                # locations = item["locations"]
                parsed_data.append(
                    {
                        "address": item["address"],
                        "origin": "INTERFACE_ATTACHED_SUBNET",
                        "description": "Incorrect device address",
                        "status": "INVALID",
                        "data": None,
                    }
                )
            else:
                parsed_data.append(
                    {
                        "address": item["address"],
                        "origin": "UNKNOWN",
                        "description": "UNKNWON",
                        "status": "INVALID",
                        "data": None,
                    }
                )

        except KeyError:
            parsed_data.append(
                {
                    "address": item["address"],
                    "origin": "ERROR",
                    "description": "Address not found in network model",
                    "status": "INVALID",
                    "data": None,
                }
            )

    return parsed_data


async def fetch(
    session, url, data=None, method="GET", username=None, password=None, headers={}
):
    auth = aiohttp.BasicAuth(username, password) if username and password else None
    if method == "GET":
        async with session.get(
            url, auth=auth, params=data, headers=headers
        ) as response:
            return await response.read(), response.status
    elif method == "POST":
        async with session.post(url, auth=auth, headers=headers, json=data) as response:
            return await response.read(), response.status
    else:
        raise ValueError(f"Invalid HTTP method: {method}")


def fixup_queries(input):
    queries = []
    for region, data in input.items():
        for application, app in data.items():
            sources = app.get("source", [])
            destinations = app.get("destination", [])
            ipProto = app.get("ipProto", [])
            dstPorts = app.get("dstPorts", [])

            print(f"Region: {region}")
            print(f"Application: {application}")
            print(f"Search Count: {len(sources) * len(destinations)}\n")

            for source in sources:
                for destination in destinations:
                    query = {
                        "srcIp": source,
                        "dstIp": destination,
                        "ipProto": ipProto,
                        "dstPort": dstPorts,
                        "application": application,
                        "region": region,
                    }
                queries.append(query)
    return queries


def error_queries(input, address_df):
    invalid_addresses = set()
    for region, data in input.items():
        for application, app in data.items():
            sources = app.get("source", [])
            destinations = app.get("destination", [])
            for source in sources:
                for destination in destinations:
                    if (address_df["address"] == source).any() or (
                        address_df["address"] == destination
                    ).any():
                        record = address_df.loc[
                            (address_df["address"] == source)
                            | (address_df["address"] == destination),
                            ["address", "status", "origin", "description"],
                        ]
                        if record["status"].values[0] != "VALID":
                            error_message = f"Error occurred. Address: {record['address'].values[0]}, Status: {record['status'].values[0]}, Description: {record['description'].values[0]}"
                            invalid_addresses.add(record["address"].values[0])

            error_df = address_df[address_df["address"].isin(invalid_addresses)].copy()

            print(f"\nErrors:\n{region}\n{application}\n")
            for index, row in error_df.iterrows():
                address = row["address"]
                hostname = resolve_ip_to_domain(address)
                error_df.loc[index, "hostname"] = hostname
                print(
                    f"Error occurred. Address: {row['address']}, Name: {hostname}, Origin: {row['origin']} Status: {row['status']}, Description: {row['description']}"
                )

            print()
            return error_df


async def process_input(appserver, snapshot, input, address_df, batch_size):
    async with aiohttp.ClientSession() as session:
        dfs = []  # List to store individual dataframes
        for region, data in input.items():
            for application, app in data.items():
                sources = app.get("source", [])
                destinations = app.get("destination", [])
                ipProto = app.get("ipProto", [])
                dstPorts = app.get("dstPorts", [])

                print(f"Region: {region}")
                print(f"Application: {application}")
                print(f"Search Count: {len(sources) * len(destinations)}\n")

                filtered_queries = [
                    {
                        "srcIp": source,
                        "dstIp": destination,
                        "ipProto": ipProto,
                        "dstPort": dstPorts,
                    }
                    for source in sources
                    for destination in destinations
                    if (
                        (address_df["address"] == source)
                        & (address_df["status"] == "VALID")
                    ).any()
                    and (
                        (address_df["address"] == destination)
                        & (address_df["status"] == "VALID")
                    ).any()
                ]

                query_list_df = pd.DataFrame(filtered_queries)
                print()
                query_list_df["region"] = region
                query_list_df["application"] = application
                total_queries = len(filtered_queries)

                if total_queries > 0:
                    num_batches = math.ceil(total_queries / batch_size)
                    for i in range(num_batches):
                        start_index = i * batch_size
                        end_index = min((i + 1) * batch_size, total_queries)
                        batch_queries = filtered_queries[start_index:end_index]
                        body = {"queries": batch_queries, **options}

                        url = (
                            f"https://{appserver}/api/snapshots/{snapshot}/pathsBulkSeq"
                        )
                        response_text, response_status = await fetch(
                            session,
                            url,
                            body,
                            method="POST",
                            username=username,
                            password=password,
                            headers=headers_seq,
                        )
                        parsed_data = []
                        # Check if the request was successful.
                        if response_status != 200:
                            raise aiohttp.ClientResponseError(
                                request_info=None,
                                history=None,
                                status=response_status,
                                message="Request failed",
                            )
                        lines = response_text.decode().split("\x1E")
                        parsed_data.extend(json.loads(line) for line in lines if line)
                        # Cleanup for dataframe import
                        fix_data = check_info_paths(parsed_data)
                        # print(f"debug {fix_data}")

                        r = pd.json_normalize(
                            fix_data,
                            record_path=["info", "paths"],
                            meta=[
                                "dstIpLocationType",
                                "srcIpLocationType",
                                "pathCount",
                                "forwardHops",
                                "returnPathCount",
                                "returnHops",
                                "queryUrl",
                            ],
                            # errors="ignore",
                        )
                        merged_df = pd.merge(
                            r, query_list_df, left_index=True, right_index=True
                        )
                        dfs.append(merged_df)

    return pd.concat(dfs, ignore_index=True)


def search_address(input):
    addresses = set()
    for region, region_value in input.items():
        for service, service_value in region_value.items():
            if isinstance(service_value, dict):
                filtered_values = {
                    key: value
                    for key, value in service_value.items()
                    if key in ["source", "destination"]
                }
                for key, value in filtered_values.items():
                    for a in value:
                        addresses.add(a)
    return addresses


async def nqe_get_hosts_by_port(queryId, appserver, snapshot, device, port):
    async with aiohttp.ClientSession() as session:
        url = f"https://{appserver}/api/nqe?snapshotId={snapshot}"
        body = {
            "queryId": queryId,
            "queryOptions": {
                "columnFilters": [
                    {"columnName": "deviceName", "value": device},
                    {"columnName": "Interface", "value": port},
                ],
            },
        }
        response_text, response_status = await fetch(
            session,
            url,
            body,
            method="POST",
            username=username,
            password=password,
            headers=headers,
        )
        if response_status == 200:
            response_json = json.loads(response_text)
        else:
            raise Exception(f"Error: {response_status} {response_text}")
    return response_json["items"][0]


async def search_subnet(appserver, snapshot, addresses):
    result_list = []  # List to store the response JSON for each address

    async with aiohttp.ClientSession() as session:
        for address in addresses:
            url = f"https://{appserver}/api/snapshots/{snapshot}/subnets"
            params = {"address": address, "minimal": "true"}
            response_text, response_status = await fetch(
                session,
                url,
                params,
                username=username,
                password=password,
                headers=headers,
            )
            if response_status == 200:
                response_json = json.loads(response_text)
                response_json["address"] = address
                result_list.append(response_json)
            else:
                raise Exception(f"Error: {response_status}")
    parsed_data = parse_subnets(result_list)
    df = pd.DataFrame(parsed_data)  # Create a dataframe from the result_df list
    return df


def main():
    arguments = docopt(__doc__)
    if arguments["run"]:
        infile = arguments["<input>"]
        appserver = arguments["<appserver>"]
        snapshot = arguments["<snapshot>"]
        queryId = arguments["<queryId>"]
        batchsize = int(arguments["--batch"])
        print(f"Setting batch size: {batchsize}")
        with open(infile) as file:
            data = json.load(file)
        report = f"intent-gen-{snapshot}.xlsx"
        pd.set_option("display.max_rows", None)  # Show all rows
        addresses = search_address(data)
        address_df = asyncio.run(search_subnet(appserver, snapshot, addresses))
        intent = asyncio.run(
            process_input(appserver, snapshot, data, address_df, batchsize)
        )
        forwarding_outcomes = addForwardingOutcomes(intent)
        updatedf = return_firstlast_hop(forwarding_outcomes)
        for index, row in updatedf.iterrows():
            device = row["lastHopDevice"]
            interface = row["lastHopEgressIntf"]
            forwardingOutcome = row["forwardingOutcome"]
            outcomes = ["DELIVERED", "NOT_DELIVERED"]
            if (
                device
                and forwardingOutcome
                and interface
                and forwardingOutcome not in outcomes
            ):
                hosts = asyncio.run(
                    nqe_get_hosts_by_port(
                        queryId,
                        appserver,
                        snapshot,
                        device,
                        interface,
                    )
                )
                updatedf.loc[index, "hostAddress"] = hosts["Address"]
                updatedf.loc[index, "MacAddress"] = hosts["MacAddress"]
                updatedf.loc[index, "OUI"] = hosts["OUI"]
                updatedf.loc[index, "hostInterface"] = hosts["Interface"]
        print(
            updatedf[
                [
                    "region",
                    "application",
                    "srcIp",
                    "dstIp",
                    "ipProto",
                    "dstPort",
                    "forwardingOutcome",
                    "securityOutcome",
                    "srcIpLocationType",
                    "dstIpLocationType",
                    "pathCount",
                    "forwardHops",
                    "returnPathCount",
                    "returnHops",
                    "firstHopDevice",
                    # "firstHopDeviceType",
                    "lastHopDevice",
                    "lastHopEgressIntf",
                    # "lastHopDeviceType",
                    "hostAddress",
                    "MacAddress",
                    "OUI",
                    "hostInterface",
                ]
            ]
        )
        updatedf[
            [
                "region",
                "application",
                "srcIp",
                "dstIp",
                "ipProto",
                "dstPort",
                "forwardingOutcome",
                "securityOutcome",
                "srcIpLocationType",
                "dstIpLocationType",
                "pathCount",
                "forwardHops",
                "returnPathCount",
                "returnHops",
                "firstHopDevice",
                "firstHopDeviceType",
                "lastHopDevice",
                "lastHopDeviceType",
                "lastHopEgressIntf",
                "hostAddress",
                "MacAddress",
                "OUI",
                "hostInterface",
                "queryUrl",
                "forwardDescription",
                "forwardRemedy",
                "securityDescription",
                "securityRemedy"
            ]
        ].to_excel(report, index=True)
        update_font(report)

    elif arguments["check"]:
        print("Running Check")
        infile = arguments["<input>"]
        appserver = arguments["<appserver>"]
        snapshot = arguments["<snapshot>"]
        report = f"errored-devices-{snapshot}.csv"
        with open(infile) as file:
            data = json.load(file)
        addresses = search_address(data)
        address_df = asyncio.run(search_subnet(appserver, snapshot, addresses))
        errored_devices = error_queries(data, address_df)
        if arguments["--csv"]:
            errored_devices.loc[:, ["address", "hostname"]].to_csv(report, index=False)

    else:
        print(
            "Invalid command. Please refer to the usage message for available commands."
        )


if __name__ == "__main__":
    main()

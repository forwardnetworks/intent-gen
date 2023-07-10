"""
Usage:
  fwd-intent-gen.py <appserver> <input> <snapshot>

Options:
  -h --help     Show this help message

"""

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

options = {
    "intent": "PREFER_DELIVERED",
    "maxCandidates": 5000,
    "maxResults": 1,
    "maxReturnPathResults": 1,
    "maxSeconds": 30,
    "maxOverallSeconds": 300,
    "includeNetworkFunctions": False,
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
        "remedy": " This error should not happen on a fully modeled network, the result is indicating there is a high chance there is a missing device in the Forward Enteprise Model. Leverage the pathsURL to diagnose where the last hop device and interface is, Forward Enterprise will report any missing devices as indicated by CDP/LLDP. Work with your teams to assess what device is missing and add to the model",
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


def addForwardingOutcomes(df):
    df["forwardDescription"] = ""
    df["forwardRemedy"] = ""

    # Loop through each row in the dataframe
    for index, row in df.iterrows():
        forwarding_outcome = row["forwardingOutcome"]
        security_outcome = row["securityOutcome"]

        # Check if the forwarding outcome exists in the forwardingOutcomes dictionary
        if forwarding_outcome in forwardingOutcomes:
            description = forwardingOutcomes[forwarding_outcome]["description"]
            remedy = forwardingOutcomes[forwarding_outcome]["remedy"]

            df.at[index, "forwardDescription"] = description
            df.at[index, "forwardRemedy"] = remedy

        if security_outcome in securityOutcomes:
            description = securityOutcomes[security_outcome]["description"]
            remedy = securityOutcomes[security_outcome]["remedy"]
            df.at[index, "securityDescription"] = description
            df.at[index, "securityRemedy"] = remedy
    return df[
        [
            "region",
            "application",
            "srcIp",
            "dstIp",
            "ipProto",
            "dstPort",
            "forwardingOutcome",
            "securityOutcome",
            "pathCount",
            "forwardHops",
            "returnPathCount",
            "returnHops",
            "forwardDescription",
            "forwardRemedy",
            "securityDescription",
            "securityRemedy",
            "queryUrl",
        ]
    ]


def remove_columns(df, columns):
    return df.drop(columns, axis=1)


def update_font(f):
    workbook = load_workbook(f)
    worksheet = workbook.active
    font = Font(size=14)  # Set font size to 14
    for row in worksheet.iter_rows():
        for cell in row:
            cell.font = font
    workbook.save(f)


def check_info_paths(data):
    for element in data:
        info = element.get("info", {})
        paths = info.get("paths", [])
        element["pathCount"] = len(paths)

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


async def fetch(session, url, data):
    async with session.post(
        url, auth=aiohttp.BasicAuth(username, password), headers=headers_seq, json=data
    ) as response:
        return await response.read(), response.status


async def process_input(appserver, snapshot, obj):
    async with aiohttp.ClientSession() as session:
        dfs = []  # List to store individual dataframes
        for region, data in obj.items():
            for application, app in data.items():
                queries = []
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
                        }
                        queries.append(query)

                query_list_df = pd.DataFrame(queries)
                query_list_df["region"] = region
                query_list_df["application"] = application
                body = {"queries": queries, **options}
                url = f"https://{appserver}/api/snapshots/{snapshot}/pathsBulkSeq"
                response_text, response_status = await fetch(session, url, body)

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

                r = pd.json_normalize(
                    fix_data,
                    record_path=["info", "paths"],
                    meta=[
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
                newdf = remove_columns(merged_df, ["hops"])

                dfs.append(newdf)
        return pd.concat(dfs, ignore_index=True)


def main(appserver, snapshot, data):
    result = asyncio.run(process_input(appserver, snapshot, data))
    updatedf = addForwardingOutcomes(result)
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
                "pathCount",
                "forwardHops",
                "returnPathCount",
                "returnHops",
            ]
        ]
    )
    updatedf.to_excel("intent-gen.xlsx", index=True)
    update_font("intent-gen.xlsx")


if __name__ == "__main__":
    arguments = docopt(__doc__)
    infile = arguments["<input>"]
    appserver = arguments["<appserver>"]
    snapshot = arguments["<snapshot>"]
    with open(infile) as file:
        data = json.load(file)
    main(appserver, snapshot, data)

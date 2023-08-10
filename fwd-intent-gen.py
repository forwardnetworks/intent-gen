#     ______                                         __
#    / ____/____   _____ _      __ ____ _ _____ ____/ /
#   / /_   / __ \ / ___/| | /| / // __ `// ___// __  /
#  / __/  / /_/ // /    | |/ |/ // /_/ // /   / /_/ /
# /_/ _   \____//_/__   |__/|__/ \__,_//_/    \__,_/
#    / | / /___   / /_ _      __ ____   _____ / /__ _____
#   /  |/ // _ \ / __/| | /| / // __ \ / ___// //_// ___/
#  / /|  //  __// /_  | |/ |/ // /_/ // /   / ,<  (__  )
# /_/ |_/ \___/ \__/  |__/|__/ \____//_/   /_/|_|/____/

# Discalimer:

# This software is provided as is, without any warranty or support. Use of the software is at your own risk. 
# The author and any contributors will not be held responsible for any damages or issues that may arise from 
# the use of this software.

# Please be aware that this software may contain bugs, errors, or other issues. 
# It may not function as intended or be fit for your specific use case.

# By using this software, you acknowledge and accept the above disclaimer and assume 
# all responsibility for any issues that may arise from its use. 

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Copyright 2023 Forward Networks, Inc.
# All rights reserved.





"""
Usage:
  fwd-intent-gen.py from_import <input> <appserver> <snapshot> [--batch=<batch_size>] [--limit=<limit>] [--max=<max_query>] [--withdiag] [--debug]
  fwd-intent-gen.py from_acls <appserver> <snapshot>   [--batch=<batch_size>] [--limit=<limit>] [--max=<max_query>] [--withdiag] [--debug]
  fwd-intent-gen.py check <input> <appserver> <snapshot> [--csv] [--debug]

Options:
  -h --help             Show this help message
  --batch=<batch_size>  Configure batch size [default: 300]
  --csv                 "Dump into CSV file for import"
  --debug               "Set Debug Flag [default: False]"
  --limit=<limit>       "Limit to n applications (ACL-names) [default: 1000]
  --max=<max_query>    "Max queries [default: 10000]
"""

import math
import re
import socket
import sys
import traceback
import pandas as pd
import aiohttp
import asyncio
import json
import os
from docopt import docopt
from openpyxl.styles import Font
from openpyxl import load_workbook
import requests
import logging
import glob
import datetime
from tqdm import tqdm

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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

acl_query = """
getAcl =
  foreach device in network.devices
  foreach aclEntry in device.aclEntries
  select {
    sources: (foreach s in aclEntry.headerMatches.ipv4Src
              select s),
    destinations: (foreach d in aclEntry.headerMatches.ipv4Dst
                   select d),
    action:    when aclEntry.action is
                       DENY -> "DENY";
                       PBR -> "PBR";
                       PERMIT -> "PERMIT",
    protocols: (foreach t in aclEntry.headerMatches.ipProtocol select {start: t.start, end: t.end}),
    dstports: (foreach p in aclEntry.headerMatches.tpDst select {start: p.start, end: p.end}),
    name: aclEntry.name
  };

getHosts =
  foreach d in network.devices
  foreach hosts in d.hosts
  foreach host in hosts.addresses
  select host;

foreach x in [0]
let acls = distinct(getAcl())
let hosts = getHosts()
foreach acl in acls
foreach host in hosts
where host in acl.sources || host in acl.destinations
group acl as a
  by { name: acl.name,
       src: acl.sources,
       dst: acl.destinations,
       protos: acl.protocols,
       dstPorts: acl.dstports,
       hostCount: length(hosts)
    }
    as b
select distinct { application: b.name, sources: b.src, destinations: b.dst, protocols: b.protos, dstPorts: b.dstPorts}
"""

host_query = """ 
foreach device in network.devices
foreach host in device.hosts
where length(host.addresses) == 1
foreach hostSubnet in host.addresses
where length(hostSubnet) == 32
foreach interface in host.interfaces
where host.hostType == DeviceHostType.InferredHost
select {
  deviceName: device.name,
  Address: address(hostSubnet),
  MacAddress: host.macAddress,
  OUI: if isPresent(host.macAddress) then ouiAssignee(host.macAddress) else "",
  HostType: host.hostType,
  Interface: interface,
}
"""

options = {
    "intent": "PREFER_DELIVERED",
    "maxCandidates": 5000,
    "maxResults": 1,
    "maxReturnPathResults": 1,
    "maxSeconds": 30,
    "maxOverallSeconds": 60,
    "includeNetworkFunctions": False,
}

headers_seq = {
    "Accept": "application/json-seq",
    "Content-Type": "application/json",
}

headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
}

# Utilities


def test_communication(appserver):
    try:
        response = requests.get(f"https://{appserver}", timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"HTTP communication failed with {appserver}.")
        sys.exit(1)


def flatten_input(data):
    rows = []
    for region, apps in data.items():
        for app, details in apps.items():
            rows.append(
                [
                    region,
                    app,
                    details["source"],
                    details["destination"],
                    details["ipProto"],
                    details["dstPorts"],
                ]
            )
    return pd.DataFrame(
        rows,
        columns=[
            "region",
            "application",
            "sources",
            "destinations",
            "protocols",
            "dstPorts",
        ],
    )


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


def parse_start_end(s):
    pattern = r"start:(\d+), end:(\d+)"
    match = re.search(pattern, s)
    if match:
        start_value = match.group(1)
        end_value = match.group(2)
        if start_value == end_value:
            return start_value
        else:
            return f"{start_value}-{end_value}"


def resolve_ip_to_domain(ip_address):
    try:
        domain_name = socket.gethostbyaddr(ip_address)[0]
        return domain_name
    except socket.herror as e:
        return ip_address


# API


def nqe_get_hosts_from_acl(query, appserver, snapshot):
    url = f"https://{appserver}/api/nqe?snapshotId={snapshot}"
    body = {"query": query, "queryOptions": {"limit": 10000}}

    response = requests.post(
        url, json=body, auth=(username, password), headers=headers, verify=False
    )

    response_text = response.text
    response_status = response.status_code

    if response_status == 200:
        response_json = response.json()["items"]
    elif response_status == 401 or response_status == 403:
        print("Please set FWD_USER and FWD_PASSWORD to authentication credentials")
        sys.exit(1)
    elif response_status == 401 or response_status == 409:
        print("Snapshot is being processed, try again in a few")
        sys.exit(1)
    else:
        raise

    return response_json


# Get the username and password from environment variables.
username = os.getenv("FWD_USER")
password = os.getenv("FWD_PASSWORD")

# Set Debug if needed
debug = True if os.getenv("DEBUG") else False

if not username or not password:
    print("Please provide both FWD_USER and FWD_PASSWORD.")
    sys.exit()


def return_firstlast_hop(df):
    new_df = df.copy()
    # Extract values using apply()
    (
        new_df["firstHopDevice"],
        new_df["firstHopDeviceType"],
        new_df["lastHopDevice"],
        new_df["lastHopDeviceType"],
        new_df["lastHopEgressIntf"],
    ) = zip(
        *new_df["hops"].apply(
            lambda hops: (
                hops[0]["deviceName"],
                hops[0]["deviceType"],
                hops[-1]["deviceName"],
                hops[-1]["deviceType"],
                hops[-1].get("egressInterface"),
            )
            if isinstance(hops, list) and len(hops) > 0
            else (None, None, None, None, None)
        )
    )

    # Remove the "hops" column
    new_df = new_df.drop(columns=["hops"])

    return new_df

def addForwardingOutcomes(result):

    result['forwardingDescription'] = result['forwardingOutcome'].apply(lambda x: forwardingOutcomes[x]["description"] if x in forwardingOutcomes else None)
    result['forwardingRemedy'] = result['forwardingOutcome'].apply(lambda x: forwardingOutcomes[x]["remedy"] if x in forwardingOutcomes else None)
    result['securityDescription'] = result['securityOutcome'].apply(lambda x: securityOutcomes[x]["description"] if x in securityOutcomes else None)
    result['securityRemedy'] = result['securityOutcome'].apply(lambda x: securityOutcomes[x]["remedy"] if x in securityOutcomes else None)

    return result



def check_info_paths(data):
    for element in data:
        info = element.get("info", {})
        paths = info.get("paths", [])
        element["pathCount"] = len(paths)
        timedOut = element.get("timedOut")
        if timedOut:
            raise Exception("Timed out")
        srcIpLocationType = element.get("srcIpLocationType", "UNKNOWN")
        dstIpLocationType = element.get("dstIpLocationType", "UNKNOWN")

        paths = paths or [
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
        else:
            element["returnPathCount"] = 0
            element["returnHops"] = 0
            return_paths = [
                {
                    "forwardingOutcome": "NOT_DELIVERED",
                    "securityOutcome": "UNKNOWN",
                    "hops": [],
                }
            ]
        element["returnPathInfo"] = {"paths": return_paths}

    return data


def parse_subnets(data):
    origin_descriptions = {
        "HOST": {"description": "Host Interface", "data_key": "hosts"},
        "INTERFACE": {"description": "Device Interface", "data_key": "interfaces"},
        "INTERFACE_ATTACHED_SUBNET": {
            "description": "Incorrect device address",
            "data_key": None,
        },
        "UNKNOWN": {"description": "UNKNOWN", "data_key": None},
    }

    parsed_data = [
        {
            "address": item["address"],
            "origin": item.get("origin", "ERROR"),
            "description": origin_descriptions.get(item.get("origin", "ERROR"), {}).get(
                "description", "INVALID"
            ),
            "status": "VALID"
            if item.get("origin") in origin_descriptions
            else "INVALID",
            "data": item.get(
                origin_descriptions.get(item.get("origin", {}), {}).get("data_key")
            ),
        }
        if "origin" in item and "address" in item
        else {
            "address": item.get("address"),
            "origin": "ERROR",
            "description": "Address not found in network model",
            "status": "INVALID",
            "data": None,
        }
        for item in data
    ]

    return parsed_data


async def fetch(
    session,
    url,
    data=None,
    method="GET",
    username=None,
    password=None,
    headers={},
    timeout=60,
):
    auth = aiohttp.BasicAuth(username, password) if username and password else None
    try:
        if method == "GET":
            async with session.get(
                url, auth=auth, params=data, headers=headers, ssl=False, timeout=timeout
            ) as response:
                return await response.read(), response.status
        elif method == "POST":
            async with session.post(
                url, auth=auth, headers=headers, json=data, ssl=False, timeout=timeout
            ) as response:
                return await response.read(), response.status
        else:
            raise ValueError(f"Invalid HTTP method: {method}")
    except (
        aiohttp.client_exceptions.ClientConnectorError,
        aiohttp.client_exceptions.ClientOSError,
        asyncio.TimeoutError,
    ) as e:
        raise e


def fixup_queries(input):
    queries = []
    for region, data in input.items():
        for application, app in data.items():
            sources = app.get("source", [])
            destinations = app.get("destination", [])
            ipProto = app.get("ipProto", [])
            dstPorts = app.get("dstPorts", [])

            queries.extend(
                [
                    {
                        "srcIp": source,
                        "dstIp": destination,
                        "ipProto": ipProto,
                        "dstPort": dstPorts,
                        "application": application,
                        "region": region,
                    }
                    for source in sources
                    for destination in destinations
                ]
            )
    return queries


def error_queries(input, address_df):
    invalid_addresses = set()

    for region, data in input.items():
        for application, app in data.items():
            sources = set(app.get("source", []))
            destinations = set(app.get("destination", []))

            addresses = sources.union(destinations)
            invalid_addresses.update(
                addresses
                - set(address_df.loc[address_df["status"] == "VALID", "address"])
            )

    error_df = address_df[address_df["address"].isin(invalid_addresses)].copy()
    error_df["hostname"] = error_df["address"].apply(resolve_ip_to_domain)

    error_messages = error_df.apply(
        lambda row: f"Error occurred. Address: {row['address']}, Name: {row['hostname']}, Origin: {row['origin']} Status: {row['status']}, Description: {row['description']}",
        axis=1,
    )

    print("\nErrors:\n")
    print("\n".join(error_messages))

    return error_df


async def process_input(
    appserver, snapshot, input_df, batch_size, max_query, address_df=None
):
    async with aiohttp.ClientSession() as session:
        dfs = []  # List to store individual dataframes
        for index, row in input_df.iterrows():
            region = row["region"]
            sources = row["sources"]
            destinations = row["destinations"]
            protocols = row["protocols"]
            dstPorts = row["dstPorts"]
            application = row["application"]

            # check hosts are locatable if from external input
            if address_df is not None:
                filtered_queries = [
                    {
                        "srcIp": source,
                        "dstIp": destination,
                        "ipProto": protocols,
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
            else:
                filtered_queries = [
                    {
                        "srcIp": source,
                        "dstIp": destination,
                        **(
                            {"ipProto": protocols}
                            if not re.match(r"\d+-\d+", protocols)
                            else {}
                        ),
                        **({"dstPort": dstPorts} if protocols in ["6", "17"] else {}),
                    }
                    for source in sources
                    for destination in destinations
                ]

            query_list_df = pd.DataFrame(filtered_queries)

            if debug:
                print(f"\nDEBUG: QueryList\n{query_list_df}")

            query_list_df["region"] = region
            query_list_df["application"] = application
            # configure query limit
            total_queries = min(len(filtered_queries), max_query)

            print(
                f"\n{index}: | Region: {region} | Application: {application} | Search Count: {total_queries}/{len(filtered_queries)}\n"
            )

            if total_queries > 0:
                num_batches = math.ceil(total_queries / batch_size)
                for i in tqdm(range(num_batches), desc="Search"):
                    start_index = i * batch_size
                    end_index = min((i + 1) * batch_size, total_queries)
                    batch_queries = filtered_queries[start_index:end_index]
                    body = {"queries": batch_queries, **options}

                    url = f"https://{appserver}/api/snapshots/{snapshot}/pathsBulkSeq"
                    try:
                        response_text, response_status = await fetch(
                            session,
                            url,
                            body,
                            method="POST",
                            username=username,
                            password=password,
                            headers=headers_seq,
                        )
                    except asyncio.TimeoutError:
                        print("Request timed out. Skipping to next iteration.")
                        continue
                    await asyncio.sleep(3)

                    parsed_data = []
                    # Check if the request was successful.
                    if response_status != 200:
                        print(
                            f"Request failed with status code: {response_status}\n result: {response_text}\n body: {body}"
                        )
                        continue

                    lines = response_text.decode().split("\x1E")
                    parsed_data.extend(json.loads(line) for line in lines if line)
                    # Cleanup for dataframe import
                    try:
                        fix_data = check_info_paths(parsed_data)
                    except Exception as e:
                        print(f"Error occurred while checking info paths: {e}")
                        continue

                    paths_df = pd.json_normalize(
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
                    logging.info("paths_df")
                    logging.warning(paths_df.iloc[0])
                    merged_df = pd.merge(
                        paths_df, query_list_df, left_index=True, right_index=True
                    )
                    merged_df.to_csv(f"./cache/intent_{index}_{i}.csv", index=False)
                    logging.info("merged_df")
                    logging.warning(merged_df.iloc[0])
                    dfs.append(merged_df)

    if len(dfs) > 0:
        return pd.concat(dfs, ignore_index=True)


def search_address(input):
    addresses = {
        a
        for region_value in input.values()
        for service_value in region_value.values()
        if isinstance(service_value, dict)
        for key, value in service_value.items()
        if key in ["source", "destination"]
        for a in value
    }
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
                "limit": 10000,
            },
        }
        try:
            response_text, response_status = await fetch(
                session,
                url,
                body,
                method="POST",
                username=username,
                password=password,
                headers=headers,
            )
        except asyncio.exceptions.TimeoutError:
            print("Request timed out. Retrying...")
            return await nqe_get_hosts_by_port(
                queryId, appserver, snapshot, device, port
            )

        if response_status == 200:
            response_json = json.loads(response_text)
            return response_json["items"]
        elif response_status in [401, 403]:
            print(
                "Please set environment for FWD_USER, FWD_PASSWORD to your credentials"
            )
            sys.exit(1)
        else:
            print(f"Error: {response_status} {response_text}")
            return None


async def run_process_input(
    appserver, snapshot, acls_df, batchsize, max_query, retries=3
):
    for retry in range(retries):
        try:
            return await process_input(
                appserver, snapshot, acls_df, batchsize, max_query
            )
        except asyncio.TimeoutError:
            print(f"Timeout error, retrying in {2 ** retry} seconds...")
            await asyncio.sleep(2**retry)
            if retry > retries:
                print("Max retries exceeded. Continuing to next iteration.")
                continue

async def nqe_get_hosts_by_port_2(appserver, snapshot):
    print(f"Gathering Hosts Details...")
    async with aiohttp.ClientSession() as session:
        url = f"https://{appserver}/api/nqe?snapshotId={snapshot}"
        body = {"query": host_query, "queryOptions": {"limit": 10000}}
        try:
            response_text, response_status = await fetch(
                session,
                url,
                body,
                method="POST",
                username=username,
                password=password,
                headers=headers,
            )
        except asyncio.exceptions.TimeoutError:
            raise

        if response_status == 200:
            response_json = json.loads(response_text)
            df = pd.DataFrame(response_json["items"])
            df.to_csv("./cache/hosts.csv")
            return response_json["items"]
        else:
            raise Exception(f"Error: {response_status} {response_text}")


async def search_subnet(appserver, snapshot, dataframe):
    result_list = []  # List to store the response JSON for each address
    async with aiohttp.ClientSession() as session:
        addresses = []
        for row in dataframe.itertuples():
            addresses.extend(row.sources)
            addresses.extend(row.destinations)
        addresses = list(set(addresses))  # remove duplicates

        for address in addresses:
            url = f"https://{appserver}/api/snapshots/{snapshot}/subnets"
            params = {"address": address, "minimal": "true"}
            try:
                response_text, response_status = await fetch(
                    session,
                    url,
                    params,
                    method="GET",
                    username=username,
                    password=password,
                    headers=headers,
                )
            except asyncio.exceptions.TimeoutError:
                print("Request timed out. Skipping to next iteration.")
                continue

            if response_status == 200:
                response_json = json.loads(response_text)
                response_json["address"] = address
                result_list.append(response_json)
            elif response_status == 403:
                print("Warning: Status 403. Please set FWD_USER and FWD_PASSWORD.")
                sys.exit(1)
            else:
                raise Exception(f"Error: {response_status}")

    parsed_data = parse_subnets(result_list)
    df = pd.DataFrame(parsed_data)
    return df


async def gather_results(
    appserver, snapshot, acls_df, batchsize, max_query, retries, address_df=None
):
    try:
        results = await asyncio.gather(
            nqe_get_hosts_by_port_2(appserver, snapshot),
            process_input(
                appserver, snapshot, acls_df, batchsize, max_query, address_df
            ),
        )
        return results
    except Exception as e:
        print(f"Error occurred: {e}")
        logging.error(f"Error occurred: {e}")
        raise


def generate_report(snapshot, intent, hosts, with_diag=False):
    report = f"intent-gen-{snapshot}.csv"
    forwarding_outcomes = addForwardingOutcomes(intent)
    updatedf = return_firstlast_hop(forwarding_outcomes)

    # print(f"DEBUG: {hosts}")

    for index, row in tqdm(updatedf.iterrows(), desc="Processing Data"):

        device = updatedf.at[index, "lastHopDevice"]
        interface = updatedf.at[index, "lastHopEgressIntf"]
        forwardingOutcome = updatedf.at[index, "forwardingOutcome"]
        outcomes = ["DELIVERED", "NOT_DELIVERED"]

        if (
            device
            and forwardingOutcome
            and interface
            and forwardingOutcome not in outcomes
            and not bool(re.match(r"^self\..*", interface))
        ):
            host = hosts[(hosts["deviceName"] == device) & (hosts["Interface"] == interface)]
            if not host.empty:
                updatedf.at[index, "hostAddress"] = host["Address"].values[0]
                updatedf.at[index, "MacAddress"] = host["MacAddress"].values[0]
                updatedf.at[index, "OUI"] = host["OUI"].values[0]
                updatedf.at[index, "hostInterface"] = host["Interface"].values[0]
                logging.info(f"Updated host details for device: {device} and interface: {interface}")
            else:
                logging.warning(f"No host details found for device: {device} and interface: {interface}")
        else:
            updatedf.at[index, "hostAddress"] = None
            updatedf.at[index, "MacAddress"] = None
            updatedf.at[index, "OUI"] = None
            updatedf.at[index, "hostInterface"] = None
            logging.warning(f"No device or interface details found for device: {device} and interface: {interface}")



    columns_to_display = [
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
        "lastHopDevice",
        "lastHopEgressIntf",
        "hostAddress",
        "MacAddress",
        "OUI",
        "hostInterface",
    ]

    print(updatedf[columns_to_display])

    # Excel has a max row limit of 1048576
    # updatedf = updatedf.head(1048575)

    
    try:
        if with_diag:
            updatedf[
                columns_to_display
                + [
                    "queryUrl",
                    "forwardDescription",
                    "forwardRemedy",
                    "securityDescription",
                    "securityRemedy",
                ]
            ].to_csv(report, index=False)
        else:
            updatedf[
                columns_to_display
                + [
                    "queryUrl",
                ]
            ].to_csv(report, index=False)
    except Exception as e:
        print(f"Error occurred while writing to CSV: {e}")
        raise
    # update_font(report)



def from_import(
    appserver, snapshot, infile, batchsize, limit, max_query, retries, with_diag
):
    print(f"Setting batch size: {batchsize}")
    print(f"Setting limit: {limit}")
    print(f"Setting max querys: {max_query}")

    test_communication(appserver)

    if debug:
        pd.set_option("display.max_rows", None)  # Show all rows

    with open(infile) as file:
        data = json.load(file)

    app_df = flatten_input(data)
    address_df = asyncio.run(search_subnet(appserver, snapshot, app_df))

    try:
        app_df.sort_values(by="application")

        # Fix list
        for column in app_df.columns:
            if app_df[column].apply(lambda x: isinstance(x, list)).any():
                app_df[column] = app_df[column].apply(tuple)

        app_df.drop_duplicates(inplace=True)
        print(f"APP Entries Found: {len(app_df)}\n")

        # add limiter for testing
        if limit:
            app_df = app_df.head(limit)

        if debug:
            print(app_df)

        import datetime

        start_time = datetime.datetime.now()
        print(f"Start time: {start_time}")
        logging.info(f"Start time: {start_time}")
        try:
            results = asyncio.run(
                gather_results(
                    appserver,
                    snapshot,
                    app_df,
                    batchsize,
                    max_query,
                    retries,
                    address_df,
                )
            )
            if results is not None:
                hosts = results[0]
                intent = results[1]
        except aiohttp.ClientOSError:
            pass
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            raise

        print(f"End time: {datetime.datetime.now()}")
        logging.info(f"End time: {datetime.datetime.now()}")

        generate_report(snapshot, intent, hosts, with_diag)

    except Exception as e:
        print(f"An error occurred: {e}")
        print(traceback.format_exc())

        logging.error(f"An error occurred: {e}")
        logging.error(traceback.format_exc())

        return


def from_acls(
    appserver, snapshot, batchsize, limit, max_query, retries, with_diag=False
):
    print(f"Setting batch size: {batchsize}")
    print(f"Setting limit: {limit}")
    print(f"Setting max querys: {max_query}")

    report = f"intent-gen-{snapshot}.xlsx"
    if debug:
        pd.set_option("display.max_rows", None)  # Show all rows

    try:
        # Retrieve all possible ACLs where a source or destination is locatable in the model
        test_communication(appserver)
        data = nqe_get_hosts_from_acl(acl_query, appserver, snapshot)
        acls_df = pd.DataFrame(data)
        if len(acls_df) == 0:
            print("No ACL names found")
            return

        if debug:
            print(acls_df)

        acls_df.sort_values(by="application")

        # Add region to conform to input specification
        acls_df["region"] = "Default"

        # Fixup port ranges from input
        acls_df["dstPorts"] = acls_df["dstPorts"].apply(parse_start_end)
        acls_df["protocols"] = acls_df["protocols"].apply(parse_start_end)

        # Fix list
        for column in acls_df.columns:
            if acls_df[column].apply(lambda x: isinstance(x, list)).any():
                acls_df[column] = acls_df[column].apply(tuple)

        acls_df.drop_duplicates(inplace=True)
        print(f"ACL Entries Found: {limit}/{len(acls_df)}\n")

        # add limiter for testing
        if limit:
            acls_df = acls_df.head(limit)

        if debug:
            print(acls_df)

        start_time = datetime.datetime.now()
        print(f"Start time: {start_time}")
        logging.info(f"Start time: {start_time}")
        try:
            results = asyncio.run(
                gather_results(
                    appserver, snapshot, acls_df, batchsize, max_query, retries
                )
            )
            if results is not None:
                hosts = pd.DataFrame(results[0])
                intent = pd.DataFrame(results[1])
                logging.warning(hosts.columns)

                

        except KeyboardInterrupt:
            print("Interrupted by user, continuing with available data...")
            # Get a list of all the csv files
            hosts = pd.read_csv("./cache/hosts.csv")
            csv_files = glob.glob("./cache/intent_*.csv")
            intent = pd.concat([pd.read_csv(f) for f in csv_files], ignore_index=True)
        except asyncio.TimeoutError:
            print("Operation timed out. Recovering from the persisted dataframe...")
            hosts = pd.read_csv("./cache/hosts.csv")
            csv_files = glob.glob("./cache/intent_*.csv")
            intent = pd.concat([pd.read_csv(f) for f in csv_files], ignore_index=True)
        except aiohttp.ClientOSError:
            print("Operation timed out. Recovering from the persisted dataframe...")
            csv_files = glob.glob("./cache/intent_*.csv")
            hosts = pd.read_csv("./cache/hosts.csv")
            intent = pd.concat([pd.read_csv(f) for f in csv_files], ignore_index=True)

        print(f"Collection End: {datetime.datetime.now()}")
        logging.info(f"Collection End: {datetime.datetime.now()}")

        generate_report(snapshot, intent, hosts, with_diag)

    except Exception as e:
        print(f"An error occurred: {e}")
        print(traceback.format_exc())
        logging.error(f"An error occurred: {e}")
        logging.error(traceback.format_exc())


def check(appserver, snapshot, infile, csv):
    report = f"errored-devices-{snapshot}.csv"

    test_communication(appserver)

    if debug:
        pd.set_option("display.max_rows", None)  # Show all rows

    with open(infile) as file:
        data = json.load(file)

    app_df = flatten_input(data)
    address_df = asyncio.run(search_subnet(appserver, snapshot, app_df))

    try:
        address_df = asyncio.run(search_subnet(appserver, snapshot, app_df))
    except Exception as e:
        print(f"Error occurred while searching subnet: {e}")
        return

    try:
        errored_devices = error_queries(data, address_df)
    except Exception as e:
        print(f"Error occurred while querying errors: {e}")
        return

    if csv:
        errored_devices.loc[:, ["address", "hostname"]].to_csv(report, index=False)


def main():
    arguments = docopt(__doc__)
    infile = arguments["<input>"]
    appserver = arguments["<appserver>"]
    snapshot = arguments["<snapshot>"]
    batchsize = int(arguments["--batch"])
    limit = int(arguments["--limit"])
    max_query = int(arguments["--max"])
    with_diag = arguments["--withdiag"]
    global debug
    debug = arguments["--debug"]
    print(f"Debug: {debug}")
    retries = 3
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    logging.basicConfig(filename=f"fwd-intent-gen-{timestamp}.log", level=logging.INFO)

    if not os.path.exists("./cache"):
        os.makedirs("./cache")

    # Check for existing intent*.csv files in ./cache directory
    csv_files = glob.glob("./cache/intent_*.csv")
    if csv_files:
        print("Found existing intent*.csv files in ./cache directory.")
        purge = input("Do you want to purge these results? (yes)/no: ")
        if purge.lower() == "yes" or purge == "":
            for file in tqdm(csv_files, desc="Purging cache"):
                os.remove(file)
        else:
            csv_files = glob.glob("./cache/intent_*.csv")
            intent = pd.concat([pd.read_csv(f) for f in csv_files], ignore_index=True)
            intent['hops'] = intent['hops'].apply(lambda x: json.loads(x.replace("'", '"')))

            print(f"Total rows in intent: {len(intent)}")

            hosts = pd.read_csv("./cache/hosts.csv")
            generate_report("cache", intent, hosts, with_diag)
            return

    if arguments["from_import"]:
        print("Running: from_import")

        from_import(
            appserver, snapshot, infile, batchsize, limit, max_query, retries, with_diag
        )

    elif arguments["check"]:
        print("Running: Check")
        infile = arguments["<input>"]
        appserver = arguments["<appserver>"]
        snapshot = arguments["<snapshot>"]
        csv = arguments["--csv"]

        check(appserver, snapshot, infile, csv)

    elif arguments["from_acls"]:
        print("Running: from_acls")
        appserver = arguments["<appserver>"]
        snapshot = arguments["<snapshot>"]
        batchsize = int(arguments["--batch"])
        limit = int(arguments["--limit"])
        max_query = int(arguments["--max"])
        with_diag = arguments["--withdiag"]
        from_acls(appserver, snapshot, batchsize, limit, max_query, retries, with_diag)

    else:
        print(
            "Invalid command. Please refer to the usage message for available commands."
        )

if __name__ == "__main__":
    main()

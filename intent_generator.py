import pandas as pd
import argparse
import aiohttp
import asyncio
import json
import os

options = {
  "intent": "PREFER_DELIVERED",
  "maxCandidates": 5000,
  "maxResults": 1,
  "maxReturnPathResults": 1,
  "maxSeconds": 30,
  "maxOverallSeconds": 300,
  "includeNetworkFunctions": False
}

def remove_columns(df, columns):
    return df.drop(columns, axis=1)


def check_info_paths(data):
    for element in data:
        if 'info' in element and 'paths' in element['info']:
            if not element['info']['paths']:
                element['info']['paths'] = [{'forwardingOutcome': 'NOTDELIVERED', 'securityOutcome': 'UNKNOWN', 'hops': []}]
            else:
                element['pathCount'] = len(element['info']['paths'])
                element['forwardHops'] = len(element['info']['paths'][0]['hops'])
        else:
            element['info'] = {'paths': []}
        
        if 'returnPathInfo' in element and 'paths' in element['returnPathInfo']:
            if element['returnPathInfo']['paths']:
                element['returnHops'] = len(element['returnPathInfo']['paths'][0]['hops'])
                element['returnPathCount'] = len(element['returnPathInfo']['paths'])
            else:
                element['returnPathInfo']['paths'] = [{'forwardingOutcome': 'NOTDELIVERED', 'securityOutcome': 'UNKNOWN', 'hops': []}]
        else:
            element['returnPathInfo'] = {'paths': []}

    return data

# Get the username and password from environment variables.
username = os.getenv('FWD_USER')
password = os.getenv('FWD_PASSWORD')

headers_seq = {
    'Accept': 'application/json-seq',
    'Content-Type': 'application/json',
}

# Parse the command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("input", help="input JSON file")
args = parser.parse_args()

# Read the input file
with open(args.input) as file:
    data = json.load(file)

async def fetch(session, url, data):
    async with session.post(url,
                            auth=aiohttp.BasicAuth(username, password),
                            headers=headers_seq,
                            json=data) as response:
        return await response.read(), response.status

async def process_input(obj):
    async with aiohttp.ClientSession() as session:
        for region, data in obj.items():
            queries = []
            sources = data.get("source", [])
            destinations = data.get("destination", [])
            ipProto = data.get("ipProto", [])
            dstPorts = data.get("dstPorts", [])

            print(f"Region: {region}")
            print(f"Search Count: {len(sources) * len(destinations)}")

            for source in sources:
                for destination in destinations:
                    query = {
                        "srcIp": source,
                        "dstIp": destination,
                        "ipProto": ipProto,
                        "dstPort":  dstPorts
                    }
                    queries.append(query)

            query_list_df = pd.DataFrame(queries)
            query_list_df['region'] = region
            body =  {"queries": queries, **options}
            response_text, response_status = await fetch(session, 'https://fwd.app/api/snapshots/627174/pathsBulkSeq', body)

            parsed_data = []
            # Check if the request was successful.
            if response_status != 200:
                raise aiohttp.ClientResponseError(request_info=None, history=None, status=response_status, message="Request failed")
            lines = response_text.decode().split('\x1E')
            parsed_data.extend(json.loads(line) for line in lines if line)
            # Cleanup for dataframe import
            fix_data = check_info_paths(parsed_data)

            r = pd.json_normalize(
                fix_data, 
                record_path=['info', 'paths'],
                meta=['forwardHops','returnHops', 'pathCount', 'returnPathCount','queryUrl'],
                errors='ignore'
            )
            merged_df = pd.merge(r, query_list_df, left_index=True, right_index=True)
            newdf = remove_columns(merged_df, ['hops'])
            reorderdf = newdf[['region', 'srcIp', 'dstIp', 'ipProto', 'dstPort',  'forwardingOutcome', 'securityOutcome', 'pathCount', 'forwardHops', 'returnPathCount','returnHops', 'queryUrl']]
            print(f"-> {reorderdf}")
            reorderdf.to_excel(f"{region}.xlsx", index=True)

# main
loop = asyncio.get_event_loop()
loop.run_until_complete(process_input(data))

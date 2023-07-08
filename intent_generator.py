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
  "maxReturnPathResults": 0,
  "maxSeconds": 30,
  "maxOverallSeconds": 300,
  "includeNetworkFunctions": False
}

def pretty_print_dict(dictionary, indent=0):
    for key, value in dictionary.items():
        if isinstance(value, dict):
            print(' ' * indent + str(key) + ':')
            pretty_print_dict(value, indent + 4)
        else:
            print(' ' * indent + str(key) + ': ' + str(value))

def remove_columns(df, columns):
    return df.drop(columns, axis=1)

def check_key_exists(df, key):
    return df.apply(lambda row: key in row.keys(), axis=1)

def check_empty_array(df, column_name):
    return df[column_name].apply(lambda x: len(x) == 0)

def copy_columns(df1,df2, columns):
    df2[columns] = df1[columns].copy()

def process_object(obj):
    print(obj)
    print() # print a new line just as a record separator

def check_info_paths(data):
    for element in data:
        if 'info' in element and 'paths' in element['info'] and not element['info']['paths']:
            element['hopfix'] = len(element['info']['paths'])
        if (
            'returnPathInfo' not in element
            or 'paths' not in element['returnPathInfo']
            or element['returnPathInfo']['paths']
        ):
            element['hopfix'] = len(element['info']['paths'])
        element['hopfix'] = len(element['info']['paths'])
        element['hopfix'] = len(element['info']['paths'])
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
                    queries['hopfix'] = (query)

            query_list_df = pd.DataFrame(queries)
            # print(query_list_df)
            # print(queries)
            # Call request.post for each region using aiohttp
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

            print(fix_data)

            r = pd.json_normalize(
                fix_data, 
                # record_path=['info', 'paths'],
                # meta=['hopfix''],
                # errors='ignore'
            )
            merged_df = pd.merge(r, query_list_df, left_index=True, right_index=True)
            print(merged_df.columns)
            print(f"-> {merged_df}")

            # for index, row in merged_df.iterrows():
            #     if (len(row['info.paths']) == 0):
            #         print(f"found error {index}")
            #         merged_df.at[index, 'forwardOutcome'] = "NOPATH"
            #         merged_df.at[index, 'securityOutcome'] = "UNKNOWN"
            #         print(merged_df)
            #     # copy_columns(merged_df,df, ['srcIp','dstIp','ipProto', 'dstPort','forwardOutcome','securityOutcome'])
            #     else:
            #         merged_df.at[index, 'forwardOutcome'] = json.dumps(row['info.paths'])
            #         print(row['info.paths'])

            # print(merged_df.columns)
            # print(merged_df)

            # # json_data = merged_df.to_json(orient='records')

            # r = pd.json_normalize(
            #     parsed_data,
            #     record_path=['info', 'paths'],
            #     # meta=['srcIpLocationType','dstIpLocationType']
            #     # errors='ignore'
            # )
            # merged_df = pd.merge(r, query_list_df, left_index=True, right_index=True) 
            # print(merged_df.columns)
            # print(merged_df)

        
        # return parsed_data,query_list_df

# Process input data

# pd.set_option('display.max_rows', None)
# pd.set_option('display.max_columns', None)

loop = asyncio.get_event_loop()
loop.run_until_complete(process_input(data))

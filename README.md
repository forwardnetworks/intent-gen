# intent-gen


```
Usage:
  fwd-intent-gen.py from_import <input> <appserver> <snapshot> [--batch=<batch_size>] [--limit=<limit>] [--max=<max_query>] [--withdiag] [--debug]
  fwd-intent-gen.py from_hosts <appserver> <snapshot>   [--batch=<batch_size>] [--limit=<limit>] [--max=<max_query>] [--withdiag] [--debug]
  fwd-intent-gen.py check <input> <appserver> <snapshot> [--csv] [--debug]

Options:
  -h --help             Show this help message
  --batch=<batch_size>  Configure batch size [default: 300]
  --csv                 "Dump into CSV file for import"
  --debug               "Set Debug Flag [default: False]"
  --limit=<limit>       "Limit to n applications (ACL-names) [default: 1000]
  --max=<max_query>    "Max queries [default: 10000]
```

## Setup

### Credentials: 

The following environmental variables need to be set to local user accounts or API-Token

FWD_USER<BR>
FWD_PASSWORD

## Usage

### Check

Check of addresses belong to a known HOST or device INTERFACE

`python fwd-intent-gen.py check input.json fwd.app 627174`

Dump errors to csv file for import into collection

`python fwd-intent-gen.py check input.json fwd.app 627174 --csv`


### from_import

Execute all checks, results are placed into an .xlsx file called `intent-gen-<snapshot>.xlsx`

`python fwd-intent-gen.py from_import input.json fwd.app 627174`


### from_hosts

`python fwd-intent-gen.py from_hosts fwd.app 642218 --limit 5`


#### Example Output

```
 region application         srcIp         dstIp  ipProto  dstPort forwardingOutcome securityOutcome pathCount forwardHops returnPathCount returnHops
0   AMERS        SNMP  10.6.142.197    10.5.20.11       17      161         DELIVERED          DENIED         1          37               1          1
1   AMERS        SNMP  10.6.142.197    10.5.20.12       17      161         DELIVERED          DENIED         1          37               1          3
2   AMERS        SNMP  10.6.143.197    10.5.20.11       17      161     NOT_DELIVERED         UNKNOWN         0           0               0          0
3   AMERS        SNMP  10.6.143.197    10.5.20.12       17      161     NOT_DELIVERED         UNKNOWN         0           0               0          0
4   AMERS   SNMP_TRAP    10.5.20.11  10.6.142.197       17      162           DROPPED       PERMITTED         1           3               0          0
5   AMERS   SNMP_TRAP    10.5.20.11  10.6.143.197       17      162           DROPPED       PERMITTED         1           3               0          0
6   AMERS   SNMP_TRAP    10.5.20.12  10.6.142.197       17      162           DROPPED       PERMITTED         1           3               0          0
7   AMERS   SNMP_TRAP    10.5.20.12  10.6.143.197       17      162           DROPPED       PERMITTED         1           3               0          0
8    APAC        SNMP  10.6.142.198     10.5.20.1       17  161-162     NOT_DELIVERED         UNKNOWN         0           0               0          0
9    APAC        SNMP  10.6.142.198    10.5.20.12       17  161-162     NOT_DELIVERED         UNKNOWN         0           0               0          0
10   APAC        SNMP  10.6.143.198     10.5.20.1       17  161-162     NOT_DELIVERED         UNKNOWN         0           0               0          0
11   APAC        SNMP  10.6.143.198    10.5.20.12       17  161-162     NOT_DELIVERED         UNKNOWN         0           0               0          0

```


# Discalimer:

This software is provided as is, without any warranty or support. Use of the software is at your own risk. The author and any contributors will not be held responsible for any damages or issues that may arise from the use of this software.

Please be aware that this software may contain bugs, errors, or other issues. It may not function as intended or be fit for your specific use case.

By using this software, you acknowledge and accept the above disclaimer and assume all responsibility for any issues that may arise from its use.



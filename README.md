# intent-gen


```
Usage:
  fwd-intent-gen.py run <appserver> <input> <snapshot> [--batch=<batch_size>]
  fwd-intent-gen.py check <appserver> <input> <snapshot>

Options:
  -h --help     Show this help message
  --batch=<batch_size>  Configure batch size [default: 300]
```


Discalimer:

This software is provided as is, without any warranty or support. Use of the software is at your own risk. The author and any contributors will not be held responsible for any damages or issues that may arise from the use of this software.

Please be aware that this software may contain bugs, errors, or other issues. It may not function as intended or be fit for your specific use case.

By using this software, you acknowledge and accept the above disclaimer and assume all responsibility for any issues that may arise from its use.


Example Output

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

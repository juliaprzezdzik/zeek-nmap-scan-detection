# Zeek Nmap scan detection (Network Security, Assignment 10.2)

Zeek scripts that raise a `Notice` when a threshold is reached; the counter then
starts over and each `msg` contains the number of previous notices for the scan.

| Script | Nmap scan | What is counted |
|---|---|---|
| `syn_scan.zeek` | `-sS` | distinct ports with half-open (SYN-only) connections |
| `connect_scan.zeek` | `-sT` | completed handshakes with no payload |
| `udp_scan.zeek` | `-sU` | distinct UDP ports with no reply |

Run:

```
zeek -C -r assignment_lecture10.pcap syn_scan.zeek
cat notice.log
```

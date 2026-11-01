# Zeek Nmap scan detection (Network Security, Assignment 10.2)

Zeek scripts that raise a `Notice` when a threshold is reached; the counter then
starts over and each `msg` contains the number of previous notices for the scan.

| Script | Nmap scan | What is counted |
|---|---|---|
| `syn_scan.zeek` | `-sS` | distinct ports with half-open (SYN-only) connections |
| `connect_scan.zeek` | `-sT` | completed handshakes with no payload |
| `udp_scan.zeek` | `-sU` | distinct UDP ports with no reply |

Run all three scripts at once on the provided pcap file:

```
zeek -C -r cicids2017_snippet.pcap syn_scan.zeek connect_scan.zeek udp_scan.zeek
cat notice.log
```

Or run a single script:

```
zeek -C -r cicids2017_snippet.pcap syn_scan.zeek
zeek -C -r cicids2017_snippet.pcap connect_scan.zeek
zeek -C -r cicids2017_snippet.pcap udp_scan.zeek
```

The Notices are written to `notice.log` in the current directory, one line per
Notice, with the number of previous Notices in the `msg` field.

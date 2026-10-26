# Detects Nmap -sU (UDP) scans.
# UDP has no handshake. The scanner sends small datagrams to many ports and
# gets no UDP reply (closed ports answer with ICMP port unreachable, open ports
# usually stay silent). Zeek therefore sees many one-way UDP "connections"
# (state S0) from the same source.

@load base/frameworks/notice

module UdpScan;

export {
	redef enum Notice::Type += { UDP_Scan };

	# distinct unanswered UDP ports before a Notice is raised
	const port_threshold = 20 &redef;
}

global ports_seen: table[addr] of set[port];
global notices_raised: table[addr] of count;

event connection_state_remove(c: connection)
	{
	if ( get_port_transport_proto(c$id$resp_p) != udp )
		return;

	# one-way traffic only: the target sent nothing back over UDP
	if ( c$resp$num_pkts > 0 )
		return;

	local src = c$id$orig_h;
	if ( src !in notices_raised )
		notices_raised[src] = 0;
	if ( src !in ports_seen )
		ports_seen[src] = set();

	add ports_seen[src][c$id$resp_p];

	if ( |ports_seen[src]| >= port_threshold )
		{
		NOTICE([$note=UDP_Scan, $src=src, $dst=c$id$resp_h,
		        $msg=fmt("UDP scan (-sU) from %s: %d distinct unanswered ports; previous notices for this scan: %d",
		                 src, port_threshold, notices_raised[src]),
		        $identifier=cat(src, notices_raised[src])]);

		++notices_raised[src];
		delete ports_seen[src];
		}
	}

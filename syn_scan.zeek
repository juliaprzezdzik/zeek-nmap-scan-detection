# Detects Nmap -sS (TCP SYN / half-open) scans.
# A SYN scan never completes the handshake: the target answers RST (closed,
# history "Sr"), does not answer (filtered, "S"), or answers SYN-ACK and the
# scanner resets (open, "ShR"). No ACK from the originator is ever seen.

@load base/frameworks/notice

module SynScan;

export {
	redef enum Notice::Type += { SYN_Scan };

	# distinct destination ports tried by one source before a Notice is raised
	const port_threshold = 100 &redef;
}

# distinct ports probed by each source since the last Notice
global ports_seen: table[addr] of set[port];
# Notices already raised for each source
global notices_raised: table[addr] of count;

event connection_state_remove(c: connection)
	{
	if ( get_port_transport_proto(c$id$resp_p) != tcp )
		return;

	# half-open only: SYN sent, handshake never completed by the originator
	if ( /^S[^A]*$/ !in c$history )
		return;

	local src = c$id$orig_h;
	if ( src !in notices_raised )
		notices_raised[src] = 0;
	if ( src !in ports_seen )
		ports_seen[src] = set();

	add ports_seen[src][c$id$resp_p];

	if ( |ports_seen[src]| >= port_threshold )
		{
		NOTICE([$note=SYN_Scan, $src=src, $dst=c$id$resp_h,
		        $msg=fmt("SYN scan (-sS) from %s: %d distinct ports reached; previous notices for this scan: %d",
		                 src, port_threshold, notices_raised[src]),
		        $identifier=cat(src, notices_raised[src])]);

		++notices_raised[src];
		delete ports_seen[src];   # threshold starts over
		}
	}

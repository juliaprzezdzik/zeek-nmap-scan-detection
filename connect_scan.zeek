# Detects Nmap -sT (TCP connect) scans.
# The scanner uses the OS connect() call, so the handshake is completed
# (SYN, SYN-ACK, ACK) and the connection is closed at once, without any payload.
# Closed ports look the same as in a SYN scan ("Sr"), so the only thing that
# identifies -sT is the open ports: completed handshakes with no data in either
# direction. A scan reaches only a handful of open ports, so we count these
# empty connections, not distinct ports.

@load base/frameworks/notice

module ConnectScan;

export {
	redef enum Notice::Type += { Connect_Scan };

	# empty completed handshakes from one source before a Notice is raised
	const connection_threshold = 100 &redef;
}

global empty_conns: table[addr] of count;
global notices_raised: table[addr] of count;

event connection_state_remove(c: connection)
	{
	if ( get_port_transport_proto(c$id$resp_p) != tcp )
		return;

	# handshake completed: SYN, SYN-ACK and an ACK from the originator
	if ( /^ShA/ !in c$history )
		return;

	# ...but nothing was sent: a connect scan just opens and closes
	if ( c$orig$size > 0 || c$resp$size > 0 )
		return;

	local src = c$id$orig_h;
	if ( src !in notices_raised )
		notices_raised[src] = 0;
	if ( src !in empty_conns )
		empty_conns[src] = 0;

	++empty_conns[src];

	if ( empty_conns[src] >= connection_threshold )
		{
		NOTICE([$note=Connect_Scan, $src=src, $dst=c$id$resp_h,
		        $msg=fmt("TCP connect scan (-sT) from %s: %d empty completed connections; previous notices for this scan: %d",
		                 src, connection_threshold, notices_raised[src]),
		        $identifier=cat(src, notices_raised[src])]);

		++notices_raised[src];
		empty_conns[src] = 0;   # threshold starts over
		}
	}

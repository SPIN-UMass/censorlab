##! Zeek script for Shadowsocks/encrypted protocol detection comparison (Experiment 4).
##!
##! Runs against a PCAP and checks TCP connection first payloads for
##! indicators of fully encrypted traffic (no known protocol fingerprint).
##!
##! Note: Zeek is a passive monitor -- it can detect suspicious connections
##! but cannot actively drop them.  Zeek does not natively expose per-byte
##! popcount or normalized entropy, so this implements a simplified check
##! based on protocol fingerprint absence.
##!
##! Usage:
##!   zeek -C -r <pcap> zeek_shadowsocks.zeek

module ShadowsocksDetect;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:          time    &log;
        uid:         string  &log;
        orig_h:      addr    &log;
        orig_p:      port    &log;
        resp_h:      addr    &log;
        resp_p:      port    &log;
        payload_len: count   &log;
        reason:      string  &log;
        action:      string  &log;
    };

    ## Payload lengths exempt from detection (Wu et al. 2023)
    const exempt_lengths: set[count] = {
        517, 518, 519, 520, 521,
        1460, 1500,
    } &redef;
}

# Track connections we have already inspected
global seen_conns: set[string];

event zeek_init()
    {
    Log::create_stream(ShadowsocksDetect::LOG,
        [$columns=Info, $path="shadowsocks_matches"]);
    seen_conns = set();
    }

function is_printable_ascii(byte_val: count): bool
    {
    return byte_val >= 0x20 && byte_val <= 0x7e;
    }

function check_protocol_fingerprint(payload: string): bool
    {
    # Check for known protocol fingerprints in first bytes
    if ( |payload| >= 2 )
        {
        local b0 = bytestring_to_count(payload[0]);
        local b1 = bytestring_to_count(payload[1]);
        # TLS records: \x16\x03, \x14\x03, \x15\x03, \x17\x03
        if ( b1 == 0x03 && (b0 == 0x16 || b0 == 0x14 || b0 == 0x15 || b0 == 0x17) )
            return T;
        # DNS-like: \x00\x00
        if ( b0 == 0x00 && b1 == 0x00 )
            return T;
        }
    # Text protocol fingerprints
    if ( |payload| >= 4 )
        {
        if ( payload[0:4] == "GET " || payload[0:4] == "POST" ||
             payload[0:4] == "HEAD" || payload[0:4] == "PUT " ||
             payload[0:4] == "HTTP" || payload[0:4] == "SSH-" )
            return T;
        }
    return F;
    }

event tcp_packet(c: connection, is_orig: bool, flags: string,
                 seq: count, ack: count, len: count, payload: string)
    {
    # Only check first data packet per connection
    if ( |payload| == 0 )
        return;

    local cid = cat(c$uid);
    if ( cid in seen_conns )
        return;
    add seen_conns[cid];

    local plen = |payload|;

    # Exempt common lengths
    if ( plen in exempt_lengths )
        return;

    # Check for known protocol fingerprints
    if ( check_protocol_fingerprint(payload) )
        return;

    # Check if first 6 bytes are all printable ASCII
    if ( plen >= 6 )
        {
        local all_printable = T;
        local i = 0;
        while ( i < 6 )
            {
            if ( ! is_printable_ascii(bytestring_to_count(payload[i])) )
                {
                all_printable = F;
                break;
                }
            ++i;
            }
        if ( all_printable )
            return;
        }

    # If we reach here, the payload has no known fingerprint and starts
    # with non-printable bytes -- flag as suspicious encrypted traffic
    Log::write(ShadowsocksDetect::LOG, [
        $ts          = network_time(),
        $uid         = c$uid,
        $orig_h      = c$id$orig_h,
        $orig_p      = c$id$orig_p,
        $resp_h      = c$id$resp_h,
        $resp_p      = c$id$resp_p,
        $payload_len = plen,
        $reason      = "no_fingerprint_non_printable",
        $action      = "would_drop"
    ]);
    }

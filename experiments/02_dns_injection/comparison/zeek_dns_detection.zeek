##! Zeek script for DNS injection detection comparison (Experiment 2).
##!
##! Runs against a PCAP and checks DNS queries for forbidden domains.
##! Logs matches to dns_injection_matches.log.
##!
##! Note: Zeek is a passive monitor -- it can detect DNS queries for
##! forbidden domains but cannot inject forged responses.
##!
##! Usage:
##!   zeek -C -r <pcap> zeek_dns_detection.zeek

module DnsInjection;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:       time    &log;
        uid:      string  &log;
        orig_h:   addr    &log;
        orig_p:   port    &log;
        resp_h:   addr    &log;
        resp_p:   port    &log;
        domain:   string  &log;
        action:   string  &log;
    };

    ## Set of forbidden domains (lowercase, without trailing dot)
    const forbidden_domains: set[string] = {
        "google.com", "facebook.com", "twitter.com", "youtube.com",
        "wikipedia.org", "instagram.com", "whatsapp.com", "telegram.org",
        "signal.org", "reddit.com", "nytimes.com", "bbc.com",
        "reuters.com", "theguardian.com", "washingtonpost.com",
        "amnesty.org", "hrw.org", "rsf.org", "torproject.org",
        "eff.org", "vpngate.net", "psiphon.ca", "lanternvpn.org",
        "protonvpn.com", "mullvad.net", "github.com", "medium.com",
        "blogspot.com", "wordpress.com", "tumblr.com", "dropbox.com",
        "soundcloud.com", "vimeo.com", "twitch.tv", "discord.com",
    } &redef;
}

event zeek_init()
    {
    Log::create_stream(DnsInjection::LOG,
        [$columns=Info, $path="dns_injection_matches"]);
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    local query_lower = to_lower(query);
    # Strip trailing dot if present
    if ( |query_lower| > 0 && query_lower[|query_lower| - 1] == "." )
        query_lower = query_lower[0:|query_lower| - 1];
    for ( domain in forbidden_domains )
        {
        if ( domain in query_lower )
            {
            Log::write(DnsInjection::LOG, [
                $ts       = network_time(),
                $uid      = c$uid,
                $orig_h   = c$id$orig_h,
                $orig_p   = c$id$orig_p,
                $resp_h   = c$id$resp_h,
                $resp_p   = c$id$resp_p,
                $domain   = query,
                $action   = "would_inject"
            ]);
            break;
            }
        }
    }

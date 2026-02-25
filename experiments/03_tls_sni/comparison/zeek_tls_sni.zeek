##! Zeek script for TLS SNI filtering comparison (Experiment 3).
##!
##! Runs against a PCAP and uses Zeek's native TLS analyzer to extract
##! SNI from ClientHello messages.  Logs matches to tls_sni_matches.log.
##!
##! Note: Zeek is a passive monitor -- it detects forbidden SNI values
##! but cannot inject TCP RST packets to reset connections.
##!
##! Usage:
##!   zeek -C -r <pcap> zeek_tls_sni.zeek

module TlsSni;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:          time    &log;
        uid:         string  &log;
        orig_h:      addr    &log;
        orig_p:      port    &log;
        resp_h:      addr    &log;
        resp_p:      port    &log;
        server_name: string  &log;
        action:      string  &log;
    };

    ## Set of forbidden domains (lowercase, without trailing dot)
    const blocked_domains: set[string] = {
        "google.com", "facebook.com", "twitter.com", "youtube.com",
        "instagram.com", "whatsapp.com", "telegram.org", "signal.org",
        "wikipedia.org", "reddit.com", "discord.com", "medium.com",
        "soundcloud.com", "tumblr.com", "vimeo.com", "pinterest.com",
        "nytimes.com", "washingtonpost.com", "bbc.com", "theguardian.com",
        "reuters.com", "amnesty.org", "hrw.org", "rsf.org",
        "torproject.org", "psiphon.ca", "lanternvpn.org", "mullvad.net",
        "protonvpn.com", "nordvpn.com", "expressvpn.com",
        "github.com", "gitlab.com", "stackoverflow.com", "twitch.tv",
    } &redef;
}

event zeek_init()
    {
    Log::create_stream(TlsSni::LOG,
        [$columns=Info, $path="tls_sni_matches"]);
    }

event ssl_extension_server_name(c: connection, is_client: bool, names: string_vec)
    {
    if ( !is_client )
        return;

    for ( i in names )
        {
        local name = to_lower(names[i]);
        for ( domain in blocked_domains )
            {
            if ( domain in name )
                {
                Log::write(TlsSni::LOG, [
                    $ts          = network_time(),
                    $uid         = c$uid,
                    $orig_h      = c$id$orig_h,
                    $orig_p      = c$id$orig_p,
                    $resp_h      = c$id$resp_h,
                    $resp_p      = c$id$resp_p,
                    $server_name = names[i],
                    $action      = "would_reset"
                ]);
                break;
                }
            }
        }
    }

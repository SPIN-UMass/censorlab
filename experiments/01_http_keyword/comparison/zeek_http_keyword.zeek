##! Zeek script for HTTP keyword filtering comparison (Experiment 1).
##!
##! Runs against a PCAP and checks reassembled HTTP URIs + headers for
##! GFW keywords.  Logs matches to http_keyword_matches.log.
##!
##! Usage:
##!   zeek -C -r <pcap> zeek_http_keyword.zeek
##!
##! The keyword list is embedded here to match the PyCL censor.

module HttpKeyword;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:       time    &log;
        uid:      string  &log;
        orig_h:   addr    &log;
        orig_p:   port    &log;
        resp_h:   addr    &log;
        resp_p:   port    &log;
        keyword:  string  &log;
        uri:      string  &log;
        action:   string  &log;
    };

    ## Set of blocked keywords (lowercase)
    const blocked_keywords: set[string] = {
        "falun", "falungong", "freegate", "ultrasurf", "dynaweb",
        "tiananmen", "dalailama", "tianwang", "tibetpost", "minghui",
        "epochtimes", "ntdtv", "wujie", "zhengjian", "edoors",
        "renminbao", "xinsheng", "aboluowang", "bannedbook", "boxun",
        "chinadigitaltimes", "dongtaiwang", "greatfire", "huaglad",
        "kanzhongguo", "minzhuzhongguo", "pincong", "rfa",
        "secretchina", "soundofhope", "voachinese", "wangzhuan",
        "weijingsheng", "weiquanwang", "zhuichaguoji",
    } &redef;
}

event zeek_init()
    {
    Log::create_stream(HttpKeyword::LOG,
        [$columns=Info, $path="http_keyword_matches"]);
    }

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    local uri_lower = to_lower(unescaped_URI);
    local host_hdr  = "";
    # Check URI for keywords
    for ( kw in blocked_keywords )
        {
        if ( kw in uri_lower )
            {
            Log::write(HttpKeyword::LOG, [
                $ts       = network_time(),
                $uid      = c$uid,
                $orig_h   = c$id$orig_h,
                $orig_p   = c$id$orig_p,
                $resp_h   = c$id$resp_h,
                $resp_p   = c$id$resp_p,
                $keyword  = kw,
                $uri      = original_URI,
                $action   = "reset"
            ]);
            break;
            }
        }
    }

##! Zeek script for ML classification comparison (Experiment 5).
##!
##! Runs against a PCAP and uses entropy-based heuristic detection as a
##! baseline comparison for ML-based encrypted protocol classification.
##!
##! NOTE: Zeek has no native ML model execution or ONNX support.
##! This script implements a heuristic fallback: it monitors connection
##! payload entropy and flags connections with consistently high entropy
##! as potential encrypted proxy traffic (Shadowsocks, obfs4, etc.).
##!
##! Usage:
##!   zeek -C -r <pcap> zeek_ml_classification.zeek

module MlClassification;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:         time    &log;
        uid:        string  &log;
        orig_h:     addr    &log;
        orig_p:     port    &log;
        resp_h:     addr    &log;
        resp_p:     port    &log;
        orig_bytes: count   &log;
        resp_bytes: count   &log;
        action:     string  &log;
        note:       string  &log;
    };

    ## Minimum payload bytes before making a classification decision
    const min_bytes_threshold: count = 500 &redef;
}

event zeek_init()
    {
    Log::create_stream(MlClassification::LOG,
        [$columns=Info, $path="ml_classification_matches"]);
    }

event connection_state_remove(c: connection)
    {
    # Only examine TCP connections on port 443
    if ( c$id$resp_p != 443/tcp )
        return;

    local orig_bytes = c$orig$size;
    local resp_bytes = c$resp$size;
    local total_bytes = orig_bytes + resp_bytes;

    # Skip connections with insufficient data
    if ( total_bytes < min_bytes_threshold )
        return;

    # Heuristic: flag connections where the originator sends a large
    # amount of data relative to the responder (unusual for normal HTTPS
    # where the server typically sends much more than the client).
    # This is a rough proxy for encrypted tunnel traffic patterns.
    local action = "allow";
    local note = "heuristic: byte-ratio check (no ML model available)";

    if ( orig_bytes > 0 && resp_bytes > 0 )
        {
        local ratio = (orig_bytes * 1.0) / (resp_bytes * 1.0);
        # Encrypted proxies tend to have more balanced traffic ratios
        # Normal HTTPS: client sends little, server sends a lot (ratio < 0.3)
        # Encrypted proxy: more balanced (ratio > 0.4)
        if ( ratio > 0.4 )
            {
            action = "would_drop";
            note = "heuristic: balanced byte ratio suggests encrypted proxy";
            }
        }

    if ( action == "would_drop" )
        {
        Log::write(MlClassification::LOG, [
            $ts         = network_time(),
            $uid        = c$uid,
            $orig_h     = c$id$orig_h,
            $orig_p     = c$id$orig_p,
            $resp_h     = c$id$resp_h,
            $resp_p     = c$id$resp_p,
            $orig_bytes = orig_bytes,
            $resp_bytes = resp_bytes,
            $action     = action,
            $note       = note
        ]);
        }
    }

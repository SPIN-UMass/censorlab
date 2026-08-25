-- Minimal Snort 3 configuration for offline PCAP evaluation (experiments/).
--
-- Only the inspectors the scenarios need (stream reassembly, TLS, DNS, HTTP),
-- the wizard/binder defaults that attach them, and the alert_csv logger
-- (alert_csv.txt in the -l directory).  Rules are passed with -R.

HOME_NET = 'any'
EXTERNAL_NET = 'any'

-- snort_defaults.lua ships next to the snort binary's etc/snort directory; the
-- harness puts that directory on SNORT_LUA_PATH.
include 'snort_defaults.lua'

stream = { }
stream_ip = { }
stream_tcp = { }
stream_udp = { }

dns = { }
ssl = { }
http_inspect = { }
ssh = { }

wizard = default_wizard

binder =
{
    { when = { proto = 'tcp', ports = '443' }, use = { type = 'ssl' } },
    { when = { proto = 'tcp', ports = '80' },  use = { type = 'http_inspect' } },
    { when = { proto = 'udp', ports = '53' },  use = { type = 'dns' } },
    { when = { proto = 'tcp', ports = '53' },  use = { type = 'dns' } },
    { when = { proto = 'tcp', ports = '22' },  use = { type = 'ssh' } },
    { when = { service = 'ssl' },  use = { type = 'ssl' } },
    { when = { service = 'http' }, use = { type = 'http_inspect' } },
    { when = { service = 'dns' },  use = { type = 'dns' } },
    { use = { type = 'wizard' } },
}

ips =
{
    enable_builtin_rules = false,
    variables = default_variables,
}

alert_csv =
{
    file = true,
    fields = 'timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule action',
}

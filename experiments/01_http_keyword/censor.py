# HTTP Keyword Filtering Censor (PyCL)
# Emulates GFW-style HTTP keyword blocking on port 80.
# Scans TCP payload for blocked keywords and resets matching connections.
#
# NOTE: The KEYWORDS list below is populated by the runner script from
# data/gfw_keywords.txt. Do not load files at top level -- RustPython
# re-executes top-level code per connection.

KEYWORDS = [
    b"falun", b"falungong", b"freegate", b"ultrasurf", b"dynaweb",
    b"tiananmen", b"dalailama", b"tianwang", b"tibetpost", b"minghui",
    b"epochtimes", b"ntdtv", b"wujie", b"zhengjian", b"edoors",
    b"renminbao", b"xinsheng", b"aboluowang", b"bannedbook", b"boxun",
    b"chinadigitaltimes", b"dongtaiwang", b"greatfire", b"huaglad",
    b"kanzhongguo", b"minzhuzhongguo", b"pincong", b"rfa",
    b"secretchina", b"soundofhope", b"voachinese", b"wangzhuan",
    b"weijingsheng", b"weiquanwang", b"zhuichaguoji",
]

def process(packet):
    tcp = packet.tcp
    if tcp and 80 in [tcp.src, tcp.dst]:
        payload = packet.payload
        if payload:
            payload_lower = payload.lower()
            for kw in KEYWORDS:
                if kw in payload_lower:
                    return "reset"

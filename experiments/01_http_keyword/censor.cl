# CensorLang HTTP keyword filtering
# Matches GFW keywords in TCP payload using regex, resets on match.

# Combined regex: match any GFW keyword in payload
regex "(?i)(falun|falungong|freegate|ultrasurf|dynaweb|tiananmen|dalailama|tianwang|tibetpost|minghui|epochtimes|ntdtv|wujie|zhengjian|edoors|renminbao|xinsheng|aboluowang|bannedbook|boxun|chinadigitaltimes|dongtaiwang|greatfire|huaglad|kanzhongguo|minzhuzhongguo|pincong|rfa|secretchina|soundofhope|voachinese|wangzhuan|weijingsheng|weiquanwang|zhuichaguoji)"

# Only inspect port 80 traffic
if field:tcp.dst != 80: RETURN allow
# Skip packets with no payload
if field:tcp.payload.len == 0: RETURN allow
# Test regex against payload
REGEX 0 -> reg:b.0
if reg:b.0 == True: RETURN reset

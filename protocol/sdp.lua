local lpeg = require "lpeg"
local R, S, V, P = lpeg.R, lpeg.S, lpeg.V, lpeg.P
local C, Ct, Cmt, Cg, Cb, Cc = lpeg.C, lpeg.Ct, lpeg.Cmt, lpeg.Cg, lpeg.Cb, lpeg.Cc
local Cf = lpeg.Cf
local sdp ={}

local l = {}
lpeg.locale(l)

local space_c = function(pat)
   local sp = P" "^0
   return sp * C(pat) *sp 
--   return l.space^0 * pat * l.space^0
end


local space_cg = function(pat,key)
   local sp = P" "^0
   return sp * Cg(C(pat),key) *sp 
--   return l.space^0 * pat * l.space^0
end

function sdp.space(pat) 
   local sp = P" "^0
   return sp * pat *sp 
end

local any = P(1)^1
local crlf = P"\r\n"
local tab =  P'\t'
local space = l.space
local alpha = l.alpha
local alnum = l.alnum
local digit = l.digit

local safe = alnum + S'-./:?#$&*;=@[]^_{|}+~"' + P"'"  
local email_safe = safe + space + tab
local pos_digit = R"19"
local integer = pos_digit * digit^0
local decimal_uchar = C(
   P'1' * digit * digit
      +P'2' * R('04') * digit
      +P'2' * P'5' * R('05')
      +(pos_digit * digit)
      +digit 
)
local byte = P(1) - S("\0\r\n") 
local byte_string =  byte^1--P"0x" * l.xdigit * l.xdigit
local text = byte_string
local b1 = decimal_uchar - P'0' -- -P'127'
local b4 = decimal_uchar - P'0'
local ip4_address = b1 * P'.' * decimal_uchar * P'.' * decimal_uchar * P'.' * b4 
local unicast_address = ip4_address
local fqdn1 = alnum + S("-.")
local fqdn = fqdn1 * fqdn1 * fqdn1 * fqdn1
local addr =  unicast_address  + fqdn
local addrtype = P"IP4" +P"IP6"
local nettype = P"IN"
local phone = P"+" * pos_digit * (space + P"-" + digit)^1
local phone_number = phone 
   + (phone + P"(" + email_safe + P")")
   + (email_safe * P"<" * phone * P">")
--rfc1630
function get_uri()
   local void = P""
   local punctuation = S("<>")
   local national = S("{}[]\\^~")
   local hex = l.xdigit
   local escape = P"%" * hex * hex
   local reserved = S("=;/#?:") + l.space
   local extra = S("!*'\"()")
   local safe = S("$-_@.&")
   local digit = l.digit
   local alpha = l.alpha
   local xalpha = alpha + digit + safe + extra + escape
   local xalphas = xalpha^1
   local xpalpha = xalpha + P"+"
   local ialpha = alpha * xalphas^-1
   local xpalphas = xpalpha^1
   local fragmentid = xalphas
   local search = xalphas^1
   local path = void 
      + xpalphas * (P"/" * xpalphas)^0
   local scheme = ialpha
   local uri = scheme * P":" * path  * search^0
   return uri
end
local uri = get_uri()
--rfc822
function get_email()
   local alpha = l.alpha
   local digit = l.digit
   local ctl = S("\t") --todo add ctl elements
   local cr = P"\r"
   local lf = P"\n"
   local space = l.space
   local htab = P"\t"
   local crlf = cr * lf
   local lwsp_char = space + htab
   local linear_white_space = (crlf^0 * lwsp_char)^1
   local specials = S("()<>$,;\\<.[]")
   local delimiters = specials + linear_white_space
   local atom = (l.alnum - space - ctl)^1
   local text = atom
   local qtext = atom - S('"\\') - cr
   local quoted_string = P'"' * qtext * P'"'
   local dtext = atom- S('[]\\') - cr
   local quoted_pair = P"\\" * alpha
   local domain_literal = P"[" * dtext + quoted_pair + P"]" 
   local word = atom + quoted_string
   local phrase = word^1
   local domain_ref = atom
   local sub_domain = domain_ref + domain_literal
   local domain = sub_domain * (P"." * sub_domain)^0
   local local_part = word * (P"." * word)^0
   local addr_spec = local_part * P"@" * domain

   local route = (P"@"*domain)^1 * P":"
   local route_addr = P"<" * route^-1 * addr_spec * P">"
   local mailbox = addr_spec
      +phrase * route_addr
   return mailbox
end

local email = get_email()

local email_address = email 
   + (email * P"(" * email_safe^1 * P")")
   + (email_safe^1 * P"<" * email * P">")

local username = safe^1
local bandwidth = digit^1
local bwtype = alnum^1
local fixed_len_timer_unit = S("dhms")
local typed_time = digit^1 * fixed_len_timer_unit^-1
local repeat_interval = typed_time
local time = pos_digit * digit^-9
local start_time = time + P"0"
local stop_time = time + P"0"
local ttl = decimal_uchar
local multicast_address = decimal_uchar * P"." * decimal_uchar * P"." * decimal_uchar * P"." * decimal_uchar * P"/" * ttl * (P"/" * integer)^-1
local connection_address = multicast_address + addr
local sess_version = digit^1
local sess_id = digit^1
local att_value = byte_string
local att_field = alnum ^1
local attribute =(att_field * P":" * att_value) + att_field
local port = digit^1
local proto = (alnum + S"/")^1
local fmt = alnum^1
local media = alnum^1


local proto_version = P"v=" * Cg(digit^1,"v") * crlf
local o_field = space_cg(username,"username") 
   * space_cg(sess_id,"sess_id") 
   * space_cg(sess_version,"sess_version")
   * space_cg(nettype,"nettype")
   * space_cg(addrtype,"addrtype")
   * space_cg(addr,"addr")
local origin_field =  P"o=" * Cg(Ct(o_field),"o") 
local session_name_field = P"s=" *Cg(space_c(text) * crlf,"s")
local information_field = P"i=" *Cg(space_c(text) * crlf,"i")
local uri_field = P"u=" *Cg(space_c(uri) * crlf,"u")
local email_field = P"e=" *space_c(email) * crlf
local email_fields = Cg(Ct(email_field ^1),"e")
local phone_field = P"p=" * space_c(phone) * crlf
local phone_fields = Cg(Ct(phone_field ^1),"p")
local connection_field = P"c=" * Cg(Ct(space_c(text)^1) * crlf,"c") 
local bandwidth_field = P"b=" * Cg(Ct(space_c(bwtype) * ":" * space_c(digit^1)) * crlf,"b")
local time_field = P"t=" * Cg(space_c(any) * crlf,"t") --todo detail

local key_field = P"k=" *Cg(space_c(text) * crlf,"k") --todo detail
local media_field = P"m=" * space_c(media) * (space_c(port)*(P"/" * integer)^-1) * space_c(proto) * space_c(fmt) * crlf,"m"

local attr_field = P"a=" * C(attribute) * crlf
local attr_fields = Cg(Ct(attr_field ^1),"a")

function sdp.bnf_test()
   local du1 = "254"
   assert(decimal_uchar:match(du1))
   assert(byte_string:match("0x12"))
   --assert(not ip4_address:match("127.0.0.1"))
   assert(not ip4_address:match("127.0.0.0"))
   assert(not ip4_address:match("127.0.0"))
   assert(ip4_address:match("126.0.0.1"))
   assert(ip4_address:match("192.168.0.1"))
   assert(fqdn:match("a-b.2"))
   assert(phone:match("+2-2b"))
   assert("+2-"==C(phone):match("+2-"))
   assert(uri:match("http://www.google.com/path/hello?a=1"),"uri not match")
   assert(email:match("yao@163.com"))
   assert(email_address:match("yao@13.com"))
   assert(email_address:match("yao@13.com(hello word)"))
   assert(email_address:match("hello world<yao@13.com>"))
   assert(username:match("hello world"))
   assert(multicast_address:match("192.168.2.3/23"))

   assert(connection_address:match("192.168.2.5"))
   assert(attribute:match("aa:33"))
   local m = "m=audio 0 RTP/AVP 96\r\n"
   assert(media_field:match(m),"media fail")
   local m1 = Ct(media_field)
   local t1= m1:match(m)
   assert(t1)
   assert(proto_version:match("v=1\r\n"),"version fail")
--   assert(addr:("192.168.0.1")- -- ==  "192.168.0.1")
   local ip = "192.21.1.1"
   print(string.len(ip))
   print(addr:match(ip))
-- assert(addr:match(ip)== string.len(ip)+1)
   print("----",o_field:match("test 931665148 2 IN IP4 192.0.0.1"))
   local o1 = Ct(origin_field):match("o=test 931665148 2 IN IP4 192.0.0.1\r\n")
   assert(o1,"origin fail")
   assert(o1.o.addr=="192.0.0.1")
   assert(session_name_field:match("s=QuickTime\r\n"))
   assert(information_field:match("i=Infomation\r\n"))	
   assert(uri_field:match("u=http:www.g.com\r\n"))
   assert(email_field:match("e=test@g.com\r\n"))	
   local es =Ct(email_fields):match("e=test@g.com\r\ne=test1@g.com\r\n")
   assert(es.e[1]=="test@g.com")
   assert(es.e[2]=="test1@g.com")
--   local t = Ct(Cg(C(safe),"id") * space * Cg(C(safe),"name")):match("a d")
--  local t = (safe):match("a b c")
--   assert(phone_field:match("p=+2-22222\r\n"))		
end

sdp.bnf_test()

local digits = digit^1
local letter = R('az','AZ') + P'-'
local alphanum = digit +  letter  + P'.' + P'_' 
local name = (alphanum)^1
local any = l.print^1

--todo fixme
local text = name
local uri = name
local email = name
local phone  = name
local bwtype = name
local attribute = (alphanum + S'@:=.,')^1
function sdp.parse(str)
--rfc 2327 Appendix A
   local proto_version = P"v=" * Cg(l.digit^1,"v") * crlf
   local origin_field = P"o=" * Cg(Ct(sdp.space(C(text))^1) * crlf,"o") 
   local session = P"s=" *Cg(sdp.space(C(text)) * crlf,"s")
   local infomataion = P"i=" *Cg(sdp.space(C(text)) * crlf,"i")
   local uri_field = P"u=" *Cg(sdp.space(C(uri)) * crlf,"u")
   local email_field = P"e=" *sdp.space(C(email)) * crlf
   local email_fields = Cg(Ct(email_field ^1),"e")
   local phone_field = P"p=" *sdp.space(C(phone)) * crlf
   local phone_fields = Cg(Ct(phone_field ^1),"p")
   local conn_field = P"c=" * Cg(Ct(sdp.space(C(text))^1) * crlf,"c") 
   local band_width = P"b=" * Cg(Ct(sdp.space(C(bwtype)) * ":" * sdp.space(C(digits))) * crlf,"b")
   local time_field = P"t=" * Cg(sdp.space(C(any)) * crlf,"t") --todo detail
   local key_field = P"k=" *Cg(sdp.space(C(text)) * crlf,"k") --todo detail
   local media = C(alphanum^1)
   local media_port = digits --todo fix add "/"
   local proto = alphanum + P("/")
   local attr_field = P"a=" * C(attribute) * crlf
   local attr_fields = Cg(Ct(attr_field ^1),"a")
--   local media_field = P"m=" * sdp.space(media) * sdp.space(C(media_port)) * sdp.space(C(text)) * sdp.space(C(text))
   local media_field = P"m=" * Cg(Ct(sdp.space(C(text))^1) * crlf,"m") 
   local media_desc = media_field
      --* infomataion^0 * conn_field^0 * band_width * key_field^0 * attr_fields^0
   local media_descs = Cg(Ct(media_desc^1),"media")
   local sdp = Ct(proto_version 
		     * origin_field
		     * session
		     * infomataion^-1
		     * uri_field^-1
		     * email_fields^-1
		     * phone_fields^-1
		     * conn_field
		     * band_width^-1
		     * time_field
		     * key_field^-1
		     * attr_fields	 
		     * media_descs
		  ,rawset)
   local r = sdp:match(str)
   return r
end


function sdp.test1()
   local str = "v=1\r\n"..
      "o=test 931665148 2 IN IP4 127.0.0.0\r\n"..
      "s=QuickTime\r\n"..
      "e=aa\r\n"..
      "e=bb\r\n"..
      "p=138\r\n"..
      "p=139\r\n"..
      "c=IN IP4 127.0.0.1\r\n"..
      "b=av:30\r\n"..
      "t=0 0\r\n"..
      "a=x-qt-text-an@:railsconf\r\n"..
      "a=range:npt=\r\n"..
      "a=isma-compliance:2,2.0,2\r\n"..
      "m=audio 0 RTP/AVP 96\r\n"..
      "b=AS:8\r\n"..
      "a=rtpmap:96 mpeg4-generic/8000/1\r\n"..
      "a=fmtp:96 profile-level-id=15;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config=1588\r\n"..
      "a=mpeg4-esid:101\r\n"..
      "a=control:trackid=1\r\n"..
      "m=aa bb\r\n"..
      "m=video 0 qq 97\r\n"..
      "b=AS:300\r\n"..
      "a=rtpmap:97 H264/90000\r\n"..
      "a=fmtp:97 packetization-mode=1;profile-level-id=4D400C;sprop-parameter-sets=J01ADKkYUI/LgDUGAQa2wrXvfAQ=,KN4JF6A=\r\n"..
      "a=mpeg4-esid:201\r\n"..
      "a=cliprect:0,0,120,160\r\n"..
      "a=framesize:97 160-120\r\n"..
      "a=control:trackid=2\r\n"
   print(str)
   local t = sdp.parse(str)

   print(t["v"])
   print(t["o"][1])
   print(t["s"])
   print(t["i"])
   print(t["u"])
   print(t["e"][1])
   print(t["e"][2])

   print(t["p"][1])
   print(t["p"][2])
   
   print(t["c"][1])
   print(t["c"][2])
   print(t["c"][3])
   
   print(t["b"][1])
   print(t["b"][2])
   print(t["t"])
   print(t["k"])
   print(t["a"][1])
   print(t["a"][2])
end
--sdp.test1()
return sdp
local lpeg = require "lpeg"
local hive_lib = require "hive.hive_lib"
local bnf = require "protocol.bnf"
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
local space = P' ' --l.space
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
local text = safe^1
local b1 = decimal_uchar -- - P'0' -- -P'127'
local b4 = decimal_uchar -- - P'0'
local ip4_address = b1 * P'.' * decimal_uchar * P'.' * decimal_uchar * P'.' * b4 
local unicast_address = ip4_address 
local fqdn1 = alnum + S("-.")
local fqdn = fqdn1 * fqdn1 * fqdn1 * fqdn1
local addr =  unicast_address  + fqdn
local addrtype = P"IP4" +P"IP6"
local nettype = P"IN"
local phone = P"+" * pos_digit * (P" " + P"-" + digit)^1
local phone_number = phone 
   + (phone + P"(" + email_safe + P")")
   + (email_safe * P"<" * phone * P">")

local uri = bnf.uri()
local email = bnf.email()

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
local att_field = (safe - P":") ^1
local attribute =(att_field * P":" * att_value) 
   + att_field
local port = digit^1
local proto = (alnum + S"/")^1
local fmt = alnum^1
local media = alnum^1


local proto_version = P"v=" * Cg(digit^1/tonumber,"v") * crlf
local o_field = space_cg(username,"username") 
   * space_cg(sess_id/tonumber,"sess_id") 
   * space_cg(sess_version/tonumber,"sess_version")
   * space_cg(nettype,"nettype")
   * space_cg(addrtype,"addrtype")
   * space_cg(addr,"addr")
local origin_field =  P"o=" * Cg(Ct(o_field) * crlf,"o") 
local session_name_field = P"s=" *Cg(space_c(text) * crlf,"s")
local t_field = P"t=" *Cg(Ct(space_c(text)^1) * crlf,"t")
local information_field = P"i=" *Cg(space_c(text) * crlf,"i")
local uri_field = P"u=" *Cg(space_c(uri) * crlf,"u")
local email_field = P"e=" *space_c(email) * crlf
local email_fields = Cg(Ct(email_field ^1),"e")
local phone_field = P"p=" * space_c(phone) * crlf
local phone_fields = Cg(Ct(phone_field ^1),"p")
local conn1 = 
   space_cg(nettype,"nettype")
   *space_cg(addrtype,"addrtype")
   *space_cg(connection_address,"connection_address")
local connection_field = P"c=" * Cg(Ct(conn1) * crlf,"c") 
local bandwidth_field = P"b=" * Ct(space_cg(bwtype,"bwtype") * P":" * space_cg(bandwidth/tonumber,"bandwidth")) * crlf
local bandwidth_fields = Cg(Ct(bandwidth_field^1),"b")
local time_field = P"t=" * Cg(space_c(any) * crlf,"t") --todo detail

local key_field = P"k=" *Cg(space_c(text) * crlf,"k") --todo detail
local media_field = P"m=" * space_cg(media,"media") * (space_cg(port/tonumber,"port")*(P"/" * integer)^-1) * space_cg(proto,"proto") * space_cg(Ct(space_c(fmt)^1),"fmt") * crlf,"m"

local attribute_field = P"a=" * C(attribute) * crlf
local attribute_fields = Cg(Ct(attribute_field ^1),"a")

local information_field2 = P"i=" * space_c(text) * crlf
local connection_field2 = P"c=" * Ct(conn1) * crlf
local key_field2 = P"k=" * space_c(text) * crlf
local media_description = 
   Cg(Ct(media_field),"m")  
   * Cg(information_field2^-1,"i")
   * Cg(Ct(connection_field2^0),"c")
   * Cg(Ct(bandwidth_field^-1),"b")
   * Cg(key_field2^-1,"k")
   * Cg(Ct(attribute_field^1),"a")
local media_descriptions = Ct(Cg(Ct(Ct(media_description)^1),"m")) --Cg(Ct(media_description^1),"m")

local media_descriptions2 = Cg(Ct(Ct(media_description)^1),"m")
local session_description = 
   Ct(
      proto_version
	 * origin_field
	 * session_name_field
         * t_field^-1
	 * information_field^-1
	 * uri_field^-1
	 * email_field^-1
	 * connection_field^-1
	 * bandwidth_fields^-1
	 * attribute_fields
	 * media_descriptions2 
   )
----[[
local t = ""..
"v=0\r\n"..
"o=- 1421883026779795610 2 IN IP4 127.0.0.1\r\n"..
"s=-\r\n"..
"t=0 0\r\n"..
"a=group:BUNDLE\r\n"..
"m=audio 0 RTP/AVP 96 20\r\n"..
"c=IN IP4 0.0.0.0\r\n"..
"a=send:aa\r\n"

 t1 ="m=audio 0 RTP/AVP 96\r\n"..
      "a=rtpmap:97 H264/90000\r\n"..
      "a=aesid:201\r\n"..
      "a=ssrc:1023 cname:hello\r\n"..
   "a=ssrc:1023 mslable:hello\r\n"

--print(C(media_description):match("m=audio 0 RTP/AVP 96\r\n"))
--"m=audio 1 RTP/SAVPF 111 103 104 0 8 106 105 13 126\r\n"
print("xxxxxxxxxxx",session_description:match(t))
----]]
local req_meta = {}
local build_field
build_field = {
   ["v"] = function(req,v)
      table.insert(req,string.format("v=%d\r\n",v))
   end,
   ["o"] = function(req,o)
      table.insert(req,string.format("o=%s %d %d %s %s %s \r\n",
				      o.username,o.sess_id
				      ,o.sess_version,o.nettype,o.addrtype
				      ,o.addr
				     )
      )
   end,
   ["b"] = function(req,b)
      local i
      for i=1, #(b) do
	 table.insert(req,string.format("b=%s:%d \r\n",b[i].bwtype,b[i].bandwidth))
      end
   end,
   ["c"]= function(req,c)
      table.insert(req,string.format("c=%s %s %s \r\n",c.nettype,c.addrtype,c.connection_address))
   end,
   ["s"] = function(req,s)
      table.insert(req,string.format("s=%s\r\n",s))
   end,
   ["i"] = function(req,i)
      table.insert(req,string.format("i=%s\r\n",i))
   end,
   ["a"] = function(req,a)
      local i
      for i = 1, #(a) do
	 table.insert(req,string.format("a=%s",a[i]))
      end
   end,
   ["media"] = function(req,media)
      table.insert(req,string.format("m=%s %s  %s  %s\r\n",media.media,media.port,media.proto,media.fmt))
   end,
   ["m"] = function(req,m)
      for i = 1 , #(m) do
	 local media   = m[i].m 
	 build_field["media"](req,media)
	 if m[i].i and m[i].i ~= "" then --todo fixme why i has value
	    build_field["i"](req,m[i].i)
	 end
	 if m[i].c then
	    local j
	    for j = 1, #(m[i].c) do
	       build_field["c"](req,m[i].c[j])
	    end
	 end
	 
	 if m[i].b then
	    build_field["b"](req,m[i].b)
	 end
	 
	 if m[i].a then
	    assert(type(m[i].a) == "table")
	    build_field["a"](req,m[i].a)
	 end
      end
   end
}

function sdp.build_req(sdp)
   assert(sdp and type(sdp) == "table")
   assert(sdp.o and sdp.s)
   assert(sdp.m)
   local data = { }
   local k,v

   if sdp.v then
      build_field["v"](data,sdp.v)
   end
   build_field["o"](data,sdp.o)
   build_field["s"](data,sdp.s)
   

   if sdp.c then
      build_field["c"](data,sdp.c)
   end
   local i
   if sdp.a then
      build_field["a"](data,sdp.a)
   end

   assert(sdp.m,"must have media")
   build_field["m"](data,sdp.m)
   

   return hive_lib.strjoin("\r\n",data).."\r\n\r\n"
  
end

function req_meta:is_bundle()
   return true
end
function req_meta:is_rtcp_mux()
   return true
end

--function req_meta:audio_ssrc()
--   req_meta:ssrc("audio")
--end

local function get_fingerprint(attrs)
   local i
   for i in ipairs(attrs) do
      local tmp = attrs[i]
      if tmp:find("fingerprint") then
	 print("sss",tmp)
	 local codec = safe^1
	 local finger = safe^1
	 local ps = Ct(P"fingerprint:" * space_c(codec) * space_c(finger))
	 local t = ps:match(tmp)
	 if t then
	    return {typ=t[1],fingerprint=t[2]}
	 end
      end
   end
   return nil
end
function req_meta:fingerprint()
   local attrs = self.a
   local finger = get_fingerprint(attrs)
   if finger then
      return finger
   end
   local ms = self.m
   local media = ms[1]
   return get_fingerprint(media.a)
end
function req_meta:ssrc(typ)
   local m = self.m
   local i,v
   local media
  
   for i,v in ipairs(m) do
      if v.m.media == typ then
	 media = v
	 break
      end
   end
   if not media then 
      return false,"no media"
   end
   local attrs = media.a
   local ssrcs = {}
   for i in ipairs(attrs) do
      local tmp = attrs[i]
      if tmp:find("ssrc:") then
	 print(tmp)
	 local value = (safe - P":") ^1
	 local key = (safe - P":") ^1
	 local pair = Cg(space_c(key) * P":" * space_c(value))
	 local ps  = Cf(Ct("") *pair^1,rawset)
	 local t = ps:match(tmp)
	 if  t then
--	    local p2 = Ct(space_c(safe^1) * ps)
	    t.str = tmp
	    table.insert(ssrcs,t)
	 end
      end
   end
   return ssrcs
end

function sdp.parse(bin)
   assert(bin and type(bin)=="string")
   local req = session_description:match(bin)
   if not req then
      return false,"not valid sdp"
   end
   return setmetatable(req,{__index = req_meta})
end

function sdp.bnf_test()
   local du1 = "254"
   assert(decimal_uchar:match(du1))
   assert(byte_string:match("0x12"))
   --assert(not ip4_address:match("127.0.0.1"))
   assert(not ip4_address:match("a.0.0.0"))
   assert(not ip4_address:match("127.0.0"))
   assert(ip4_address:match("0.0.0.0"))
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
   assert(attribute:match("group:BUNDDLE video audio"))
   assert(attribute:match("msid-semetic: WMS"))
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
--   print("----",o_field:match("test 931665148 2 IN IP4 192.0.0.1"))
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
   assert(phone_field:match("p=+2-22222\r\n"))		
   local f1 = Ct(phone_fields):match("p=+2-1\r\np=+3-1\r\n")
   assert(f1.p[1] == "+2-1")
   assert(f1.p[2] == "+3-1")
   local conn = "c=IN IP4 127.0.0.1\r\n"
   assert(connection_field:match(conn))
   local c1 = Ct(connection_field):match(conn)
   assert(c1.c.nettype == "IN")
   assert(c1.c.addrtype == "IP4")   
   assert(c1.c.connection_address == "127.0.0.1")
   local b1 = "b=test:12\r\n\b=t2:13\r\n"
   assert(bandwidth_field:match(b1))
   local bt = Ct(bandwidth_fields):match(b1)
   assert(bt.b[1].bwtype == "test")
   assert(bt.b[1].bandwidth == "12")
   local at = "a=rtpmap:97 H264/90000\r\na=bb:12\r\n"
   assert(attribute_field:match(at))
   local att = Ct(attribute_fields):match(at)
   assert(att.a[1] == "rtpmap:97 H264/90000")
   assert(att.a[2] == "bb:12")

   local media ="m=video 123 qq 98\r\n"..
      "i=Info\r\n"..
      "c=IN IP4 127.0.0.1\r\n"..
      "c=IN IP6 127.0.0.1\r\n"..
      "b=AS:300\r\n"..
      "a=rtpmap:97 H264/90000\r\n"..
      "a=aesid:201\r\n"..
      "a=ssrc:1023 cname:hello\r\n"..
      "a=ssrc:1023 mslable:hello\r\n"

   assert(att_value:match("mpeg4-esid"))
   local media2 = "m=audio 22 qq 97\r\n"..
      "b=AS:300\r\n"..
      "a=rtpmap:97 H264/90000\r\n"..
      "a=mpeg4esid:201\r\n"..
      "a=ssrc:1023 cname:hello\r\n"..
      "a=ssrc:1023 mslable:hello\r\n"..
      "a=fingerprint:sha-256 12:34:56\r\n"..
      "m=vedio 0 qq 97\r\n"..
      "b=AS:300\r\n"..
      "a=rtpmap:97 H264/90000\r\n"..
      "a=mpeg4esid:201\r\n"
   assert(media_description:match(media))
   print(media_description:match(media),string.len(media))
   local mt = Ct(media_description):match(media)
   assert(mt.m.media=="video")
   assert(mt.i == "Info")
   assert(mt.c[1].nettype=="IN")
   assert(mt.c[2].addrtype=="IP6")
   assert(mt.i=="Info")
   assert(mt.a[2]=="aesid:201")
   print(mt.b[1].bandwidth)
   assert(mt.b[1].bwtype=="AS")
   
   assert(media_descriptions:match(media2))

   local mtt = Ct(Cg(Ct(Ct(media_description)^1),"m")):match(media2)
   local mtt2 = media_descriptions:match(media2)
   print(mtt.m[2].m.media)
   print(mtt.m[1].m.port)
   assert(mtt.m[2].m.media=="vedio")
   assert(mtt2.m[2].m.media=="vedio")

   local session = 
      "v=1\r\n"..
      "o=test 931665148 2 IN IP4 192.0.0.1\r\n"..
      "s=QuickTime\r\n"..
      "c=IN IP4 127.0.0.1\r\n"..
      "b=av:30\r\n"..
      "a=range:npt=\r\n"..
      "a=isma-compliance:2,2.0,2\r\n"..
      "" .. media2
   
   local st = session_description:match(session)
   assert(st)
   assert(st.v == 1)
   assert(st.s == "QuickTime")
   assert(st.c.nettype == "IN")
   assert(st.c.addrtype == "IP4")
   assert(st.c.connection_address == "127.0.0.1")
   print(st.b[1].bandwidth)
   assert(st.b[1].bandwidth == "30")
   assert(st.m[1].m.media == "audio")
   assert(st.m[2].m.media == "vedio")
   
   print("xxxxx",#(st.m[1].a))
   return setmetatable(st,{__index = req_meta})
end
function parse_test()
   local sdp =[[
v=0
o=- 1421883026779795610 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE audio video
a=msid-semantic: WMS
m=audio 1 RTP/SAVPF 111 103 104 0 8 106 105 13 126
c=IN IP4 0.0.0.0
a=rtcp:1 IN IP4 0.0.0.0
a=ice-ufrag:S+KKU7zeZD52BD9a
a=ice-pwd:QynIQR9E4BJuIlSckY7JPRBP
a=ice-options:google-ice
a=fingerprint:sha-256 B9:DF:70:CC:7D:A1:71:10:3E:4B:66:50:7C:25:38:E6:14:EC:AA:74:A6:73:FE:BE:A0:AB:56:5C:F8:36:5C:50
a=setup:actpass
a=mid:audio
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=recvonly
a=rtcp-mux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WZ/+eA1aV6JmsJOJyROSun/2H94tlyGrJUHtXYBi
a=rtpmap:111 opus/48000/2
a=fmtp:111 minptime=10
a=rtpmap:103 ISAC/16000
a=rtpmap:104 ISAC/32000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:106 CN/32000
a=rtpmap:105 CN/16000
a=rtpmap:13 CN/8000
a=rtpmap:126 telephone-event/8000
a=maxptime:60
m=video 1 RTP/SAVPF 100 116 117
c=IN IP4 0.0.0.0
a=rtcp:1 IN IP4 0.0.0.0
a=ice-ufrag:S+KKU7zeZD52BD9a
a=ice-pwd:QynIQR9E4BJuIlSckY7JPRBP
a=ice-options:google-ice
a=fingerprint:sha-256 B9:DF:70:CC:7D:A1:71:10:3E:4B:66:50:7C:25:38:E6:14:EC:AA:74:A6:73:FE:BE:A0:AB:56:5C:F8:36:5C:50
a=setup:actpass
a=mid:video
a=extmap:2 urn:ietf:params:rtp-hdrext:toffset
a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
a=recvonly
a=rtcp-mux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WZ/+eA1aV6JmsJOJyROSun/2H94tlyGrJUHtXYBi
a=rtpmap:100 VP8/90000
a=rtcp-fb:100 ccm fir
a=rtcp-fb:100 nack
a=rtcp-fb:100 nack pli
a=rtcp-fb:100 goog-remb
a=rtpmap:116 red/90000
a=rtpmap:117 ulpfec/90000
]]
end
local debug = false
if debug then
   local t =sdp.bnf_test()
   local t1 = sdp.build_req(t)
   print("sdp:test",t1)
   print("sdp test:xxx",t:ssrc("audio"))
   print("sdp test:xxx",t:ssrc("audio"))
   print("sdp test:finger",t:fingerprint().typ,t:fingerprint().fingerprint)
end
--sdp.test1()
local rtp_def ={
   RTCP_Sender_PT = 200 ,--, // RTCP Sender Report
   RTCP_Receiver_PT =   201,-- // RTCP Receiver Report
   RTCP_RTP_Feedback_PT = 205,-- // RTCP Transport Layer Feedback Packet
   RTCP_PS_Feedback_PT  =  206,-- // RTCP Payload Specific Feedback Packet
   VP8_90000_PT  =      100,-- // VP8 Video Codec
   RED_90000_PT  =      116,-- // REDundancy (RFC 2198)
   ULP_90000_PT    =    117,-- // ULP/FEC
   ISAC_16000_PT   =    103,-- // ISAC Audio Codec
   ISAC_32000_PT   =    104,-- // ISAC Audio Codec
   PCMU_8000_PT    =    0,--   // PCMU Audio Codec
   OPUS_48000_PT   =    111,-- // Opus Audio Codec
   PCMA_8000_PT    =    8,--   // PCMA Audio Codec
   CN_8000_PT      =    13,--  // CN Audio Codec
   CN_16000_PT     =    105,-- // CN Audio Codec
   CN_32000_PT     =    106,-- // CN Audio Codec
   CN_48000_PT     =    107,-- // CN Audio Codec
   TEL_8000_PT     =    126 --// Tel Audio Events
}

local uuid = require "protocol.uuid"
local function random_key(len)
   if len ==nil then
      len = 10
   end
   local ascii = {"a","b","c","d","e","f","g","h","i","g","k","l","m","n","o","p","q","r","s","t","u","v"}
   local str =""
   while len>0 do
      local r = math.random(1,256)
      len = len -1
   end
end
local sdp_M ={}
--[[
   {type="CANDIDATE_TYPE_SERVER_REFLEXIVE",
   transport = "udp",
   addr = {ip=ip,port=port},
   base_addr = {ip = host.addr.ip,port= host.addr.port},
   cid = host.cid,
   sid = host.sid,
   user = host.user,
   priority = compute_candidate_priority("CANDIDATE_TYPE_SERVER_REFLEXIVE",host.cid),
   pwd = host.pwd,
   stun_ip = gather.stun_ip,
   stun_port = gather.stun_port
   }
--]]

local typ_str = {
      CANDIDATE_TYPE_HOST = "host",
      CANDIDATE_TYPE_PEER_REFLEXIVE = "prflx",
      CANDIDATE_TYPE_SERVER_REFLEXIVE = "srflx",
      CANDIDATE_TYPE_RELAYED = "relay"
}
local i 
for k,v in pairs(typ_str) do
   typ_str[v] = k
end
local json = require "cjson"
function sdp.get_remotes(Jsons,user,pwd,is_rtcp_mux)
   local i,v
   local audio,video = {},{}
   for i,v in ipairs(Jsons) do
      --local t = json.decode(Jsons[i])
      local candi = v
      local elem = safe^1
      local elems = space_c(elem)^1
      local cp = Ct(P"a=candidate:" * elems * "\r\n")
      local t2 = cp:match(candi)
      assert(t2,"candies str not valied")
      local typ = typ_str[t2[8]]
      local c1 =  {
	 fid = t[1],
	 type = typ,
	 transport = "udp", --t2[3]
	 addr = {ip=t[5],port=tonumber(t[6])},
	 base_addr = {ip = host.addr.ip,port= host.addr.port},
	 cid = t[2],
	 sid = 1,
	 user = user,
	 priority = t[4],
	 pwd = pwd
      }
      if t2[8] ~= "host" then
	 c1.base_addr.ip= t2[11]
	 c1.base_addr.port = t2[13]
      end
      
      if is_rtcp_mux then
	 if t2[2] == "1" then
	    if t.sdpMid == "audio" then
	       table.insert(audio,c1)
	    else
	       table.insert(vedio,c1)
	    end
	 end
      else
	 if t.sdpMid == "audio" then
	    table.insert(audio,c1)
	 else
	    table.insert(vedio,c1)
	 end
      end
   end
   table.sort(audio,function(a,b)
		 return a.priority >b.priority
   end)
   
   table.sort(video,function(a,b)
		 return a.priority >b.priority
   end)
   return true,audio,video
end       
function sdp_M:get_sdp()
   local tbl ={}
   local info = self
   local msid = uuid.new()
   local audio_candis,Video_candis = {},{}
   info.msid = msid
   table.insert(tbl,"v=0")
   table.insert(tbl,"o=- 0 0 IN IP4 127.0.0.1")
   table.insert(tbl,"s=-")
   table.insert(tbl,"t=0 0")
   if self.is_bundle then
      table.insert(tbl,"a=group:BUNDLE audio video")
      table.insert(tbl,string.format("a=msid-semantic: WMS %s",msid))
   end
   local candidates = info.candidates
   assert(candidates,"must have candidates")
   local i
   --audio
   local ip = "127.0.0.1"
   local port = 7000 --default
   local str = "m=audio %d RTP/SAVPF %s"   
   local payloads = {} 
   for i in ipairs(info.payloads) do
      table.insert(payloads,info.payloads[i].payload_type)
   end
   payloads = table.concat(payloads," ")
   table.insert(tbl,string.format(str,port,payloads))
   table.insert(tbl,string.format("c=IN IP4 %s",ip))
   if info.is_rtcp_mux then
      table.insert(tbl,string.format("a=rtcp:%d IN IP4 %s",port,ip))
   end
   local user = candidates[1].user
   local pwd = candidates[1].pwd
   ip = candidates[1].addr.ip
   port = candidate[1].addr.port
   table.insert(tbl,"a=ice-ufrag:"..user)
   table.insert(tbl,"a=ice-pwd:"..pwd)
   for i in ipairs(candidates) do
      local candi = candidates[i]
      local cstr = "a=candidate:%s %s %s %s %s %s typ %s"
      local host_typ_str 
      host_typ_str = typ_str[candi.type]
      assert(host_typ_str)
      cstr = string.format(cstr,candi.fid,candi.cid,candi.transport,candi.priority,
			   candi.addr.ip,candi.addr.port,host_typ_str)
      if canid.type ~="CANDIDATE_TYPE_HOST" then
	 cstr = cstr .. string.format(" raddr %s rport %d",candi.base_addr.ip,candi.base_addr.port)
      end
      cstr = cstr .. "generation 0"
      table.insert(audio_candis,cstr)
      --table.insert(tbl,cstr)
   end
   table.insert(tbl,"a=fingerprint:sha-256 "..info.fingerprint)
   table.insert(tbl,"a=sendrecv")
   table.insert(tbl,"a=mid:audio")
   if info.is_rtcp_mux then
      table.insert(tbl,"a=rtcp-mux")
   end
   
   for i in ipairs(info.payloads) do
      local srtp =""
      local rtp = info.payloads[i]
      local typ = rtp_def[rtp.media_type]
      if rtp.media_type == 2 then --audio
	 if rtp.channels >1 then
	    srtp = string.format("a=rtpmap:%d %s/%d/%d",typ,rtp.encoding_name,rtp.clock_rate,rtp.channels)
	 else
	    srtp = string.format("a=rtpmap:%d %s/%d",typ,rtp.encoding_name,rtp.clock_rate)
	 end
	 table.insert(tbl,srtp)
	 if rtp.encoding_name == "opus" then
	    table.insert(tbl,string.format("a=fmtp:%d minptime=10",typ))
	 end
      end
   end
   local audio_ssrc = info.audio_ssrc
   if not audio_ssrc then
      audio_ssrc = 44444
   end
   table.insert(tbl,"a=maxptime:60")
   table.insert(tbl,string.format("a=ssrc:%d cname:o/i14u9pJrxRKAsu",audio_ssrc))
   table.insert(tbl,string.format("a=ssrc:%d msid:%d",audio_ssrc,msid))
   table.insert(tbl,string.format("a=ssrc:%d mslable:%d",audio_ssrc,msid))
   table.insert(tbl,string.format("a=ssrc:%d label:%d",audio_ssrc,msid))



--video
   local ip = "127.0.0.1"
   local port = 7000 --default
   local str = "m=vedio %d RTP/SAVPF %s"   
   local payloads = {} 
   for i in ipairs(info.payloads) do
      table.insert(payloads,info.payloads[i].payload_type)
   end
   payloads = table.concat(payloads," ")
   table.insert(tbl,string.format(str,port,payloads))
   table.insert(tbl,string.format("c=IN IP4 %s",ip))
   if info.is_rtcp_mux then
      table.insert(tbl,string.format("a=rtcp:%d IN IP4 %s",port,ip))
   end
   local user = candidates[1].user
   local pwd = candidates[1].pwd
   table.insert(tbl,"a=ice-ufrag:"..user)
   table.insert(tbl,"a=ice-pwd:"..pwd)
   for i in ipairs(candidates) do
      local candi = candidates[i]
      local cstr = "a=candidate:%s %s %s %s %s %s typ %s"
      local host_typ_str 
      host_typ_str = typ_str[candi.type]
      assert(host_typ_str)
      cstr = string.format(cstr,candi.fid,candi.cid,candi.transport,candi.priority,
			   candi.addr.ip,candi.addr.port,host_typ_str)
      if canid.type ~="CANDIDATE_TYPE_HOST" then
	 cstr = cstr .. string.format(" raddr %s rport %d",candi.base_addr.ip,candi.base_addr.port)
      end
      cstr = cstr .. "generation 0"
      table.insert(vedio_candis,cstr)
      --table.insert(tbl,cstr)
   end
   table.insert(tbl,"a=fingerprint:sha-256 "..info.fingerprint)
   table.insert(tbl,"a=sendrecv")
   table.insert(tbl,"a=mid:video")
   if info.is_rtcp_mux then
      table.insert(tbl,"a=rtcp-mux")
   end
   
   for i in ipairs(info.payloads) do
      local srtp =""
      local rtp = info.payloads[i]
      local typ = rtp_def[rtp.media_type]
      if rtp.media_type == 1 then --vedio
	 srtp = string.format("a=rtpmap:%d %s/%d",typ,rtp.encoding_name,rtp.clock_rate)
	 table.insert(tbl,srtp)
	 if rtp.encoding_name == "VP8" then
	    table.insert(tbl,string.format("a=rtcp-fb:%d ccm fir",typ))
	    table.insert(tbl,string.format("a=rtcp-fb:%d nack",typ))
	    table.insert(tbl,string.format("a=rtcp-fb:%d goog-remb",typ))
	 end
      end
   end
   local vedio_ssrc = info.vedio_ssrc
   if not vedio_ssrc then
      vedio_ssrc = 55543
   end
   table.insert(tbl,"a=maxptime:60")
   table.insert(tbl,string.format("a=ssrc:%d cname:o/i14u9pJrxRKAsu",audio_ssrc))
   table.insert(tbl,string.format("a=ssrc:%d msid:%d",audio_ssrc,msid))
   table.insert(tbl,string.format("a=ssrc:%d mslable:%d",audio_ssrc,msid))
   table.insert(tbl,string.format("a=ssrc:%d label:%d",audio_ssrc,msid))


   return table.concat(tbl,"\r\n"),audio_candis,Video_candis
end


function sdp.new_sdp_info()
   local info ={}
   local vp8 = {
      payload_type = "VP8_90000_PT",
      encoding_name = "VP8",
      clock_rate = 90000,
      channels = 1,
      media_type = 1,--video,audio,other
   }

   local red = {
      payload_type = "RED_90000_PT",
      encoding_name = "red",
      clock_rate = 90000,
      channels = 1,
      media_type = 1,--video,audio,other
   }
   
   local ulpfec = {
      payload_type = "ULP_90000_PT",
      encoding_name = "ulpfec",
      clock_rate = 90000,
      channels = 1,
      media_type = 1,--video,audio,other
   }
   local pcmu = {
      payload_type = "PCMU_8000_PT",
      encoding_name = "PCMU",
      clock_rate = 8000,
      channels = 1,
      media_type = 1,--video,audio,other
   }
   
   local telephoneevent = {
      payload_type = "TEL_8000_PT",
      encoding_name = "telephone-event",
      clock_rate = 8000,
      channels = 1,
      media_type = 2,--video,audio,other
   }
   info.payloads = {vp8,red,ulpfec,pcmu,telephoneevent}
   return setmetatable(info,{__index=sdp_M})
end
return sdp
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
local b1 = decimal_uchar - P'0' -- -P'127'
local b4 = decimal_uchar - P'0'
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
local media_field = P"m=" * space_cg(media,"media") * (space_cg(port/tonumber,"port")*(P"/" * integer)^-1) * space_cg(proto,"proto") * space_cg(fmt,"fmt")^-1 * crlf,"m"

local attribute_field = P"a=" * C(attribute) * crlf
local attribute_fields = Cg(Ct(attribute_field ^1),"a")

local information_field2 = P"i=" * space_c(text) * crlf
local connection_field2 = P"c=" * Ct(conn1) * crlf
local key_field2 = P"k=" * space_c(text) * crlf
local media_description = 
   Cg(Ct(media_field),"m")  
   * Cg(information_field2^-1,"i")
   * Cg(Ct(connection_field2^0),"c")
   * Cg(Ct(bandwidth_field^1),"b")
   * Cg(key_field2^-1,"k")
   * Cg(Ct(attribute_field^1),"a")
local media_descriptions = Ct(Cg(Ct(Ct(media_description)^1),"m")) --Cg(Ct(media_description^1),"m")

local media_descriptions2 = Cg(Ct(Ct(media_description)^1),"m")
local session_description = 
   Ct(
      proto_version
	 * origin_field
	 * session_name_field
	 * information_field^-1
	 * uri_field^-1
	 * email_field^-1
	 * connection_field^-1
	 * bandwidth_fields
	 * attribute_fields
	 * media_descriptions2
   )

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

function sdp.parse(bin)
   assert(bin and type(bin)=="string")
   local req = session_description:match(bin)
   if not req then
      return false
   end
   return setmetatable(req,{__index = req_meta})
end

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
      "a=aesid:201\r\n"

   assert(att_value:match("mpeg4-esid"))
   local media2 = "m=audio 22 qq 97\r\n"..
      "b=AS:300\r\n"..
      "a=rtpmap:97 H264/90000\r\n"..
      "a=mpeg4esid:201\r\n"..
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
   return st
end

local t =sdp.bnf_test()
local t1 = sdp.build_req(t)
print(t1)
--sdp.test1()
return sdp
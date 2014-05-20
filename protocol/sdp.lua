local lpeg = require "lpeg"
local R, S, V, P = lpeg.R, lpeg.S, lpeg.V, lpeg.P
local C, Ct, Cmt, Cg, Cb, Cc = lpeg.C, lpeg.Ct, lpeg.Cmt, lpeg.Cg, lpeg.Cb, lpeg.Cc
local Cf = lpeg.Cf
local sdp ={}
local crlf = P"\r\n"
local l = {}
lpeg.locale(l)

function sdp.space(pat) 
   local sp = P" "^0
   return sp * pat *sp 
end


local digit = R'09'
local digits = digit^1
local letter = R('az','AZ') + P'-'
local alphanum = digit +  letter 
local name = alphanum^1
local any = l.print^1
local no_sp = l.print - P" "
local no_sps = no_sp^1
--todo fixme
local text = name
local uri = name
local email = name
local phone  = name
local bwtype = name
local attribute = any
function sdp.parse(str)
--rfc 2327 Appendix A
   local proto_version = P"v=" * Cg(l.digit^1,"v") * crlf
   local origin_field = P"o=" * Cg(Ct(sdp.space(C(no_sp))^1) * crlf,"o") 
   local session = P"s=" *Cg(sdp.space(C(text)) * crlf,"s")
   local infomataion = P"i=" *Cg(sdp.space(C(text)) * crlf,"i")
   local uri_field = P"u=" *Cg(sdp.space(C(uri)) * crlf,"u")
   local email_field = P"e=" *sdp.space(C(email)) * crlf
   local email_fields = Cg(Ct(email_field ^1),"e")
   local phone_field = P"p=" *sdp.space(C(phone)) * crlf
   local phone_fields = Cg(Ct(phone_field ^1),"p")
   local conn_field = P"c=" * Cg(Ct(sdp.space(C(text))^1) * crlf,"c") 
   local band_width = P"b=" * Cg(Ct(sdp.space(C(bwtype)) * ":" * sdp.space(C(digits))) * crlf,"b")
   local time_field = P"t=" * Cg(sdp.space(C(text)) * crlf,"t") --todo detail
   local key_field = P"k=" *Cg(sdp.space(C(text)) * crlf,"k") --todo detail
   local media = C(alphanum^1)
   local media_port = digits --todo fix add "/"
   local proto = alphanum + P("/")
   local attr_field = P"a=" * C(attribute) * crlf
   local attr_fields = Cg(Ct(attr_field ^1),"a")
   local media_field = P"m=" * sdp.space(media) * sdp.space(C(media_port)) * sdp.space(C(proto^1))
   local media_desc = media_field * infomataion^0 * conn_field^0 * band_width * key_field^0 * attr_fields^0
   local media_descs = Cg(Ct(media_desc^1),"media")
   local sdp = Ct(proto_version 
		     * origin_field
		     * session
		     * infomataion^0
		     * uri_field^0
		     * email_fields^0
		     * phone_fields^0
		     * conn_field
		     * band_width^0
		     * time_field
		     * key_field^0
		     * attr_fields	 
		     * media_descs
		  ,rawset)
   local r = sdp:match(str)
   return r
end


function sdp.test1()
   local str = "v=1\r\n"..
      "o=- 165 931665148 IN IP4 127.0.0.0\r\n"..
      "s=QuickTime\r\n"..
      "c=IN IP4 127.0.0.1\r\n"..
      "t=0 0\r\n"..
      "a=x-qt-text-an©:railsconf\r\n"..
      "a=range:npt=now-\r\n"..
      "a=isma-compliance:2,2.0,2\r\n"..
      "m=audio 0 RTP/AVP 96\r\n"..
      "b=AS:8\r\n"..
      "a=rtpmap:96 mpeg4-generic/8000/1\r\n"..
      "a=fmtp:96 profile-level-id=15;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config=1588\r\n"..
      "a=mpeg4-esid:101\r\n"..
      "a=control:trackid=1\r\n"..
      "m=video 0 RTP/AVP 97\r\n"..
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
sdp.test1()
return sdp
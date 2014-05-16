--some code from nmap
--
--local cell = require "cell"
local lpeg = require "lpeg"
local text_protocol = require "protocol.text_protocol"
local hive_lib = require "hive.hive_lib"
local Method = {
   INVITE = "INVITE",
   MESSAGE = "MESSAGE",
   REGISTER = "REGISTER"
}

local Status = {
   OK = 200,
   TRYING = 100,
   RING = 180,
   TIMEOUT = 408,
   UNAUTHORIZED = 401,
   FORBIDDEN = 403 
}

local sip_parser = {method = Method,status = Status}
local function trim(s)
    assert(type(s) == "string")
    return s:match "^%s*(.-)%s*$"
end
function sip_parser.parse_via(s)
   local via = {} 
   local i,e,pos 
   local first,second
   pos = 1
   text_protocol.skip_lws(s,pos)
   local _,e  = string.find(s," ",pos)
   first = string.sub(s,pos,e-1)
   pos = e
   text_protocol.skip_lws(s,pos)
   i,e = string.find(s,";",pos)
   if e then
      second = string.sub(s,pos,e-1)
   else
      return false,"no via uri"
   end
   via[1] = first
   via[2] = second
   pos = e 
   while pos <= #s  do
      text_protocol.skip_lws(s,pos)
      local i,lp,rp
      i,_ = string.find(s,";",pos)
      if i then
	 pos = i+1
	 text_protocol.skip_lws(s,pos)
	 e,lp = text_protocol.get_token(s,pos)
	 if not lp then break end
	 pos = e
      else
	break
      end
      i,_ = string.find(s,"=",pos)
      if i then 
	 pos = i +1
	 text_protocol.skip_lws(s,pos)
	 e,rp = text_protocol.get_token(s,pos)
	 if rp then
	    pos = e
	 else

	    return false ,string.format(":%s,have no right value,at %d",s,pos)
	 end
      else
	 return false ,string.format(":%s,have no right value,at %d",s,pos)
      end
      via[lp] = rp
   end
   return true,via
end

function sip_parser.get_via_addr(s)
   assert(s)
   assert(type(s) == "string")
   local ok,v = sip_parser.parse_via(s)
   if ok then
      return sip_parser.p_uri(v[2],5060)
   else
      return ok,v
   end
end
function sip_parser.get_branch(via)
   assert(via)
   assert(type(via) == "string")
   local ok,v = sip_parser.parse_via(via)
   if ok then
      return true,trim(v.branch)
   else
      return ok,v
   end

end

function sip_parser.build_author(author)
   local data = {}
   local k,v
   for k,v in pairs(author) do
      table.insert(data,string.format("%s=\"%s\"",k,v))
   end
   return string.format("%s %s",author[1],hive_lib:strjoin(",",data))   
end

function sip_parser.parse_auth(s)
   local author = {}
   local pos = 1
   text_protocol.skip_lws(s,pos)
   local e,first = text_protocol.get_token(s,pos)
   if not first then
      return false,string.format("%s:no digest",s)
   end
   author[1] =  first
   pos = e +1
   while pos <= #s  do
      text_protocol.skip_lws(s,pos)
      local i,lp,rp
      local i,_ = string.find(s,"=",pos)
      if i then
	 lp = string.sub(s,pos,i-1)
	 pos = i+1
      else
	break
      end
      local i,_ = string.find(s,",",pos)
      if i then 
	 rp = string.sub(s,pos,i-1)
	 pos = i+1
      else
	 --todo add valide 
	 rp = string.sub(s,pos,#s)
      end
      author[lp] = rp
   end
   return true,author
end

function sip_parser.build_req(method,uri,headers,body)
   local data = { }
   local k,v
   table.insert(data,string.format("%s %s SIP/2.0",method,uri))
   if headers then
      for k,v in pairs(headers) do
	 table.insert(data,string.format("%s: %s",k,v))
      end
   end
   if body then
      table.insert(data,string.format("Content-Length:%d\r\n",#body))
      table.insert(data,body)
      return true,hive_lib.strjoin("\r\n",data)
   else
      table.insert(data,"Content-Length:0")
      return true,hive_lib.strjoin("\r\n",data).."\r\n\r\n"
   end
end


local function get_status_desc(s)
   local k,v
   for k,v in pairs(Status) do
      if s == v then
	 return k
      end
   end
end

function sip_parser.build_rep(status,headers,body)
   local data = {}
   local k,v
   assert(status)
   local desc = get_status_desc(status)
   assert(desc)
   table.insert(data,string.format("SIP/2.0 %d %s",status,desc))
   if headers then
      for k,v in pairs(headers) do
	 table.insert(data,string.format("%s:%s",k,v))
      end
   end
   if body then
      table.insert(data,string.format("Content-Length:%d\r\n",#body))
      table.insert(data,body)
      return true,hive_lib.strjoin("\r\n",data)
   else
      table.insert(data,"Content-Length:0")
      return true,hive_lib.strjoin("\r\n",data).."\r\n\r\n"
   end
end


function sip_parser.get_des(req,rep)
   --todo add rule for contact,router
   return sip_parser.p_uri(req.uri,5060)
end
sip_parser.p_uri =function(url,default_port)
   local pos,start
   pos = 1
   start =1
   local _,e = string.find(url,"@",pos)
   if e then
      pos = e+1
      start = pos
   end
   _,pos = string.find(url,":",pos)
   if not pos then
      return true,trim(string.sub(url,start,#url)),default_port
   else
      local ip = string.sub(url,start,pos-1)
      local port = string.sub(url,pos+1,#url)
      --validate data
      return true,trim(ip),tonumber(port)
   end
end

sip_parser.p_addr = function (url, default)
   local uri ={}
   local start
   local pos = 1
   local _,e = string.find(url,"@",pos)
   if not e then
      return false,string.format("not valide url:%s",url)
   end
   pos = e+1
   local _,e = string.find(url,":",pos)
   if e then
      uri.host = trim(string.sub(url,pos,e-1))
      uri.port = tonumber(string.sub(url,e+1,#url))
   else
      uri.host = string.sub(url,pos,#url)
   end
   return uri
end

function sip_parser.get_to(req)
   return sip_parser.get_addr("To",req)
end
function sip_parser.get_from(req)
   return sip_parser.get_addr("From",req)
end

function sip_parser.get_addr(Head,req)
   local s = req.header[Head]
   local pos
   if not s then
      return false,nil
   end
   local to = {}
   local name 

   pos = 1
   text_protocol.skip_lws(s,pos)
   local _, e = string.find(s, "<", pos)
   if not e then
      return false,string.format("%s:have no <",s)
   end
   
   if e ~= pos then
      to[1] = string.sub(s,pos,e-1)
   end
   
   local _, e2 = string.find(s, ">", e)
   if not e2 then 
      return false,string.format("%s:have no >",s)
   end
   local addr = string.sub(s,e+1,e2-1)
   to[2] = addr
   pos = e2 +1
   while pos <= #s  do
      text_protocol.skip_lws(s,pos)
      local i,lp,rp
      i,_ = string.find(s,";",pos)
      if i then
	 pos = i+1
	 text_protocol.skip_lws(s,pos)
	 e,lp = text_protocol.get_token(s,pos)
	 if not lp then break end
	 pos = e
      else
	break
      end
      i,_ = string.find(s,"=",pos)
      if i then 
	 pos = i +1
	 text_protocol.skip_lws(s,pos)
	 e,rp = text_protocol.get_token(s,pos)
	 if rp then
	    pos = e
	 else

	    return false ,string.format(":%s,have no right value,at %d",s,pos)
	 end
      else
	 return false ,string.format(":%s,have no right value,at %d",s,pos)
      end
      to[lp] = rp
   end
   return true,to
end


local function parse_data(socket,sip)
   local ok,heads = text_protocol.recv_header(socket)
   if not ok then
      return ok,heads 
   end
   ok,heads =  text_protocol.parse_header(heads,sip)
   if not ok then
      return ok,heads
   end
   ok,heads = text_protocol.parse_body(socket,sip)
   if not ok then
      return ok,heads
   end
   return true
end

function sip_parser.parse_sip(socket)
   local first = socket:readline("\r\n")
   local version, status, reason_phrase = string.match(first,
						       "^SIP/(%d%.%d) *(%d+) *(.*)")
   if  version then
      local rep = {
	 status=nil,
	 version=nil,
	 ["first-line"]=nil,
	 header={},
	 rawheader={},
	 body=""
      }
      rep.status =  tonumber(status)
      rep.version = tonumber(version)
      rep["first-line"] =  first
      local ok,err = parse_data(socket,rep)
      if ok then 
	 return true,rep
      else
	 return ok,err
      end
   end
   local method,uri
   method,uri,version = string.match(first,
				     "(%a+) *([^%s]+) SIP/(%d%.%d)")
   if version then
      local req = {
	 method=nil,
	 uri=nil,
	 ["first-line"]=nil,
	 header={},
	 rawheader={},
	 body=""
      }
      req.status =  status
      req.method = method
      req.uri = uri
      req["first-line"] =  first
      local ok,err = parse_data(socket,req)
      if ok then
	 return true,req
      else
	 return ok,err
      end
   end
   return false,"sip message not valid:" ..  first
end

local R, S, V, P = lpeg.R, lpeg.S, lpeg.V, lpeg.P
local C, Ct, Cmt, Cg, Cb, Cc = lpeg.C, lpeg.Ct, lpeg.Cmt, lpeg.Cg, lpeg.Cb, lpeg.Cc
function sip_parser.space(pat) 
   local sp = P" "^0
   return sp * pat *sp 
end

function sip_parser.parse_name_addr(s)

   local l = {}
   lpeg.locale(l)
   local sp = l.space^0
   local display_name =sip_parser.space((l.print - P"<")^0)
   local userinfo = (l.print - P"@")^0
   local hostport = C((l.print- S":>")^1) *(P":" * C(l.digit^1))^0
   local scheme = P"sips" + P"sip"
   local sip_uri = C(scheme) * ":" * C(userinfo) * P"@" * hostport         
   local addr_spec = sip_uri --  + absolute_uri
   local name_addr = Ct(C(display_name^-1) * P"<" * sip_uri * P">")
   local t = name_addr:match(s)
   if not t then
      return nil
   end
   local r = {}
   local index = 0
   if t[1] == "sip" or t[1]== "sips" then
   else
      index = index +1
   end
   r.display_name = t[index]
   r.scheme = t[index+1]
   r.name = t[index+2]
   r.ip = t[index+3]
   if t[index+4] then
      r.port = 0 + t[index+4]
   else
      r.port = 5060
   end
   return r
end

function sip_parser.test()
   l = sip_parser.parse_name_addr("name <sips:test@192.168.2.1:5061>")
   print(l.scheme)
end

return sip_parser

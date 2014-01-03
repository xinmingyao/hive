--local cell = require "cell"

local text_protocol = {}
local hivelib = require "hive.hive_lib"

-- Returns the index just past the end of LWS.
local function skip_lws(s, pos)
  local _, e

  while true do
    while string.match(s, "^[ \t]", pos) do
      pos = pos + 1
    end
    _, e = string.find(s, "^\r?\n[ \t]", pos)
    if not e then
      return pos
    end
    pos = e + 1
  end
end


-- Get a token starting at offset. See RFC 2616, section 2.2.
-- @return the first index following the token, or nil if no token was found.
-- @return the token.
local function get_token(s, offset)
  -- All characters except CTL and separators.
  local _, i, token = s:find("^([^()<>@,;:\\\"/%[%]?={} \0\001-\031\127]+)", offset)
  if i then
    return i + 1, token
  else
    return nil
  end
end

local function skip_until_token(s,pos)
   local i,token
   i = pos
   while true  do
      _, i, token = s:find("^([^()<>@,;:\\\"/%[%]?={} \0\001-\031\127]+)", i)
      if i then 
	 return i+1,token
      end
   end
end
local function line_is_empty(line)
  return line == "" 
end
function text_protocol.recv_header(socket)
   local lines = {}
   while true do
      local line
      line = socket:readline("\r\n")
      if line == "timeout" then
	 return false,"timeout"
      end
      if line_is_empty(line) then
	 break
      end
      lines[#lines + 1] = line
   end
   lines[#lines + 1] = ""
   return true,table.concat(lines,"\r\n")
   
end

function text_protocol.parse_body(socket, response)
   if response.header["Content-Length"] then
      local content_length = tonumber(response.header["Content-Length"])
      if not content_length then
	 return false, string.format("Content-Length %q is non-numeric", response.header["Content-length"])
      end
      if content_length >0  then
	 local body = socket:readbytes(content_length)
	 if body == "timeout" then
	    return false,"timeout"
	 end
	 response.body = body
	 return true
      else
	 return true
      end
   else
      return true
   end
end

function text_protocol.parse_header(header, response)
   local pos
   local name, words
   local s, e   
   response.header = {}
   response.rawheader = hivelib.strsplit("\r?\n", header)
   pos = 1
   while pos <= #header do
      -- Get the field name.
      e, name = get_token(header, pos)
      
      if not name or e > #header or string.sub(header, e, e) ~= ":" then
	 return nil, string.format("Can't get header field name at %q", string.sub(header, pos, pos + 30))
      end
      pos = e + 1
      
      -- Skip initial space.
      pos = skip_lws(header, pos)
      -- Get non-space words separated by LWS, then join them with a single space.
      words = {}
      while pos <= #header and not string.match(header, "^\r?\n", pos) do
	 s = pos
	 while not string.match(header, "^[ \t]", pos) and
	 not string.match(header, "^\r?\n", pos) do
	    pos = pos + 1
	 end
	 words[#words + 1] = string.sub(header, s, pos - 1)
	 pos = skip_lws(header, pos)
      end
      
      -- Set it in our table.
      --name = string.lower(name)
      if response.header[name] then
	 response.header[name] = response.header[name] .. ", " .. table.concat(words, " ")
      else
	 response.header[name] = table.concat(words, " ")
      end
      
      -- Next field, or end of string. (If not it's an error.)
      s, e = string.find(header, "^\r?\n", pos)
      if not e then
	 return nil, string.format("Header field named %q didn't end with CRLF", name)
      end
      pos = e + 1
   end
   return true
end


text_protocol.get_token = get_token
text_protocol.skip_lws = skip_lws

return text_protocol
---
-- Standard Nmap Scripting Engine functions. This module contains various handy
-- functions that are too small to justify modules of their own.
--
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
-- @class module
-- @name stdnse

local coroutine = require "coroutine"
local math = require "math"
local os = require "os"
local string = require "string"
local table = require "table"
local assert = assert;
local error = error;
local getmetatable = getmetatable;
local ipairs = ipairs
local pairs = pairs
local next = next
local rawset = rawset
local require = require;
local select = select
local setmetatable = setmetatable;
local tonumber = tonumber;
local tostring = tostring;
local type = type

local ceil = math.ceil
local max = math.max

local format = string.format;
local rep = string.rep

local concat = table.concat;
local insert = table.insert;
local pack = table.pack;
local unpack = table.unpack;

local difftime = os.difftime;
local time = os.time;

local EMPTY = {}; -- Empty constant table

local hive_lib = {}
hive_lib.print_debug = function(level, fmt, ...)
    print(fmt,...)
end

hive_lib.print_verbose = function(level, fmt, ...)
    print(fmt,...)
end


--- Join a list of strings with a separator string.
-- 
-- This is Lua's <code>table.concat</code> function with the parameters
-- swapped for coherence.
-- @usage
-- stdnse.strjoin(", ", {"Anna", "Bob", "Charlie", "Dolores"})
-- --> "Anna, Bob, Charlie, Dolores"
-- @param delimiter String to delimit each element of the list.
-- @param list Array of strings to concatenate.
-- @return Concatenated string.
hive_lib.strjoin = function (delimiter, list)
  assert(type(delimiter) == "string" or type(delimiter) == nil, "delimiter is of the wrong type! (did you get the parameters backward?)")
    
  return concat(list, delimiter);
end

--- Split a string at a given delimiter, which may be a pattern.
-- @usage
-- stdnse.strsplit(",%s*", "Anna, Bob, Charlie, Dolores")
-- --> { "Anna", "Bob", "Charlie", "Dolores" }
-- @param pattern Pattern that separates the desired strings.
-- @param text String to split.
-- @return Array of substrings without the separating pattern.
hive_lib.strsplit = function (pattern, text)
  local list, pos = {}, 1;

  assert(pattern ~= "", "delimiter matches empty string!");

  while true do
    local first, last, match = text:find(pattern, pos);
    if first then -- found?
      list[#list+1] = text:sub(pos, first-1);
      pos = last+1;
    else
      list[#list+1] = text:sub(pos);
      break;
    end
  end

  return list;
end

--- Generate a random string.
-- You can either provide your own charset or the function will use
-- a default one which is [A-Z].
-- @param len Length of the string we want to generate.
-- @param charset Charset that will be used to generate the string.
-- @return A random string of length <code>len</code> consisting of
-- characters from <code>charset</code> if one was provided, otherwise
-- <code>charset</code> defaults to [A-Z] letters.
local function generate_random_string(len, charset)
  local t = {}
  local ascii_A = 65
  local ascii_Z = 90
  if charset then
    for i=1,len do
      t[i]=charset[math.random(#charset)]
    end
  else
    for i=1,len do
      t[i]=string.char(math.random(ascii_A,ascii_Z))
    end
  end
  return table.concat(t)
end



--[[ This function may be usable in Lua 5.2
function lines(socket)
  return make_buffer(socket, "\r?\n"), nil, nil;
end --]]

do
  local t = {
    ["0"] = "0000",
    ["1"] = "0001",
    ["2"] = "0010",
    ["3"] = "0011",
    ["4"] = "0100",
    ["5"] = "0101",
    ["6"] = "0110",
    ["7"] = "0111",
    ["8"] = "1000",
    ["9"] = "1001",
    a = "1010",
    b = "1011",
    c = "1100",
    d = "1101",
    e = "1110",
    f = "1111"
  };

--- Converts the given number, n, to a string in a binary number format (12
-- becomes "1100").
-- @param n Number to convert.
-- @return String in binary format.
local  function tobinary(n)
    assert(tonumber(n), "number expected");
    return (("%x"):format(n):gsub("%w", t):gsub("^0*", ""));
  end
end

--- Converts the given number, n, to a string in an octal number format (12
-- becomes "14").
-- @param n Number to convert.
-- @return String in octal format.
local function tooctal(n)
  assert(tonumber(n), "number expected");
  return ("%o"):format(n)
end

--- Encode a string or number in hexadecimal (12 becomes "c", "AB" becomes
-- "4142").
--
-- An optional second argument is a table with formatting options. The possible
-- fields in this table are
-- * <code>separator</code>: A string to use to separate groups of digits.
-- * <code>group</code>: The size of each group of digits between separators. Defaults to 2, but has no effect if <code>separator</code> is not also given.
-- @usage
-- stdnse.tohex("abc") --> "616263"
-- stdnse.tohex("abc", {separator = ":"}) --> "61:62:63"
-- stdnse.tohex("abc", {separator = ":", group = 4}) --> "61:6263"
-- stdnse.tohex(123456) --> "1e240"
-- stdnse.tohex(123456, {separator = ":"}) --> "1:e2:40"
-- stdnse.tohex(123456, {separator = ":", group = 4}) --> "1:e240"
-- @param s String or number to be encoded.
-- @param options Table specifiying formatting options.
-- @return String in hexadecimal format.
local function tohex( s, options ) 
  options = options or EMPTY
  local separator = options.separator
  local hex

  if type( s ) == "number" then
    hex = ("%x"):format(s)
  elseif type( s ) == 'string' then
    hex = ("%02x"):rep(#s):format(s:byte(1,#s))
  else
    error( "Type not supported in tohex(): " .. type(s), 2 )
  end

  -- format hex if we got a separator
  if separator then
    local group = options.group or 2
    local fmt_table = {}
    -- split hex in group-size chunks
    for i=#hex,1,-group do
      -- table index must be consecutive otherwise table.concat won't work
      fmt_table[ceil(i/group)] = hex:sub(max(i-group+1,1),i)
    end

    hex = concat( fmt_table, separator )
  end

  return hex
end

---Either return the string itself, or return "<blank>" (or the value of the second parameter) if the string
-- was blank or nil.
--
--@param string The base string.
--@param blank  The string to return if <code>string</code> was blank
--@return Either <code>string</code> or, if it was blank, <code>blank</code>
local function string_or_blank(string, blank)
  if(string == nil or string == "") then
    if(blank == nil) then
      return "<blank>"
    else
      return blank
    end
  else
    return string
  end
end

---
-- Parses a time duration specification, which is a number followed by a
-- unit, and returns a number of seconds. The unit is optional and
-- defaults to seconds. The possible units (case-insensitive) are
-- * <code>ms</code>: milliseconds,
-- * <code>s</code>: seconds,
-- * <code>m</code>: minutes,
-- * <code>h</code>: hours.
-- In case of a parsing error, the function returns <code>nil</code>
-- followed by an error message.
--
-- @usage
-- parse_timespec("10") --> 10
-- parse_timespec("10ms") --> 0.01
-- parse_timespec("10s") --> 10
-- parse_timespec("10m") --> 600
-- parse_timespec("10h") --> 36000
-- parse_timespec("10z") --> nil, "Can't parse time specification \"10z\" (bad unit \"z\")"
--
-- @param timespec A time specification string.
-- @return A number of seconds, or <code>nil</code> followed by an error
-- message.
local function parse_timespec(timespec)
  if timespec == nil then return nil, "Can't parse nil timespec" end
  local n, unit, t, m
  local multipliers = {[""] = 1, s = 1, m = 60, h = 60 * 60, ms = 0.001}

  n, unit = string.match(timespec, "^([%d.]+)(.*)$")
  if not n then
    return nil, string.format("Can't parse time specification \"%s\"", timespec)
  end

  t = tonumber(n)
  if not t then
    return nil, string.format("Can't parse time specification \"%s\" (bad number \"%s\")", timespec, n)
  end

  m = multipliers[unit]
  if not m then
    return nil, string.format("Can't parse time specification \"%s\" (bad unit \"%s\")", timespec, unit)
  end

  return t * m
end

-- Find the offset in seconds between local time and UTC. That is, if we
-- interpret a UTC date table as a local date table by passing it to os.time,
-- how much must be added to the resulting integer timestamp to make it
-- correct?
local function utc_offset(t)
  -- What does the calendar say locally?
  local localtime = os.date("*t", t)
  -- What does the calendar say in UTC?
  local gmtime = os.date("!*t", t)
  -- Interpret both as local calendar dates and find the difference.
  return difftime(os.time(localtime), os.time(gmtime))
end
--- Convert a date table into an integer timestamp. Unlike os.time, this does
-- not assume that the date table represents a local time. Rather, it takes an
-- optional offset number of seconds representing the time zone, and returns
-- the timestamp that would result using that time zone as local time. If the
-- offset is omitted or 0, the date table is interpreted as a UTC date. For
-- example, 4:00 UTC is the same as 5:00 UTC+1:
-- <code>
-- date_to_timestamp({year=1970,month=1,day=1,hour=4,min=0,sec=0})          --> 14400
-- date_to_timestamp({year=1970,month=1,day=1,hour=4,min=0,sec=0}, 0)       --> 14400
-- date_to_timestamp({year=1970,month=1,day=1,hour=5,min=0,sec=0}, 1*60*60) --> 14400
-- </code>
-- And 4:00 UTC+1 is an earlier time:
-- <code>
-- date_to_timestamp({year=1970,month=1,day=1,hour=4,min=0,sec=0}, 1*60*60) --> 10800
-- </code>
local function date_to_timestamp(date, offset)
  offset = offset or 0
  return os.time(date) + utc_offset(os.time(date)) - offset
end

local function format_tz(offset)
  local sign, hh, mm

  if not offset then
    return ""
  end
  if offset < 0 then
    sign = "-"
    offset = -offset
  else
    sign = "+"
  end
  -- Truncate to minutes.
  offset = math.floor(offset / 60)
  hh = math.floor(offset / 60)
  mm = math.floor(math.fmod(offset, 60))

  return string.format("%s%02d:%02d", sign, hh, mm)
end
--- Format a date and time (and optional time zone) for structured output.
--
-- Formatting is done according to RFC 3339 (a profile of ISO 8601), except
-- that a time zone may be omitted to signify an unspecified local time zone.
-- Time zones are given as an integer number of seconds from UTC. Use
-- <code>0</code> to mark UTC itself. Formatted strings with a time zone look
-- like this:
-- <code>
-- format_timestamp(os.time(), 0)       --> "2012-09-07T23:37:42+00:00"
-- format_timestamp(os.time(), 2*60*60) --> "2012-09-07T23:37:42+02:00"
-- </code>
-- Without a time zone they look like this:
-- <code>
-- format_timestamp(os.time())          --> "2012-09-07T23:37:42"
-- </code>
--
-- This function should be used for all dates emitted as part of NSE structured
-- output.
local function format_timestamp(t, offset)
  local tz_string = format_tz(offset)
  offset = offset or 0
  return os.date("!%Y-%m-%dT%H:%M:%S", t + offset) .. tz_string
end

--- Format the difference between times <code>t2</code> and <code>t1</code>
-- into a string in one of the forms (signs may vary):
-- * 0s
-- * -4s
-- * +2m38s
-- * -9h12m34s
-- * +5d17h05m06s
-- * -2y177d10h13m20s
-- The string shows <code>t2</code> relative to <code>t1</code>; i.e., the
-- calculation is <code>t2</code> minus <code>t1</code>.
local function format_difftime(t2, t1)
  local d, s, sign, yeardiff

  d = difftime(time(t2), time(t1))
  if d > 0 then
    sign = "+"
  elseif d < 0 then
    sign = "-"
    t2, t1 = t1, t2
    d = -d
  else
    sign = ""
  end
  -- t2 is always later than or equal to t1 here.

  -- The year is a tricky case because it's not a fixed number of days
  -- the way a day is a fixed number of hours or an hour is a fixed
  -- number of minutes. For example, the difference between 2008-02-10
  -- and 2009-02-10 is 366 days because 2008 was a leap year, but it
  -- should be printed as 1y0d0h0m0s, not 1y1d0h0m0s. We advance t1 to be
  -- the latest year such that it is still before t2, which means that its
  -- year will be equal to or one less than t2's. The number of years
  -- skipped is stored in yeardiff.
  if t2.year > t1.year then
    local tmpyear = t1.year
    -- Put t1 in the same year as t2.
    t1.year = t2.year
    d = difftime(time(t2), time(t1))
    if d < 0 then
      -- Too far. Back off one year.
      t1.year = t2.year - 1
      d = difftime(time(t2), time(t1))
    end
    yeardiff = t1.year - tmpyear
    t1.year = tmpyear
  else
    yeardiff = 0
  end

  local s, sec, min
  s = ""
  -- Seconds (pad to two digits).
  sec = d % 60
  d = math.floor(d / 60)
  if d == 0 and yeardiff == 0 then
    return sign .. string.format("%gs", sec) .. s
  end
  s = string.format("%02gs", sec) .. s
  -- Minutes (pad to two digits).
  min = d % 60
  d = math.floor(d / 60)
  if d == 0 and yeardiff == 0 then
    return sign .. string.format("%dm", min) .. s
  end
  s = string.format("%02dm", min) .. s
  -- Hours.
  s = string.format("%dh", d % 24) .. s
  d = math.floor(d / 24)
  if d == 0 and yeardiff == 0 then
    return sign .. s
  end
  -- Days.
  s = string.format("%dd", d) .. s
  if yeardiff == 0 then return sign .. s end
  -- Years.
  s = string.format("%dy", yeardiff) .. s
  return sign .. s
end

---Get the indentation symbols at a given level. 
local function format_get_indent(indent, at_end)
  local str = ""
  local had_continue = false

  if(not(at_end)) then
    str = rep('  ', #indent) -- Was: "|  "
  else
    for i = #indent, 1, -1 do
      if(indent[i] and not(had_continue)) then
        str = str .. "  " -- Was: "|_ "
      else
        had_continue = true
        str = str .. "  " -- Was: "|  "
      end
    end
  end

  return str
end

local function splitlines(s)
  local result = {}
  local i = 0

  while i <= #s do
    local b, e
    b, e = string.find(s, "\r?\n", i)
    if not b then
      break
    end
    result[#result + 1] = string.sub(s, i, b - 1)
    i = e + 1
  end

  if i <= #s then
    result[#result + 1] = string.sub(s, i)
  end

  return result
end


---Takes a table of output on the commandline and formats it for display to the 
-- user. This is basically done by converting an array of nested tables into a 
-- string. In addition to numbered array elements, each table can have a 'name' 
-- and a 'warning' value. The 'name' will be displayed above the table, and 
-- 'warning' will be displayed, with a 'WARNING' tag, if and only if debugging
-- is enabled. 
-- 
-- Here's an example of a table:
-- <code>
--   local domains = {}
--   domains['name'] = "DOMAINS"
--   table.insert(domains, 'Domain 1')
--   table.insert(domains, 'Domain 2')
-- 
--   local names = {}
--   names['name'] = "NAMES"
--   names['warning'] = "Not all names could be determined!"
--   table.insert(names, "Name 1")
-- 
--   local response = {}
--   table.insert(response, "Apple pie")
--   table.insert(response, domains)
--   table.insert(response, names)
-- 
--   return stdnse.format_output(true, response)
-- </code>
--
-- With debugging enabled, this is the output:
-- <code>
--   Host script results:
--   |  smb-enum-domains:
--   |    Apple pie
--   |    DOMAINS
--   |      Domain 1
--   |      Domain 2
--   |    NAMES (WARNING: Not all names could be determined!)
--   |_     Name 1
-- </code>
--
--@param status A boolean value dictating whether or not the script succeeded. 
--              If status is false, and debugging is enabled, 'ERROR' is prepended
--              to every line. If status is false and debugging is disabled, no output
--              occurs. 
--@param data   The table of output. 
--@param indent Used for indentation on recursive calls; should generally be set to
--              nil when callling from a script. 
-- @return <code>nil</code>, if <code>data</code> is empty, otherwise a
-- multiline string.
local function format_output(status, data, indent)
  -- If data is nil, die with an error (I keep doing that by accident)
  assert(data, "No data was passed to format_output()")

  -- Don't bother if we don't have any data
  if (#data == 0) then
    return nil
  end

  local result = format_output_sub(status, data, indent)

  -- Check for an empty result
  if(result == nil or #result == "" or result == "\n" or result == "\n") then
    return nil
  end

  return result
end


--- Parses the script arguments passed to the --script-args option.
--
-- @usage
-- --script-args 'script.arg1=value,script.arg3,script-x.arg=value'
-- local arg1, arg2, arg3 = get_script_args('script.arg1','script.arg2','script.arg3')
--      => arg1 = value
--      => arg2 = nil
--      => arg3 = 1
--
-- --script-args 'displayall,unsafe,script-x.arg=value,script-y.arg=value'
-- local displayall, unsafe = get_script_args('displayall','unsafe')
--      => displayall = 1
--      => unsafe     = 1
--
-- --script-args 'dns-cache-snoop.mode=timed,dns-cache-snoop.domains={host1,host2}'
-- local mode, domains = get_script_args('dns-cache-snoop.mode',
--                                       'dns-cache-snoop.domains')
--      => mode    = 'timed'
--      => domains = {host1,host2}
--
-- @param Arguments  Script arguments to check.
-- @return Arguments values.
hive_lib.get_script_args = function  (...)
  local args = {}

  for i, set in ipairs({...}) do 
    if type(set) == "string" then
      set = {set}
    end
    for _, test in ipairs(set) do
      local v = arg_value(test)
      if v then
        args[i] = v
        break
      end
    end
  end

  return unpack(args, 1, select("#", ...))
end

---Get the best possible hostname for the given host. This can be the target as given on 
-- the commandline, the reverse dns name, or simply the ip address. 
--@param host The host table (or a string that'll simply be returned). 
--@return The best possible hostname, as a string. 
hive_lib.get_hostname = function (host)
  if type(host) == "table" then
    return host.targetname or ( host.name ~= '' and host.name ) or host.ip
  else
    return host
  end
end



--- This function allows you to create worker threads that may perform
-- network tasks in parallel with your script thread.
--
-- Any network task (e.g. <code>socket:connect(...)</code>) will cause the
-- running thread to yield to NSE. This allows network tasks to appear to be
-- blocking while being able to run multiple network tasks at once.
-- While this is useful for running multiple separate scripts, it is
-- unfortunately difficult for a script itself to perform network tasks in
-- parallel. In order to allow scripts to also have network tasks running in
-- parallel, we provide this function, <code>stdnse.new_thread</code>, to
-- create a new thread that can perform its own network related tasks
-- in parallel with the script.
--
-- The script launches the worker thread by calling the <code>new_thread</code>
-- function with the parameters:
-- * The main Lua function for the script to execute, similar to the script action function.
-- * The variable number of arguments to be passed to the worker's main function.
--
-- The <code>stdnse.new_thread</code> function will return two results:
-- * The worker thread's base (main) coroutine (useful for tracking status).
-- * A status query function (described below).
--
-- The status query function shall return two values:
-- * The result of coroutine.status using the worker thread base coroutine.
-- * The error object thrown that ended the worker thread or <code>nil</code> if no error was thrown. This is typically a string, like most Lua errors.
--
-- Note that NSE discards all return values of the worker's main function. You
-- must use function parameters, upvalues or environments to communicate
-- results.
--
-- You should use the condition variable (<code>nmap.condvar</code>)
-- and mutex (<code>nmap.mutex</code>) facilities to coordinate with your
-- worker threads. Keep in mind that Nmap is single threaded so there are
-- no (memory) issues in synchronization to worry about; however, there
-- is resource contention. Your resources are usually network
-- bandwidth, network sockets, etc. Condition variables are also useful if the
-- work for any single thread is dynamic. For example, a web server spider
-- script with a pool of workers will initially have a single root html
-- document. Following the retrieval of the root document, the set of
-- resources to be retrieved (the worker's work) will become very large
-- (an html document adds many new hyperlinks (resources) to fetch).
--@name new_thread
--@class function
--@param main The main function of the worker thread.
--@param ... The arguments passed to the main worker thread.
--@return co The base coroutine of the worker thread.
--@return info A query function used to obtain status information of the worker.
--@usage
--local requests = {"/", "/index.html", --[[ long list of objects ]]}
--
--function thread_main (host, port, responses, ...)
--  local condvar = nmap.condvar(responses);
--  local what = {n = select("#", ...), ...};
--  local allReqs = nil;
--  for i = 1, what.n do
--    allReqs = http.pGet(host, port, what[i], nil, nil, allReqs);
--  end
--  local p = assert(http.pipeline(host, port, allReqs));
--  for i, response in ipairs(p) do responses[#responses+1] = response end
--  condvar "signal";
--end
--
--function many_requests (host, port)
--  local threads = {};
--  local responses = {};
--  local condvar = nmap.condvar(responses);
--  local i = 1;
--  repeat
--    local j = math.min(i+10, #requests);
--    local co = stdnse.new_thread(thread_main, host, port, responses,
--        table.unpack(requests, i, j));
--    threads[co] = true;
--    i = j+1;
--  until i > #requests;
--  repeat
--    condvar "wait";
--    for thread in pairs(threads) do
--      if coroutine.status(thread) == "dead" then threads[thread] = nil end
--    end
--  until next(threads) == nil;
--  return responses;
--end
do end -- no function here, see nse_main.lua

--- Returns the base coroutine of the running script.
--
-- A script may be resuming multiple coroutines to facilitate its own
-- collaborative multithreading design. Because there is a "root" or "base"
-- coroutine that lets us determine whether the script is still active
-- (that is, the script did not end, possibly due to an error), we provide
-- this <code>stdnse.base</code> function that will retrieve the base
-- coroutine of the script. This base coroutine is the coroutine that runs
-- the action function.
--
-- The base coroutine is useful for many reasons but here are some common
-- uses:
-- * We want to attribute the ownership of an object (perhaps a network socket) to a script.
-- * We want to identify if the script is still alive.
--@name base
--@class function
--@return coroutine Returns the base coroutine of the running script.
do end -- no function here, see nse_main.lua

--- The Lua Require Function with errors silenced.
--
-- See the Lua manual for description of the require function. This modified
-- version allows the script to quietly fail at loading if a required
-- library does not exist.
--
--@name silent_require
--@class function
--@usage stdnse.silent_require "openssl"
do end -- no function here, see nse_main.lua



---Checks if the port is in the port range
-- For example, calling:
-- <code>in_port_range({number=31337,protocol="udp"},"T:15,50-75,U:31334-31339")</code>
-- would result in a true value
--@param port a port structure containing keys port number(number) and protocol(string)
--@param port_range a port range string in Nmap standard format (ex. "T:80,1-30,U:31337,21-25")
--@returns boolean indicating whether the port is in the port range
local function in_port_range(port,port_range)
	assert(port and type(port.number)=="number" and type(port.protocol)=="string" and 
			(port.protocol=="udp" or port.protocol=="tcp"),"Port structure missing or invalid: port={ number=<port_number>, protocol=<port_protocol> }")
	assert((type(port_range)=="string" or type(port_range)=="number") and port_range~="","Incorrect port range specification.")
	
	-- Proto - true for TCP, false for UDP
	local proto
	if(port.protocol=="tcp") then proto = true else proto = false end
	
	--TCP flag for iteration - true for TCP, false for UDP, if not specified we presume TCP
	local tcp_flag = true
	
	-- in case the port_range is a single number 
	if type(port_range)=="number" then
		if proto and port_range==port.number then return true
		else return false
		end
	end
	
	--clean the string a bit
	port_range=port_range:gsub("%s+","")
	
	-- single_pr - single port range
	for i, single_pr in ipairs(strsplit(",",port_range)) do
		if single_pr:match("T:") then
			tcp_flag = true
			single_pr = single_pr:gsub("T:","")
		else 
			if single_pr:match("U:") then 
				tcp_flag = false 
				single_pr = single_pr:gsub("U:","")
			end
		end
		
		-- compare ports only when the port's protocol is the same as
		-- the current single port range
		if tcp_flag == proto then
			local pone = single_pr:match("^(%d+)$")
			if pone then
				pone = tonumber(pone)
				assert(pone>-1 and pone<65536, "Port range number out of range (0-65535).")
				
				if pone == port.number then 
					return true 
				end
			else
				local pstart, pend = single_pr:match("^(%d+)%-(%d+)$")
				pstart, pend = tonumber(pstart), tonumber(pend)
				assert(pstart,"Incorrect port range specification.")
				assert(pstart<=pend,"Incorrect port range specification, the starting port should have a smaller value than the ending port.")
				assert(pstart>-1 and pstart<65536 and pend>-1 and pend<65536, "Port range number out of range (0-65535).")
				
				if port.number >=pstart and port.number <= pend then
					return true
				end
			end
		end
	end
	-- if no match is found then the port doesn't belong to the port_range
	return false
end

--- Module function that mimics some behavior of Lua 5.1 module function.
--
-- This convenience function returns a module environment to set the _ENV
-- upvalue. The _NAME, _PACKAGE, and _M fields are set as in the Lua 5.1
-- version of this function. Each option function (e.g. stdnse.seeall)
-- passed is run with the new environment, in order.
--
-- @see stdnse.seeall
-- @see strict
-- @usage
--   _ENV = stdnse.module(name, stdnse.seeall, require "strict");
-- @param name The module name.
-- @param ... Option functions which modify the environment of the module.
local function module (name, ...)
  local env = {};
  env._NAME = name;
  env._PACKAGE = name:match("(.+)%.[^.]+$");
  env._M = env;
  local mods = pack(...);
  for i = 1, mods.n do
    mods[i](env);
  end
  return env;
end

--- Change environment to load global variables.
--
-- Option function for use with stdnse.module. It is the same
-- as package.seeall from Lua 5.1.
--
-- @see stdnse.module
-- @usage
--  _ENV = stdnse.module(name, stdnse.seeall);
-- @param env Environment to change.
local function seeall (env)
  local m = getmetatable(env) or {};
  m.__index = _G;
  setmetatable(env, m);
end

--- Return a table that keeps elements in order of insertion.
--
-- The pairs function, called on a table returned by this function, will yield
-- elements in the order they were inserted. This function is meant to be used
-- to construct output tables returned by scripts.
--
-- Reinserting a key that is already in the table does not change its position
-- in the order. However, removing a key by assigning to <code>nil</code> and
-- then doing another assignment will move the key to the end of the order.
--
-- @return An ordered table.
local function output_table ()
  local t = {}
  local order = {}
  local function iterator ()
    for i, key in ipairs(order) do
      coroutine.yield(key, t[key])
    end
  end
  local mt = {
    __newindex = function (_, k, v)
      if t[k] == nil and v ~= nil then
        -- New key?
        table.insert(order, k)
      elseif v == nil then
        -- Deleting an existing key?
        for i, key in ipairs(order) do
          if key == k then
            table.remove(order, i)
            break
          end
        end
      end
      rawset(t, k, v)
    end,
    __index = function (_, k)
      return t[k]
    end,
    __pairs = function (_)
      return coroutine.wrap(iterator)
    end,
    __call = function (_) -- hack to mean "not_empty?"
      return not not next(order)
    end
  }
  return setmetatable({}, mt)
end

--- A pretty printer for Lua objects.
--
-- Takes an object (usually a table) and prints it using the
-- printer function. The printer function takes a sole string
-- argument and will be called repeatedly.
--
-- @args obj The object to pretty print.
-- @args printer The printer function.
local function pretty_printer (obj, printer)
  if printer == nil then printer = print end

  local function aux (obj, spacing)
    local t = type(obj)
    if t == "table" then
      printer "{\n"
      for k, v in pairs(obj) do
        local spacing = spacing.."\t"
        printer(spacing)
        printer "["
        aux(k, spacing)
        printer "] = "
        aux(v, spacing)
        printer ",\n"
      end
      printer(spacing.."}")
    elseif t == "string" then
      printer(format("%q", obj))
    else
      printer(tostring(obj))
    end
  end

  return aux(obj, "")
end

-- This pattern must match the percent sign '%' since it is used in
-- escaping.
local FILESYSTEM_UNSAFE = "[^a-zA-Z0-9._-]"
---
-- Escape a string to remove bytes and strings that may have meaning to
-- a filesystem, such as slashes. All bytes are escaped, except for:
-- * alphabetic <code>a</code>-<code>z</code> and <code>A</code>-<code>Z</code>, digits 0-9, <code>.</code> <code>_</code> <code>-</code>
-- In addition, the strings <code>"."</code> and <code>".."</code> have
-- their characters escaped.
--
-- Bytes are escaped by a percent sign followed by the two-digit
-- hexadecimal representation of the byte value.
-- * <code>filename_escape("filename.ext") --> "filename.ext"</code>
-- * <code>filename_escape("input/output") --> "input%2foutput"</code>
-- * <code>filename_escape(".") --> "%2e"</code>
-- * <code>filename_escape("..") --> "%2e%2e"</code>
-- This escaping is somewhat like that of JavaScript
-- <code>encodeURIComponent</code>, except that fewer bytes are
-- whitelisted, and it works on bytes, not Unicode characters or UTF-16
-- code points.
local function filename_escape(s)
  if s == "." then
    return "%2e"
  elseif s == ".." then
    return "%2e%2e"
  else
    return (string.gsub(s, FILESYSTEM_UNSAFE, function (c)
      return string.format("%%%02x", string.byte(c))
    end))
  end
end

return hive_lib;


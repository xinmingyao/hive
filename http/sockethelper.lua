local cell = require "cell"
local sockethelper = {}
local socket_error = setmetatable({} , { __tostring = function() return "[Socket Error]" end })

sockethelper.socket_error = socket_error

function sockethelper.readfunc(fd)
   local sock = cell.bind(fd)
   return function (sz)
      local ret = sock:readbytes(sz)
      if ret then
	 return ret
      else
	 error(socket_error)
      end
   end
end

function sockethelper.writefunc(fd)
   local sock = cell.bind(fd)
   return function(content)
      sock:write(content)
   end
end

return sockethelper

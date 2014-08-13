local cell = require "cell"
local mcu_tool = require "mcu.mcu_tool"
local meetings ={}
local meeting_no = 1

local function get_meeting_no()
   meeting_no = meeting_no + 1
   return meeting_no
end

cell.command {
   auth = function(data)
      local user = data.user
      local jid = user .. "@mt.com"
      return true,jid
   end
}

function cell.main(msg,gui)

end

local cell = require "cell"
local mcu_tool = require "mcu.mcu_tool"
local meetings ={}
local meeting_no = 0

local function get_meeting_no()
   meeting_no = meeting_no + 1
   return meeting_no
end

cell.command {
   create_meeting= function(user,meet)
      local mt_no = get_meeting_no()
      meet.host_name = user
      meetings[mt_no] = meet
      return mt_no
   end,
   list_meeting = function(T)
      local r = {}
      for k,v in ipairs(meetings) do
	 local tmp = {}
	 tmp.name = v.name
	 tmp.host_name = v.name
	 tmp.statue = v.statue
	 tmp.create_time = v.create_time
	 table.insert(r,tmp)
      end
      return r
   end
}

function cell.main(msg,gui)

end

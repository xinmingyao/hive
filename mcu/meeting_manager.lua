local cell = require "cell"
local meetings = {}

cell.command {
   join_meeting= function(data,user)
      local mt_no = data.meeting_no
      assert(mt_no,"must have meetng no!")
      if not meetings[mt_no] then
	 local service = cell.command("launch","mcu.meeting",mt_no)
	 meetings[mt_no] = service
      end
      local r2 = cell.call(meetings[mt_no],"join_meeting",user_name)
      return true
   end
}
function cell.main(...)

end

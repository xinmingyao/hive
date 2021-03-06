local c = require "hivecore"
package.path = package.path .. ";./test/?.lua;./?.lua;./ssl/?.lua"
local system_cell = assert(package.searchpath("hive.system", package.path),"system cell was not found")

local hive = {}

function hive.start(t)
	local main = assert(package.searchpath(t.main, package.path), "main cell was not found")
	if t.gui then
	local gui = package.searchpath(t.gui, package.path)
		return c.start(t, system_cell, main,gui)
	else
		return c.start(t, system_cell, main)
	end
end

return hive

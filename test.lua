package.cpath = package.cpath ..";./ssl/?.so".. ";./?.dylib"
package.path = package.path .. ";./ssl/?.lua"
local main = ...
local hive = require "hive"
if not main then
   main = "test.main"
end
hive.start {
   thread = 4,
   main = main,
}


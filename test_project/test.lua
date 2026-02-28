-- test.lua

function run()
    -- VULNERABILITY LUA001
    os.execute("rm -rf /tmp/stuff")
    
    -- VULNERABILITY LUA002
    local f = loadstring("print('evil code')")
end

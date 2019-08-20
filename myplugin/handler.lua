-- If you're not sure your plugin is executing, uncomment the line below and restart Kong
-- then it will throw an error which indicates the plugin is being loaded at least.

--assert(ngx.get_phase() == "timer", "The world is coming to an end!")

http = require "resty.http"
cjson = require "cjson.safe"
sso={"http://111.203.146.69/oauth/check_token","http://sso-smart.cast.org.cn:8080/oauth/check_token"}
auth={"http://111.203.146.69/oauth/authorize?client_id=talent&redirect_uri=/oauth/code?back_to=http://210.14.118.96/ep/cookie_talent.html&response_type=code&scope=read",
      "http://sso-smart.cast.org.cn:8080/oauth/authorize?client_id=talent&redirect_uri=/oauth/code?back_to=http://210.14.118.96/ep/cookie_talent.html&response_type=code&scope=read"}
sso_index=0
cookie=nil
forward_ip=nil
token=nil

--[[
do some preparation
]]--
function prepare()
  if forward_ip == nil 
  then
    kong.log.error("no forward_ip,return error")
    kong.response.exit(500, "An unexpected error occurred:there is no forward_ip")
  else
    if string.find(forward_ip,"210.14.118.96") then 
      sso_index=0 
    elseif string.find(forward_ip,"210.14.118.96") or string.find(forward_ip,"smart.cast.org.cn") then
      sso_index=1
    else
      kong.response.exit(500,"An unexpected error occurred:forward_ip should be 210.14.118.96/95 or smart.cast.org.cn")
    end
  end

--[[
get token from cookie
]]--
function get_token()
  if cookie ~=nil 
  then
    --kong.log(cookie)
    local pattern="token=[a-z0-9]{4,20}-[a-z0-9]{4,20}-[a-z0-9]{4,20}-[a-z0-9]{4,20}-[a-z0-9]{4,20}"
    local start,endd=string.find(cookie,pattern)
    if start ~= nil 
    then 
      token=string.sub(cookie,start+6,endd)
      -- ngx.req.set_header("apikey",key)
      --kong.service.request.add_header("apikey",key)
      --kong.log(ngx.req.get_headers())
      --kong.log(kong.request.get_header('apikey'))
    else
      kong.response.exit(401,"Unauthorized:there is no token or format of token is invalid")
    end
  else
    kong.response.exit(401,"Unauthorized:there is no token or format of token is invalid")
  end
 
--[[
get information from oauth server by checking token
handle information , such as  add consumer infrmation for kay_auth or create consumer 
consider set consumer information in cache 
--]]
function handle_token()
  local httpc= http:new()
  local res,err=httpc:request_uri(sso[sso_index],{
    method = "GET",
    headers={
      ["grant_type"]="authorization_code",
      ["token"]=token
    }
  })

  -- response
  if res 
  then
    if res.status ~= 200 
    then
      kong.response.exit(401,"Unauthorized:token is invalid",{["Location"]=auth[sso_index]})
    else
      local json = cjson.decode(res.body)
      if json ~= nil and  json["PERSON_ID"] ~= nil then
        -- configure nginx log to add my_username my_username_1
        nginx.request.set_header("my_username",json["PERSON_ID"])
        kong.service.request.add_header("my_username_1",json["PERSON_ID"])
        kong.log(ngx.req.get_headers())
      end
    end
  else
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    return
  end


-- Grab pluginname from module name
local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")

-- load the base plugin object and create a subclass
local plugin = require("kong.plugins.base_plugin"):extend()

-- constructor
function plugin:new()
  plugin.super.new(self, plugin_name)

  -- do initialization here, runs in the 'init_by_lua_block', before worker processes are forked

end

---------------------------------------------------------------------------------------------
-- In the code below, just remove the opening brackets; `[[` to enable a specific handler
--
-- The handlers are based on the OpenResty handlers, see the OpenResty docs for details
-- on when exactly they are invoked and what limitations each handler has.
--
-- The call to `.super.xxx(self)` is a call to the base_plugin, which does nothing, except logging
-- that the specific handler was executed.
---------------------------------------------------------------------------------------------


--[[ handles more initialization, but AFTER the worker process has been forked/created.
-- It runs in the 'init_worker_by_lua_block'
function plugin:init_worker()
  plugin.super.init_worker(self)

  -- your custom code here

end --]]

--[[ runs in the ssl_certificate_by_lua_block handler
function plugin:certificate(plugin_conf)
  plugin.super.certificate(self)

  -- your custom code here

end --]]

--[[ runs in the 'rewrite_by_lua_block' (from version 0.10.2+)
-- IMPORTANT: during the `rewrite` phase neither the `api` nor the `consumer` will have
-- been identified, hence this handler will only be executed if the plugin is
-- configured as a global plugin!
function plugin:rewrite(plugin_conf)
  plugin.super.rewrite(self)

  -- your custom code here

end --]]

---[[ runs in the 'access_by_lua_block'
function plugin:access(plugin_conf)
  plugin.super.access(self)

  -- your custom code here
 -- cookie=ngx.req.get_header("Cookie")
  cookie=kong.request.get_header("Cookie")
  forward_ip=kong.client.get_forwarded_ip()
  
  prepare()

  -- get token
  get_token()
 
  -- check token
  handle_token()



--[[
  if cookie ~=nil then
    kong.log(cookie)
    start,endd=string.find(cookie,"apikey")
    if start ~= nil then 
      key=string.sub(cookie,endd+1)
      kong.log(key)
      -- ngx.req.set_header("apikey",key)
      kong.service.request.add_header("apikey",key)
      kong.log(ngx.req.get_headers())
      kong.log(kong.request.get_header('apikey'))
    end
  end
  ]]--
  --ngx.req.set_header("Hello-World", "this is on a request")

end --]]

---[[ runs in the 'header_filter_by_lua_block'
--[[function plugin:header_filter(plugin_conf)
  plugin.super.header_filter(self)

  -- your custom code here, for example;
  ngx.header["Bye-World"] = "this is on the response"

end --]]
--]]
--[[ runs in the 'body_filter_by_lua_block'
function plugin:body_filter(plugin_conf)
  plugin.super.body_filter(self)

  -- your custom code here

end --]]

--[[ runs in the 'log_by_lua_block'
function plugin:log(plugin_conf)
  plugin.super.log(self)

  -- your custom code here

end --]]


-- set the plugin priority, which determines plugin execution order
plugin.PRIORITY = 1010
-- > 1000 key auth

-- return our plugin object
return plugin

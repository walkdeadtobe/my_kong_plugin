local http = require "resty.http"
local cjson = require "cjson.safe"
local aes = require "resty.aes"
local str = require "resty.string"



local _M={}
local sso={"http://111.203.146.69/oauth/check_token","http://sso-smart.cast.org.cn:8080/oauth/check_token"}
local auth={"http://111.203.146.69/oauth/authorize?client_id=keixe&redirect_uri=/oauth/code?back_to=http://210.14.118.96/ep/cookie.html&response_type=code&scope=read",
            "http://111.203.146.69/oauth/authorize?client_id=talent&redirect_uri=/oauth/code?back_to=http://210.14.118.96/ep/cookie_talent.html&response_type=code&scope=read",
            "http://sso-smart.cast.org.cn:8080/oauth/authorize?client_id=kexie&redirect_uri=/oauth/code?back_to=http://210.14.118.96/ep/cookie.html&response_type=code&scope=read",
            "http://sso-smart.cast.org.cn:8080/oauth/authorize?client_id=talent&redirect_uri=/oauth/code?back_to=http://210.14.118.96/ep/cookie_talent.html&response_type=code&scope=read"
          }


local sso_index=0
local auth_index=0
local cookie=nil
local forward_ip=nil
local http_refer=nil
local token=nil



function _M.run()
 -- cookie=ngx.req.get_header("Cookie")
  cookie=kong.request.get_header("Cookie")
  forward_ip=kong.client.get_forwarded_ip()
  http_refer=kong.request.get_header("http_referer")
  local path=kong.request.get_path_with_query()
  local path_pattern="/api/v1/data/(oauth|talent|recommendation)/((34fa6f5dcaec9149a513c0193002e77d|e6c2550b9b069be64a79d8a40bf94bed)\\?code=[0-9a-zA-Z]{1,10}&client_id=(kexie|talent)|(7b98d44dd0595d3a6928d658703c78a6|425d095b3404e19c3e8ae59c7ffe9548|f7c4905ebed8186fa5eaa462856f1be4|daef336118adb6d93875b742255dce4c))"
  local start,endd,err=ngx.re.find(path,path_pattern)
  kong.log("path0:",path)
  if start == nil then
    kong.log("path1:",path)
    prepare()
    -- get token
    get_token()
    -- check token
    handle_token()
  end

  start,endd,err=ngx.re.find("qqaaq","qq")
  if start ~= nil then
    kong.log("qqaaq",start)
  end
end

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


--[[
do some preparation
]]--
function prepare()
  if forward_ip == nil 
  then
    kong.log.error("no forward_ip,return error")
    kong.response.exit(500, "An unexpected error occurred:there is no forward_ip")
  else
    kong.log("forward_ip=",forward_ip)
    if string.find(forward_ip,"210.14.118.96") then 
      sso_index=1 --数组从1开始计数 
    elseif string.find(forward_ip,"210.14.118.96") or string.find(forward_ip,"smart.cast.org.cn") then
      sso_index=2
    else
      kong.response.exit(500,"An unexpected error occurred:forward_ip should be 210.14.118.96/95 or smart.cast.org.cn")
    end
  end

  if http_refer == nil 
  then
    -- 默认请求来源 210.14.118.96/95
    kong.log("there is no  http_referer ")
    -- 后面需要用到这个变量
    http_refer="null"
    auth_index=0
  else
    kong.log("http_referer=",http_refer)
    if string.find(http_refer,"ep") or string.find(http_refer,"talent") then 
      --默认请求来源 210.14.118.96/ep 或 默认请求来源 210.14.118.95/talent 
      sso_index=1 
    else
      sso_index=0
    end
  end
end

--[[
get token from cookie
]]--
function get_token()
  if cookie ~=nil 
  then
    kong.log("cookie=",cookie)
    local pattern="token=[a-z0-9]{4,20}-[a-z0-9]{4,20}-[a-z0-9]{4,20}-[a-z0-9]{4,20}-[a-z0-9]{4,20}"
    local start,endd,err=ngx.re.find(cookie,pattern)
    if start ~= nil 
    then 
      token=string.sub(cookie,start+6,endd)
      kong.log("token=",token)
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
end
--[[
get information from oauth server by checking token
handle information , such as  add consumer infrmation for kay_auth or create consumer 
consider set consumer information in cache 
--]]
function handle_token()
  local httpc= http:new()
  local res,err=httpc:request_uri(sso[sso_index].."?grant_type=authorization_code&token="..token,{
    method = "GET",
    --[[headers={
      ["grant_type"]="authorization_code",
      ["token"]=token
    }]]--
  })

  -- response
  if res 
  then
    if res.status ~= 200 
    then
      kong.response.exit(401,"Unauthorized:token is invalid",{["Location"]=auth[sso_index].."&refer="..http_refer})
    else
      kong.log("res.status = 200 ")
      local json = cjson.decode(res.body)
      if json == nil then 
        kong.response.exit(500,"oauth server response empty body")
      end
      if json.status ~= 200 then
        kong.response.exit(401,"Unauthorized:token is invalid",{["Location"]=auth[sso_index].."&refer="..http_refer})
      end
      if json["PERSON_ID"] ~= nil then
        -- configure nginx log to add my_username my_username_1
        kong.log("personid=",json["PERSON_ID"])
        ngx.req.set_header("my_username_1",json["PERSON_ID"])
        kong.service.request.add_header("my_username",json["PERSON_ID"])
        kong.log("my_username",kong.request.get_header("my_username"))
        encrypt(json["PERSON_ID"])
      end
    end
  else
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    return
  end
end

function encrypt(username)
  local len=#token
  local secert_apponit="_secert"
  local secert=""
  local count=0
  for i=1,len do
    if 45 == string.byte(token,i) then
      secert=secert..tostring(count%10)
      count=0
    else
      count=count+string.byte(token,i)
    end
  end
  secert=secert..tostring(count%10)..secert_apponit
  kong.log("secert:",secert)
  local aes_128_cbc_md5 = aes:new(secert)
        -- the default cipher is AES 128 CBC with 1 round of MD5
        -- for the key and a nil salt
  local encrypted = aes_128_cbc_md5:encrypt(username)
  kong.log(username," 加密后为 ",str.to_hex(encrypted))
  ngx.req.set_header("encrypt_use",str.to_hex(encrypted))
  kong.service.request.add_header("encrypt_use",str.to_hex(encrypted))

end





return _M 


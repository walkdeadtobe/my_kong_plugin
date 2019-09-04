local http = require "resty.http"
local cjson = require "cjson.safe"
local aes = require "resty.aes"
local resty_md5 = require "resty.md5"
local str = require "resty.string"



local _M={}
local sso={"http://111.203.146.69/oauth/check_token","http://sso-smart.cast.org.cn:8080/oauth/check_token"}
local auth={"http://111.203.146.69/oauth/authorize?client_id=kexie&redirect_uri=/oauth/code?back_to=http://210.14.118.96/ep/cookie.html&response_type=code&scope=read",
            "http://111.203.146.69/oauth/authorize?client_id=talent&redirect_uri=/oauth/code?back_to=http://210.14.118.96/ep/cookie_talent.html&response_type=code&scope=read",
            "http://sso-smart.cast.org.cn:8080/oauth/authorize?client_id=kexie&redirect_uri=/oauth/code?back_to=http://smart.cast.org.cn/talent/cookie.html&response_type=code&scope=read",
            "http://sso-smart.cast.org.cn:8080/oauth/authorize?client_id=talent&redirect_uri=/oauth/code?back_to=http://smart.cast.org.cn/talent/cookie_talent.html&response_type=code&scope=read"
          }
--无需指明location，由前端页面指明refer=window.location
--[[
local sso_index=2
local auth_index=1
local cookie=nil
local forward_ip=nil
local http_refer=nil
local token=nil
--]]
--variable ={sso_index,auth_index,cookie=nil,forward_ip,http_refer,token}


function _M.run()
 -- cookie=ngx.req.get_header("Cookie")
  local my_variable={}
  local cookie=kong.request.get_header("Cookie")
  local forward_ip=kong.client.get_forwarded_ip()
  local http_refer=kong.request.get_header("referer")
  my_variable['sso_index']=2
  my_variable['auth_index']=1
  my_variable['cookie']=cookie
  my_variable['forward_ip']=forward_ip
  my_variable['http_refer']=http_refer
  local path=kong.request.get_path_with_query()
  local path_pattern="/api/v1/data/(oauth|talent|recommendation|dzk|dxs|dkp|zhiku|kejie|qczx)/"..
                     "((34fa6f5dcaec9149a513c0193002e77d|e6c2550b9b069be64a79d8a40bf94bed)\\?code=[0-9a-zA-Z]{1,10}&client_id=(kexie|talent)|"..
                     "(7b98d44dd0595d3a6928d658703c78a6|425d095b3404e19c3e8ae59c7ffe9548|f7c4905ebed8186fa5eaa462856f1be4|daef336118adb6d93875b742255dce4c|00eb8edafbc1a314967ef2e09984b97f|54f69a4614f3a06d444a63f339f68c1f|17e277023035d4a260259de5fb2e6c96|d26ab175092ef64d46ac3b54a0c00797|46223c24d04342c978087d6de0a3dcc5|96c3ea9283687775dbbac5f380842f3a|33713bba5afe32cafe719afd445adb89|fc0c864c56d424d7b0d4d7a7db82b584|09d475ff63fd0cc2edc49f1c6f972ce3|9d293aeec8e747ab866bc4918ee30e8d))"
  local start,endd,err=ngx.re.find(path,path_pattern)
  kong.log("path0:",path)
  if start == nil then
    kong.log("path1:",path)
    my_variable=prepare(my_variable)
    -- get token
    my_variable=get_token(my_variable)
    -- check token
    handle_token(my_variable)
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
function prepare(my_variable)
  local forward_ip=my_variable['forward_ip']
  local sso_index=my_variable['sso_index']
  local http_refer=my_variable['http_refer']
  if forward_ip == nil 
  then
    kong.log.error("no forward_ip,return error")
    kong.response.exit(500, "An unexpected error occurred:there is no forward_ip")
  else
    kong.log("forward_ip=",forward_ip)
    if string.find(forward_ip,"210.14.118.96") then 
      my_variable['sso_index']=1 --数组从1开始计数 
    elseif string.find(forward_ip,"210.14.118.95") or string.find(forward_ip,"smart.cast.org.cn") then
      my_variable['sso_index']=2
    else
      --kong.response.exit(500,"An unexpected error occurred:forward_ip should be 210.14.118.96/95 or smart.cast.org.cn")
    end
  end

  if http_refer == nil 
  then
    -- 默认请求来源 210.14.118.96/95
    kong.log("there is no  http_referer ")
    -- 后面需要用到这个变量
    my_variable['auth_index']=1
  else
    kong.log("http_referer=",http_refer)
    if string.find(http_refer,"ep") or string.find(http_refer,"talent") then 
      --默认请求来源 210.14.118.96/ep 或 默认请求来源 210.14.118.95/talent 
      my_variable['auth_index']=2
    else
      my_variable['auth_index']=1
    end
  end
  return my_variable
end

--[[
get token from cookie
]]--
function get_token(my_variable)
  local cookie=my_variable['cookie']
  if cookie ~=nil 
  then
    kong.log("cookie=",cookie)
    local pattern="token=[a-z0-9]{4,20}-[a-z0-9]{4,20}-[a-z0-9]{4,20}-[a-z0-9]{4,20}-[a-z0-9]{4,20}"
    local start,endd,err=ngx.re.find(cookie,pattern)
    if start ~= nil 
    then 
      token=string.sub(cookie,start+6,endd)
      my_variable['token']=token
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
  return my_variable
end
--[[
get information from oauth server by checking token
handle information , such as  add consumer infrmation for kay_auth or create consumer 
consider set consumer information in cache 
--]]
function handle_token(my_variable)
  local sso_index=my_variable['sso_index']
  local auth_index=my_variable['auth_index']
  local token=my_variable['token']
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
      kong.response.exit(401,"Unauthorized:token is invalid",{["Location"]=auth[(sso_index-1)*2+auth_index]})
    else
      kong.log("res.status = 200 ")
      local json = cjson.decode(res.body)
      if json == nil then 
        kong.response.exit(500,"oauth server response empty body")
      end
      if json.status ~= 200 then
        kong.response.exit(401,"Unauthorized:token is invalid",{["Location"]=auth[(sso_index-1)*2+auth_index]})
      end
      if json["PERSON_ID"] ~= nil then
        -- configure nginx log to add my_username my_username_1
        kong.log("personid=",json["PERSON_ID"])
        ngx.req.set_header("username-1",json["PERSON_ID"])
        kong.service.request.add_header("username",json["PERSON_ID"])
        kong.log("my_username",kong.request.get_header("username"))
        encrypt(json["PERSON_ID"],token)
      end
    end
  else
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    return
  end
end

function encrypt(username,token)
  local len=#token
  local time=os.date("%Y-%m-%d-%H-%M")
  local secert=""
  local count=0
  for i=1,len do
    if 45 == string.byte(token,i) then
      secert=secert.."0"..tostring(count%10)
      count=0
    else
      count=count+string.byte(token,i)
    end
  end
  secert=secert.."0"..tostring(count%10).."secret"
  kong.log("secert:",username..secert..time)
  local md5 = resty_md5:new()
  local ok = md5:update(token..time)
  if not ok then
      ngx.say("failed to add data")
      return
  end
  local digest = md5:final()
  kong.log("md5: ", str.to_hex(digest))
  ngx.req.set_header("md5sum",str.to_hex(digest))
  ---[[
  local aes_128_cbc_md5 = aes:new(secert,nil,aes.cipher(128,"cbc"), {iv="1234567890123456"})
        -- the default cipher is AES 128 CBC with 1 round of MD5
        -- for the key and a nil salt
  len=16-#username
  for i=1,len do
    username=username.."x"
  end
  ngx.req.set_header("usename++:",username)
  local encrypted = aes_128_cbc_md5:encrypt(username)
  kong.log(username," 加密后为 ",str.to_hex(encrypted))
  ngx.req.set_header("encrypt1",(encrypted))
  ngx.req.set_header("encrypt",str.to_hex(encrypted))
  --kong.service.request.add_header("encrypt",str.to_hex(encrypted))
  ---]]

end

function api_key(name)
  --初始账户体系中包含有空格的账户名，在这里同步时默认去除
  name=string.gsub(name," ","")
  local md5 = resty_md5:new()
  local ok = md5:update(name)
  if not ok then
      ngx.say("failed to add data")
      return
  end
  local digest = str.to_hex(digestmd5:final())
  kong.log("name md5: ", str.to_hex(digest))
  ngx.req.set_header("md5sum",str.to_hex(digest))
  
  local len=#digest
  local key=""
  local count=0
  for i=1,len do
    if string.byte(digest,i)>=97 then
      key=key..string.char((string.byte(digest,i)-97+13)%26+97)
    else
      key=key..string.char((string.byte(digest,i)-48+5)%10+48)
    end
  end
  kong.log("apikey:",key)
  ngx.req.set_header("apikey",key)

end



return _M 


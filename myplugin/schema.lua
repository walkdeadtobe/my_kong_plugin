local typedefs = require "kong.db.schema.typedefs"
return {
  no_consumer = true,
  --no_consumer = true, -- this plugin is available on APIs as well as on Consumers,
  fields = {
    -- Describe your plugin's configuration's schema here.
    sso_domain = { type = "string", default = "http://sso-smart.cast.org.cn:8080"},
    check_path = { type = "string", default = "/oauth/check_token" },
    front_domain = { type = "string", default = "http://smart.cast.org.cn"},
    client = {
            type = "record",
            --required = true,
            fields = {
              { kexie = { type = "string", default = "sso_domain/oauth/authorize?client_id=kexie&redirect_uri=/oauth/code?back_to=front_domain/ep/cookie.html&response_type=code&scope=read"},}
              { talent = { type = "string", default = "sso_domain/oauth/authorize?client_id=talent&redirect_uri=/oauth/code?back_to=front_domain/ep/cookie_talent.html&response_type=code&scope=read"},}
            },
          }, 
  },
  self_check = function(schema, plugin_t, dao, is_updating)
    -- perform any custom verification
    return true
  end
}

local typedefs = require "kong.db.schema.typedefs"
return {
  name = "myplugin"
  --no_consumer = true, -- this plugin is available on APIs as well as on Consumers,
  fields = {
    -- Describe your plugin's configuration's schema here.
    { consumer = typedefs.no_consumer },
    { run_on = typedefs.run_on_first },
    { protocols = typedefs.protocols_http },
    { config = {
      type = "record",
      fields = {
        { 
          sso_domain = {
            type = "string",
            default = "http://sso-smart.cast.org.cn:8080"
          },
          check_path = {
            type = "string",
            default = "/oauth/check_token"
          },
          front_domain = {
            type = "string",
            default = "http://smart.cast.org.cn"
          },
          client = {
            type = "table",
            --required = true,
            default = {
            kexie = "sso_domain/oauth/authorize?client_id=kexie&redirect_uri=/oauth/code?back_to=front_domain/ep/cookie.html&response_type=code&scope=read",
            talent = "sso_domain/oauth/authorize?client_id=talent&redirect_uri=/oauth/code?back_to=front_domain/ep/cookie_talent.html&response_type=code&scope=read",
            },
          },


          }, 
        },
        
        --{ anonymous = { type = "string", uuid = true, legacy = true }, },
        --{ key_in_body = { type = "boolean", default = false }, },
      },
  }, },
    
  },
  self_check = function(schema, plugin_t, dao, is_updating)
    -- perform any custom verification
    return true
  end
}

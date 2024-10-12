using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using pushNotification.service.cdp.core.config;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<KeycloakOptions>(builder.Configuration.GetSection("Keycloak"));
builder.Services.Configure<CloudOptions>(builder.Configuration.GetSection("CloudConfig"));
//builder.Services.AddHostedService<PubSubSubscriberService>();

builder.Services.AddHttpClient("SkipSSL").ConfigurePrimaryHttpMessageHandler(() =>
{
    var httpClientHandler = new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
    };

    httpClientHandler.Proxy = null;
    httpClientHandler.UseProxy = false;

    httpClientHandler.CheckCertificateRevocationList = false;
    httpClientHandler.ServerCertificateCustomValidationCallback = (message, cert, chain, erros) => { return true; };

    return httpClientHandler;
});



builder.Services.AddMemoryCache();
builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie()
.AddOpenIdConnect(options =>
{
    var keycloakOptions = builder.Configuration.GetSection("Keycloak").Get<KeycloakOptions>();
    options.Authority = keycloakOptions.ServerRealmEndpoint;

    options.ClientId = keycloakOptions.KH_SSO_ClientId;
    options.ClientSecret = keycloakOptions.KH_SSO_ClientSecret;
    
    options.ResponseType = OpenIdConnectResponseType.Code;

    options.RequireHttpsMetadata = false;
    options.SaveTokens = true;

    options.Scope.Add("openid");
    options.Scope.Add("profile");

    options.TokenValidationParameters = new TokenValidationParameters
    {
        NameClaimType = "preferred_username",
        RoleClaimType = "roles"
    };

    options.BackchannelHttpHandler = new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        //ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
    };

    // @ KeyPoint:組合成完整的URL For Keycloak Plugin 程式碼去做解析

    // 全行打到CDP會帶如下QueryString
    // ?Token=20298A8C31F94609B87972F1FC9DF998&UserID=95352&EncTicket=8575ED1C0F13DE883E945F4EDDC8FB81&username=95352&langCode=ZHT&ssousername=95352&clientType=&site2pstoretoken=&AppName=X100206&Field=Int

    // 完整Url類似如下,
    // https://localhost:51022/signin-oidc?Token=20298A8C31F94609B87972F1FC9DF998&UserID=95352&EncTicket=8575ED1C0F13DE883E945F4EDDC8FB81&username=95352&langCode=ZHT&ssousername=95352&clientType=&site2pstoretoken=&AppName=X100206&Field=Int

    // 故protocol/openid-connect/auth 這一段IdentityProvider解析，Keycloak Plugin程式碼會去抓redirect_uri後面QueryString給行內SSO Server去做Invalid
    options.Events = new OpenIdConnectEvents
    {

        OnRedirectToIdentityProvider =  context =>
        {
            // 判斷處

            var request = context.Request;

            var originalQueryString = request.QueryString.Value.Substring(1);

            // For KH 額外客製 (暫解)

            if (request.HasFormContentType)
            {
                // Read form data
                var formData = context.Request.ReadFormAsync().Result;

                if (formData.ContainsKey("txtToken"))
                {
                    // KH SSO
                    context.ProtocolMessage.ClientId = keycloakOptions.KH_SSO_ClientId;
                    context.ProtocolMessage.ClientSecret = keycloakOptions.KH_SSO_ClientSecret;

                    var txtToken = formData["txtToken"];
                    context.ProtocolMessage.RedirectUri += "?IDP_TOKEN=" + Uri.EscapeDataString(txtToken);
                }
            }
            else
            {
                //Cathay SSO
                context.ProtocolMessage.ClientId = keycloakOptions.KH_SSO_ClientId;
                context.ProtocolMessage.ClientSecret = keycloakOptions.KH_SSO_ClientSecret;
                context.ProtocolMessage.RedirectUri += "?IDP_TOKEN=" + originalQueryString;

                /*
                context.ProtocolMessage.ClientId = keycloakOptions.Master_SSO_ClientId;
                context.ProtocolMessage.ClientSecret = keycloakOptions.Master_SSO_ClientSecret;
                context.ProtocolMessage.RedirectUri = context.ProtocolMessage.RedirectUri + originalQueryString;      
                */
            }


            Console.WriteLine($"Redirect to identity Provider, the RedirectUri is {context.ProtocolMessage.RedirectUri}");
            return Task.CompletedTask;
        },

        OnAuthorizationCodeReceived = context =>
        {
            Console.WriteLine($"Authorization code received, the code is {context.ProtocolMessage.Code}");
            return Task.CompletedTask;
        },

        OnTokenResponseReceived = ctx =>
        {
            Console.WriteLine($"Token Response Received");
            return Task.CompletedTask;
        },

        OnTokenValidated = ctx =>
        {
            Console.WriteLine($"Token validated for {ctx.Principal.Identity.Name}");
            return Task.CompletedTask;
        },
        OnAuthenticationFailed = ctx =>
        {
            Console.WriteLine($"Authentication failed: {ctx.Exception.Message}");
            return Task.CompletedTask;
        },
        
    };
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});

//app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();

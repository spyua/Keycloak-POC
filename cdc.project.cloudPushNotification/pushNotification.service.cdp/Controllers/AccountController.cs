using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using pushNotification.service.cdp.core.config;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;

namespace pushNotification.service.cdp.Controllers
{

    /// <summary>
    /// For SSO Login Test Usage
    /// </summary>
    [ApiController]
    [Route("api/user")]
    public class AccountController : ControllerBase
    {

        private readonly ILogger<AccountController> _logger;
        private readonly KeycloakOptions _keycloakConfig;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IMemoryCache _memoryCache;
        private Dictionary<string, string> _userNoInfo;

        public AccountController(ILogger<AccountController> logger
                               , IOptions<KeycloakOptions> keycloakConfig
                               , IHttpClientFactory httpClientFactory
                               , IMemoryCache memoryCache)
        {
            _logger = logger;
            _keycloakConfig = keycloakConfig.Value;
            _httpClientFactory = httpClientFactory;
            _memoryCache = memoryCache;
            _userNoInfo = new Dictionary<string, string>();
        }


        [HttpGet(nameof(CustomLoginSSO))]
        public IActionResult CustomLoginSSO()
        {

            // Keycloak的授權端點URL
            var authRequestUri = "https://ovs-cp-lnk-01-keycloak.gcubut.gcp.uwccb/realms/ChannelWeb/protocol/openid-connect/auth";

            // (!!這裡注意!!) 這邊For Demo而已，建議可用Dictionary <Token, Querystring>處理.
            _memoryCache.Set("idp_query_string", Request.QueryString);

            // (!!!這裡關鍵!!!)重導向URI - 用戶完成登入後將被重導回此URI，並附帶授權碼
            var redirectUri = $"https://ovs-cp-lnk-01-cdp.gcubut.gcp.uwccb/api/user/CustomLoginSSOCallback{Request.QueryString}";

            // 構建授權請求的查詢參數
            var queryParams = new Dictionary<string, string>
            {
                {"client_id", _keycloakConfig.ClientId},
                {"response_type", "code"},
                {"scope", "openid"},
                {"redirect_uri", redirectUri}
                // 可選：如果需要，可以加入"state"和"nonce"參數以增強安全性
            };

            // 將查詢參數轉換為URL編碼的字串
            var queryString = string.Join("&", queryParams.Select(kv => $"{HttpUtility.UrlEncode(kv.Key)}={HttpUtility.UrlEncode(kv.Value)}"));

            // 完整的重導向URL
            var finalRedirectUri = $"{authRequestUri}?{queryString}";

            _logger.LogDebug($"redirectUri: {redirectUri}");
            // 記錄Request相關的訊息
            _logger.LogDebug($"Request.Method: {Request.Method}");
            _logger.LogDebug($"Request.Headers: {Request.Headers}");
            _logger.LogDebug($"Request.Body: {Request.Body}");


            // 重導向到Keycloak的登入頁面
            return Redirect(finalRedirectUri);
        }

        [HttpGet(nameof(CustomLoginSSOCallback))]
        public async Task<IActionResult> CustomLoginSSOCallback(string code) // 接收授權碼
        {
            var tokenEndpoint = "https://ovs-cp-lnk-01-keycloak.gcubut.gcp.uwccb/realms/ChannelWeb/protocol/openid-connect/token";
            var client = _httpClientFactory.CreateClient("SkipSSL");

            // (!!這裡注意!!) 這邊For Demo而已，建議可用Dictionary <Token, Querystring>處理.
            var idpQueryString = _memoryCache.Get("idp_query_string");

            // (!!!這裡關鍵!!!)重導向URI - 必須與獲取授權碼請求中的URI匹配，所以這邊也會有idpQueryString
            var redirectUri = $"https://ovs-cp-lnk-01-cdp.gcubut.gcp.uwccb/api/user/CustomLoginSSOCallback{idpQueryString}";

            var tokenRequestContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("client_id", _keycloakConfig.ClientId),
                new KeyValuePair<string, string>("client_secret", _keycloakConfig.ClientSecret), // 如果客戶端是機密的，需要此參數
                new KeyValuePair<string, string>("code", code),
                new KeyValuePair<string, string>("redirect_uri", redirectUri)
            });

            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/x-www-form-urlencoded"));

            var response = await client.PostAsync(tokenEndpoint, tokenRequestContent);
            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                // 解析回應內容來獲取令牌
                // 處理令牌（例如，保存令牌，使用令牌調用受保護的資源等）

                // 記錄回應內容
                _logger.LogDebug($"responseContent: {responseContent}");

                return Ok(responseContent); // 或者將用戶導向另一個頁面
            }

            // 記錄錯誤訊息
            _logger.LogDebug($"無法從Keycloak獲得令牌：{response.StatusCode}");
            return BadRequest("無法從Keycloak獲得令牌");
        }

        [HttpGet(nameof(GetKeycloakResponse))]
        public async Task<string> GetKeycloakResponse()
        {
            const string apiUrl = "https://ovs-cp-lnk-01-keycloak.gcubut.gcp.uwccb"; // Replace with target URL

            var client = _httpClientFactory.CreateClient("SkipSSL");

            var response = await client.GetAsync(apiUrl);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                // 解析回應內容來獲取令牌
                // 處理令牌（例如，保存令牌，使用令牌調用受保護的資源等）

                // 記錄回應內容
                _logger.LogDebug($"responseContent: {responseContent}");

                return responseContent; // 或者將用戶導向另一個頁面
            }

            return "ERROR";
        }

        [HttpGet(nameof(EsiGetKeycloakResponse))]
        public async Task<string> EsiGetKeycloakResponse()
        {
            const string apiUrl = "https://ovs-cp-lnk-01-keycloak.gcubut.gcp.uwccb"; // Replace with target URL

            try
            {
                // Call SendRequest for GET with no request body
                using HttpResponseMessage response = await SendRequest<object, HttpResponseMessage>(apiUrl, HttpMethod.Get, null);

                // Ensure successful response
                response.EnsureSuccessStatusCode();

                // Read response content as string
                string content = await response.Content.ReadAsStringAsync();

                _logger.LogInformation($"Return content:{content}");

                return content;
            }
            catch (HttpRequestException ex)
            {
                // Handle request exceptions (e.g., network issues)
                _logger.LogInformation($"Error getting Google response: {ex.Message}");
                throw; // Rethrow for further handling if needed
            }
            catch (Exception ex)
            {
                // Handle general exceptions
                _logger.LogInformation($"Unexpected error: {ex.Message}");
                throw; // Rethrow for further handling if needed
            }
        }

        public async Task<TResponse> SendRequest<TRequest, TResponse>(string apiUrl, HttpMethod httpMethod, HttpClient httpClient = null, TRequest request = default(TRequest))
        {
            var bypassCertificateValid = true;
            bool httpClientFromOutSide = true;
            try
            {
                _logger.LogInformation($"No1. SendRequest Start");

                if (httpClient == null)
                {
                    var handler = new SocketsHttpHandler();
                    var sslOptions = new SslClientAuthenticationOptions();

                    if (bypassCertificateValid)
                    {
                        sslOptions.RemoteCertificateValidationCallback = delegate { return true; };
                    }

                    sslOptions.CertificateChainPolicy = new X509ChainPolicy { DisableCertificateDownloads = true };
                    handler.SslOptions = sslOptions;
                    httpClient = new HttpClient(handler);



                    httpClientFromOutSide = false;
                    _logger.LogInformation($"No2. new HttpClientHandler");
                    /*
                    var handler = new SocketsHttpHandler()
                    {
                        SslOptions = new SslClientAuthenticationOptions
                        {
                            RemoteCertificateValidationCallback = delegate { return true; },
                            CertificateChainPolicy = new X509ChainPolicy
                            {
                                DisableCertificateDownloads = true
                            }
                        }
                    };
                    */

                }

                HttpRequestMessage httpRequestMessage = new HttpRequestMessage
                {
                    RequestUri = new Uri(string.Format(apiUrl)),
                    Method = httpMethod
                };

                _logger.LogInformation($"No3. new HttpRequestMessage");

                if (httpMethod != HttpMethod.Get && !EqualityComparer<TRequest>.Default.Equals(request, default(TRequest)))
                {
                    ByteArrayContent content = ((!((object)request is ByteArrayContent byteArrayContent)) ? new StringContent(JsonConvert.SerializeObject(request), Encoding.UTF8, "application/json") : byteArrayContent);
                    httpRequestMessage.Content = content;
                }

                _logger.LogInformation($"No4. new StringContent");

                TResponse result;

                _logger.LogInformation($"No5. Ready SendAsync");

                if (typeof(TResponse) == typeof(HttpResponseMessage))
                {


                    result = (TResponse)(object)(await httpClient.SendAsync(httpRequestMessage));
                    _logger.LogInformation($"No6. HttpResponseMessage");
                }
                else
                {


                    using HttpResponseMessage response = await httpClient.SendAsync(httpRequestMessage);
                    string text = await response.Content.ReadAsStringAsync();
                    result = (TResponse)((!(typeof(TResponse) == typeof(string))) ? ((object)JsonConvert.DeserializeObject<TResponse>(text)) : ((object)(TResponse)(object)text));

                    _logger.LogInformation($"No7. HttpResponseMessage");
                }



                return result;
            }
            catch (Exception)
            {
                throw;
            }
            finally
            {
                if (!httpClientFromOutSide)
                {
                    httpClient.Dispose();
                }
            }
        }

        /*
        [HttpGet(nameof(CustomLoginSSO))]
        public async Task<IActionResult> CustomLoginSSO()
        {
            var client = _httpClientFactory.CreateClient();
            var authRequestUri = "https://ovs-cp-lnk-01-keycloak.gcubut.gcp.uwccb/realms/ChannelWeb/protocol/openid-connect/auth";

            var requestContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("client_id", _keycloakConfig.ClientId),
                new KeyValuePair<string, string>("response_type", "code"),
                new KeyValuePair<string, string>("scope", "openid"),
                new KeyValuePair<string, string>("redirect_uri", $"http://localhost:51022/api/user/TestGet?{Request.QueryString}"),
            });

            var response = await client.PostAsync(authRequestUri, requestContent);
            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                // 處理回應內容
                return Content(responseContent);
            }

            return BadRequest("無法從Keycloak獲得回應");
        }
        */

        [Authorize]
        [HttpGet(nameof(Login))]
        public async Task<string> Login()
        {
            _logger.LogInformation("Login sucess");

            var accessToken = await HttpContext.GetTokenAsync("access_token");
            _logger.LogInformation("access_token:" + accessToken);

            var idToken = await HttpContext.GetTokenAsync("id_token");
            _logger.LogInformation("idToken:" + idToken);

            var refreshToken = await HttpContext.GetTokenAsync("refresh_token");
            _logger.LogInformation("refreshToken:" + refreshToken);

            return "SSO Auth check ok";
        }

        //[Authorize]
        [HttpGet(nameof(TestGet))]
        public string TestGet(string hostName)
        {
            IPAddress[] addresses = Dns.GetHostAddresses(hostName);

            var addressStringBuilder = new StringBuilder();
            if (addresses.Length == 0)
            {
                Console.WriteLine($"No addresses found for hostname: {hostName}");
            }
            else
            {
                Console.WriteLine($"Addresses for hostname: {hostName}");
                foreach (IPAddress address in addresses)
                {
                    Console.WriteLine(address);
                    addressStringBuilder.AppendLine(address.ToString());
                }
            }

            return addressStringBuilder.ToString();
        }
    }
}
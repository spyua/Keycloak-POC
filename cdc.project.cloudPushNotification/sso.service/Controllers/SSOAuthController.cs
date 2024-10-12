using Microsoft.AspNetCore.Mvc;
using sso.service.Dto;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace MockSSOService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class SSOAuthController : ControllerBase
    {
        private static readonly Dictionary<string, string> MockSessionKeys = new Dictionary<string, string>
        {
            { "validSessionKey", "User123" },
            { "expiredSessionKey", "UserExpired" }
        };

        [HttpGet(nameof(TestGet))]
        public string TestGet()
        {
            return "Test OK";
        }


        [HttpPost("verify")]
        public IActionResult VerifySessionKey([FromBody] SessionKeyDto sessionKeyDto)
        {
            if (sessionKeyDto == null || string.IsNullOrEmpty(sessionKeyDto.sessionKey))
            {
                return BadRequest(new KHVerifyResponseData
                {
                    ResponseCode = "200",
                    ResponseDesc = "Session key is null or empty"
                });
            }

            var idpSessionKey = sessionKeyDto.sessionKey;

            if (MockSessionKeys.ContainsKey(idpSessionKey))
            {
                if (idpSessionKey == "expiredSessionKey")
                {
                    return Unauthorized(new KHVerifyResponseData
                    {
                        ResponseCode = "401",
                        ResponseDesc = "Session key expired"
                    });
                }

                return Ok(new KHVerifyResponseData
                {
                    ResponseCode = "200",
                    ResponseDesc = "Verification successful, user: " + MockSessionKeys[idpSessionKey]
                });
            }

            return NotFound(new KHVerifyResponseData
            {
                ResponseCode = "200",
                ResponseDesc = "Session key not found"
            });
        }
    }

    public class KHVerifyResponseData
    {
        public string ResponseCode { get; set; }
        public string ResponseDesc { get; set; }
    }
}

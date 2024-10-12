using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace keycloak_sso_net6.Controllers
{
 
    [ApiController]
    [Route("api/user")]
    public class UserVerifyController : ControllerBase
    {

        private readonly ILogger<UserVerifyController> _logger;

        public UserVerifyController(ILogger<UserVerifyController> logger)
        {
            _logger = logger;
        }

        [Authorize]
        [HttpGet(nameof(Login))]
        public string Login()
        {
            return "auth check ok";
        
        }

        [Authorize]
        [HttpGet(nameof(GetAccount))]
        public string GetAccount()
        {
            return "Mario";
        }
    }
}

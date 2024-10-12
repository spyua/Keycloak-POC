using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace keycloak_role_net6.Controllers
{

    [ApiController]
    [Route("api/policy-role")]
    public class PolicyRoleController : ControllerBase
    {
        private readonly ILogger<PolicyRoleController> _logger;

        public PolicyRoleController(ILogger<PolicyRoleController> logger)
        {
            _logger = logger;
        }


        [Authorize(Policy = "MustHaveGetRole")]
        [HttpGet(nameof(ReadWrite))]
        public string ReadWrite()
        {
            return "ReadWrite";
        }

    }
}

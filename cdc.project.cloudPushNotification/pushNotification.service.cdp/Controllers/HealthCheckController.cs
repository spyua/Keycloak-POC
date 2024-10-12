using Microsoft.AspNetCore.Mvc;

namespace pushNotification.service.cdp.Controllers
{

    [ApiController]
    [Route("/")]
    public class HealthCheckController
    {
        private readonly ILogger<HealthCheckController> logger;

        public HealthCheckController(ILogger<HealthCheckController> logger)
        {
            this.logger = logger;
        }

        [HttpGet]
        public string GetRoot()
        {
            return "RESTful Service Work";
        }
    }


}

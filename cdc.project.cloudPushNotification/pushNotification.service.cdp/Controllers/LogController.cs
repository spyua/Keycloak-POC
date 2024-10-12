using Microsoft.AspNetCore.Mvc;
using NLog;

namespace pushNotification.service.cdp.Controllers
{
    [ApiController]
    [Route("api/logtest")]
    public class LogController : ControllerBase
    {
        private readonly NLog.ILogger _logger;

        public LogController()
        {
            _logger = LogManager.GetCurrentClassLogger();
        }

        [HttpGet(nameof(LogInfo))]
        public async Task<string> LogInfo()
        {
            _logger.Info("GetInfo", "Info Info Info Info Info");
            return "Log Info";
        }

        [HttpGet(nameof(LogError))]
        public async Task<string> LogError()
        {
            _logger.Error("GetError", "Error Error Error Error Error");
            return "Log Error";
        }


        [HttpGet(nameof(LogWarring))]
        public async Task<string> LogWarring()
        {
            _logger.Warn("GetWarring", "Warring Warring Warring Warring Warring");
            return "Log Warring";
        }

    }
}

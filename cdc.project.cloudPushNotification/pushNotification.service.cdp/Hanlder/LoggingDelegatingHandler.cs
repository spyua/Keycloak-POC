namespace pushNotification.service.cdp.Hanlder
{
    public class LoggingDelegatingHandler : DelegatingHandler
    {
        private readonly ILogger<LoggingDelegatingHandler> _logger;

        public LoggingDelegatingHandler(ILogger<LoggingDelegatingHandler> logger)
        {
            _logger = logger;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // 在發送請求前記錄URL和參數
            _logger.LogInformation($"Sending request to {request.RequestUri} with method {request.Method}");
            Console.WriteLine($"Sending request to {request.RequestUri} with method {request.Method}");
            if (request.Content != null)
            {
                var requestContent = await request.Content.ReadAsStringAsync();
                _logger.LogInformation($"Request content: {requestContent}");
                Console.WriteLine($"Request content: {requestContent}");
            }

            // 發送請求
            var response = await base.SendAsync(request, cancellationToken);

            // 這裡可以記錄響應信息，如果需要的話
             _logger.LogInformation(await response.Content.ReadAsStringAsync());

            return response;
        }
    }
}

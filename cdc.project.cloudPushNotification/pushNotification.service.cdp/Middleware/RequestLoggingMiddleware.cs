namespace pushNotification.service.cdp.Middleware
{
    public class RequestLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RequestLoggingMiddleware> _logger;

        public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {

            // 在這裡記錄進入的請求信息
            _logger.LogInformation($"Middlewar Incoming request: {context.Request.Method} {context.Request.Path}");
            Console.WriteLine($"Middlewar Incoming request: {context.Request.Method} {context.Request.Path}");
            // 記錄查詢字符串參數
            if (context.Request.QueryString.HasValue)
            {
                _logger.LogInformation($"Middlewar Query string: {context.Request.QueryString.Value}");
                Console.WriteLine($"Middlewar Query string: {context.Request.QueryString.Value}");
            }

            // 如果需要記錄表單數據，確保請求的Content-Type是application/x-www-form-urlencoded或multipart/form-data
            if (context.Request.HasFormContentType)
            {
                var formData = await context.Request.ReadFormAsync();
                foreach (var pair in formData)
                {
                    _logger.LogInformation($"Middlewar Form data: {pair.Key} = {pair.Value}");
                    Console.WriteLine($"Middlewar Form data: {pair.Key} = {pair.Value}");
                }
            }

            // 調用管道中的下一個中間軟體
            await _next(context);
        }
    }
}

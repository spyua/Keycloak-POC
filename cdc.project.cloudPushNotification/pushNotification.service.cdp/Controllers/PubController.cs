using Google.Cloud.PubSub.V1;
using Microsoft.AspNetCore.Mvc;
using pushNotification.service.cdp.core.config;
namespace pushNotification.service.cdp.Controllers
{
    /// <summary>
    /// For Test Pub Sub Usage
    /// </summary>

    [ApiController]
    [Route("api/pub")]
    public class PubController : ControllerBase
    {
        private readonly CloudOptions _cloudOption; 
        private readonly ILogger<PubController> _logger;

        private SubscriberClient _subscriber;
       
        public PubController(CloudOptions cloudOption, ILogger<PubController> logger)
        {
            _cloudOption = cloudOption;
            _logger = logger;

        }

        [HttpPost(nameof(PublishMessage))]
        public async Task<IActionResult> PublishMessage([FromBody] string message)
        {
            
            TopicName topicName = TopicName.FromProjectTopic(_cloudOption.ProjectId, _cloudOption.TopicId);
            _logger.LogInformation("Topic ID:" + topicName.TopicId);
          
            PublisherClient publisher = await PublisherClient.CreateAsync(topicName);
            _logger.LogInformation("Topic Name:" + publisher.TopicName);

            byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(message);  // Conflic witch  Google.Cloud.PubSub.V1 

            string messageId = await publisher.PublishAsync(messageBytes);
            _logger.LogInformation("Publish message id:" + messageId);

            return Ok(new { TopicId = topicName.TopicId
                            , TopicName = publisher.TopicName
                            , MessageId = messageId });
        }
    }
}

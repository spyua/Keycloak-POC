using Google.Cloud.PubSub.V1;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using pushNotification.service.cdp.core.config;

namespace pushNotification.service.cdp.Service
{
    /// <summary>
    /// For Sub Test Usage
    /// </summary>
    public class PubSubSubscriberService : BackgroundService
    {
        private readonly CloudOptions _cloudOption;
        private readonly ILogger<PubSubSubscriberService> _logger;
        private SubscriberClient _subscriber;

        public PubSubSubscriberService(IOptions<CloudOptions> cloudConfig, ILogger<PubSubSubscriberService> logger)
        {
            _cloudOption = cloudConfig.Value;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try
            {

                _logger.LogInformation("Start Subscriber Service");
                SubscriptionName subscriptionName = SubscriptionName.FromProjectSubscription(_cloudOption.ProjectId, _cloudOption.SubscriptionId);

                _subscriber = await SubscriberClient.CreateAsync(subscriptionName);

                _logger.LogInformation("Subscriber created for subscription " + _cloudOption.SubscriptionId);


                await _subscriber.StartAsync((PubsubMessage message, CancellationToken cancel) =>
                {
                    string text = System.Text.Encoding.UTF8.GetString(message.Data.ToArray());
                    _logger.LogInformation($"Received message {message.MessageId}: {text}");

                    // Process Revceive Message...

                    return Task.FromResult(SubscriberClient.Reply.Ack);
                });

                await Task.Delay(Timeout.Infinite, stoppingToken);

            }
            catch(Exception ex)
            {            
                _logger.LogError(ex.ToString());
            }
            finally
            {
                if (_subscriber != null)
                {
                    await _subscriber.StopAsync(CancellationToken.None);
                    _logger.LogInformation("Subscriber stopped.");
                }
            }

        }
    }

}


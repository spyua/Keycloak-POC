namespace pushNotification.service.cdp.core.config
{
    public class KeycloakOptions
    {

        public string RootURL { get; set; }
        public string Realm { get; set; }
        public string Master_SSO_ClientId { get; set; }
        public string Master_SSO_ClientSecret { get; set; }
        public string KH_SSO_ClientId { get; set; }
        public string KH_SSO_ClientSecret { get; set; }

        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string GrantType { get; set; }
        public bool SaveTokens { get; set; }

        public string CallbackPath { get; set; }

        // For Endpoint Setting
        public string Metadata { get; set; }
        public string TokenExchange { get; set; }
        public string POSTToken { get; set; }
        public string ServerRealmEndpoint  => $"{RootURL}/realms/{Realm}";
        public string POSTTokenEndpoint => $"{ServerRealmEndpoint}/{POSTToken}";
        public string TokenChangeEndpoint => $"{ServerRealmEndpoint}/{TokenExchange}";
        public string MetadataEndpoint => $"{ServerRealmEndpoint}/{Metadata}";
    }
}

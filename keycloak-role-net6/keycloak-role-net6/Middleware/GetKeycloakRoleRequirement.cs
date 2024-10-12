using Microsoft.AspNetCore.Authorization;
using Newtonsoft.Json;

namespace keycloak_role_net6.Middleware
{
    public class GetKeycloakRoleRequirement : IAuthorizationRequirement
    {
        public List<string> RequiredRoles { get; }

        public GetKeycloakRoleRequirement(List<string> requiredRoles = null)
        {
            RequiredRoles = requiredRoles ?? new List<string>();
        }
    }

    public class KeycloakIDTokenGetRoleHandler : AuthorizationHandler<GetKeycloakRoleRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, GetKeycloakRoleRequirement requirement)
        {
            var resourceAccessClaim = context.User.Claims.FirstOrDefault(c => c.Type == "resource_access");
            if (resourceAccessClaim != null)
            {
                var resourceAccess = JsonConvert.DeserializeObject<dynamic>(resourceAccessClaim.Value);

                var userRoles = resourceAccess?["admin-rest-client"]?["roles"]?.ToObject<List<string>>();

                if (userRoles == null)
                    return Task.CompletedTask;

                bool roleFound = false;
                foreach (var role in userRoles)
                {
                    if (requirement.RequiredRoles.Contains(role))
                    {
                        roleFound = true;
                        break;
                    }
                }

                if (roleFound)
                {
                    context.Succeed(requirement);
                }
                return Task.CompletedTask;
            }
            return Task.CompletedTask;
        }
    }
}

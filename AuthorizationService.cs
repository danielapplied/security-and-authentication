using System;

public static class AuthorizationService
{
    public static void Authorize(string userRole, string requiredRole)
    {
        if (!string.Equals(userRole, requiredRole, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("Access denied");
        }
    }

    public static bool HasAccess(string userRole, string requiredRole)
    {
        return string.Equals(userRole, requiredRole, StringComparison.OrdinalIgnoreCase);
    }
}

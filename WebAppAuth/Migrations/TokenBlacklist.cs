using System;
using System.IdentityModel.Tokens.Jwt;

namespace WebAppAuth.Migrations;

public class TokenBlacklist
{
    private static readonly HashSet<string> BlacklistedTokens = new();
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(30);
    private static DateTime _lastCleanup = DateTime.UtcNow;

    public void Add(string token)
    {
        lock (BlacklistedTokens)
        {
            // Периодически очищаем старые токены
            if (DateTime.UtcNow - _lastCleanup > CleanupInterval)
            {
                BlacklistedTokens.RemoveWhere(t => IsTokenExpired(t));
                _lastCleanup = DateTime.UtcNow;
            }
            
            BlacklistedTokens.Add(token);
        }
    }

    public bool Contains(string token)
    {
        lock (BlacklistedTokens)
        {
            return BlacklistedTokens.Contains(token);
        }
    }

    private  bool IsTokenExpired(string token)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);
            return jwtToken.ValidTo < DateTime.UtcNow;
        }
        catch
        {
            return true;
        }
    }
}

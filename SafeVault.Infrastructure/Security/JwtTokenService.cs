using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace SafeVault.Infrastructure.Security
{
    public class JwtTokenService
    {
        private readonly string _issuer;
        private readonly string _audience;
        private readonly byte[] _key;
        private readonly TimeSpan _lifetime;

        public JwtTokenService(string issuer, string audience, string signingKey, TimeSpan lifetime)
        {
            _issuer = issuer;
            _audience = audience;
            _key = Encoding.UTF8.GetBytes(signingKey);
            _lifetime = lifetime;
        }

        public string CreateToken(string userId, string userName, IEnumerable<string> roles)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.UniqueName, userName),
                new Claim(ClaimTypes.NameIdentifier, userId),
                new Claim(ClaimTypes.Name, userName)
            };
            claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

            var creds = new SigningCredentials(new SymmetricSecurityKey(_key), SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: _issuer,
                audience: _audience,
                claims: claims,
                expires: DateTime.UtcNow.Add(_lifetime),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}

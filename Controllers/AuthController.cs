using FruitCopyBackTest.DTO.Auth;
using Microsoft.AspNetCore.Mvc;
using StackExchange.Redis;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace FruitCopyBackTest.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly IDatabase _redis;
        private readonly IConfiguration _cfg;

        public AuthController(IConnectionMultiplexer mux, IConfiguration cfg)
        {
            _redis = mux.GetDatabase();
            _cfg = cfg;
        }

        [HttpPost("request-otp")]
        public async Task<ActionResult> RequestOtp([FromBody] RequestOtpDto dto, CancellationToken ct)
        {
            var id = Normalize(dto.PhoneOrEmail);

            var rlKey = $"otp_rl:{id}";
            //if (await _redis.StringGetAsync(rlKey) is { HasValue: true })
            //    return Request

            await _redis.StringSetAsync(rlKey, "1", TimeSpan.FromSeconds(30));

            var code = RandomOtp(6);
            var otpKey = $"orp:{id}";
            var hashed = HashOtp(code, _cfg["Jwt:key"]!);

            await _redis.StringSetAsync(otpKey, hashed, TimeSpan.FromMinutes(2));

            return Ok(new { message = "OTP Generated (dev)", code });
        }

        [HttpPost("verify-otp")]
        public async Task<ActionResult<TokenResponseDto>> VerifyOtp([FromBody] VerifyOtpDto dto, CancellationToken ct)
        {
            var id = Normalize(dto.PhoneOrEmail);

            var otpKey = $"otp:{id}";
            var storedHash = await _redis.StringGetAsync(otpKey);

            if (!storedHash.HasValue)
                return Unauthorized(new { message = "OTP expired or not found" });

            var incomingHash = HashOtp(dto.code, _cfg["Jwt:Key"]!);

            if (!CryptographicEquals(storedHash!, incomingHash))
                return Unauthorized(new { message = "Invalid OTP" });

            await _redis.KeyDeleteAsync(otpKey);

            var playerId = DeterministicGuid(id);

            var minutes = int.Parse(_cfg["Jwt:AccessTokenMinutes"] ?? "60");
            var token = IssueJwt(playerId, minutes);

            return Ok(new TokenResponseDto(
                AccessToken: token,
                ExpiresInSeconds: minutes * 60));
        }

        private string IssueJwt(Guid playerId, int minutes)
        {
            var issuer = _cfg["Jwt:Issuer"]!;
            var audience = _cfg["Jwt:Audience"]!;
            var key = _cfg["Jwt:Key"]!;

            var claims = new[]
            {
                new Claim("player_id",playerId.ToString())
            };

            var creds = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)), SecurityAlgorithms.HmacSha256);

            var jwt = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(minutes),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        private static string Normalize(string s) => s.Trim().ToLowerInvariant();

        private static string RandomOtp(int digits)
        {
            var bytes = RandomNumberGenerator.GetBytes(digits);
            var sb = new StringBuilder(digits);
            for (int i = 0; i < digits; i++)
                sb.Append(bytes[i] % 10);
            return sb.ToString();
        }

        private static string HashOtp(string code, string secret)
        {
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(code));
            return Convert.ToBase64String(hash);
        }

        private static bool CryptographicEquals(string a, string b)
        {
            var ba = Encoding.UTF8.GetBytes(a);
            var bb = Encoding.UTF8.GetBytes(b);
            return CryptographicOperations.FixedTimeEquals(ba, bb);
        }

        private static Guid DeterministicGuid(string input)
        {
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
            Span<byte> g = stackalloc byte[16];
            bytes.AsSpan(0, 16).CopyTo(g);
            return new Guid(g);
        }
    }
}

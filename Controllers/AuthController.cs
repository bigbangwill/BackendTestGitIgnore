using FruitCopyBackTest.DTO.Auth;
using Microsoft.AspNetCore.Mvc;
using StackExchange.Redis;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using FruitCopyBackTest.DTO;
using FruitCopyBackTest.Data;
using FruitCopyBackTest.Entities;
using Microsoft.EntityFrameworkCore;

namespace FruitCopyBackTest.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly IDatabase _redis;
        private readonly IConfiguration _cfg;
        private readonly AppDbContext _db;

        public AuthController(IConnectionMultiplexer mux, IConfiguration cfg, AppDbContext appDbContext)
        {
            _redis = mux.GetDatabase();
            _cfg = cfg;
            _db = appDbContext;
        }

        [HttpPost("request-otp")]
        public async Task<ActionResult> RequestOtp([FromBody] RequestOtpDto dto, CancellationToken ct)
        {
            var id = Normalize(dto.PhoneOrEmail);

            var rlKey = $"otp_rl:{id}";
            if (await _redis.StringGetAsync(rlKey) is { HasValue: true })
                return Unauthorized(new { message = "OTP request rate limit exceeded. Try again later." });

            await _redis.StringSetAsync(rlKey, "1", TimeSpan.FromSeconds(30));

            var code = RandomOtp(6);
            var otpKey = $"otp:{id}";
            var hashed = HashOtp(code, _cfg["Jwt:Key"]!);

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

            var incomingHash = HashOtp(dto.Code, _cfg["Jwt:key"]!);
            if (!CryptographicEquals(storedHash!, incomingHash))
                return Unauthorized(new { message = "Code is not correct" });

            await _redis.KeyDeleteAsync(otpKey);

            var playerId = DeterministicGuid(id);

            var player = await _db.Player.FindAsync([playerId], ct);
            if (player == null)
            {
                player = new Player()
                {
                    Id = playerId,
                    LoginKey = id,
                    Role = AccountRolesEnum.Player.ToString(),
                    CreatedAtUtc = DateTime.UtcNow
                };
                _db.Player.Add(player);
                await _db.SaveChangesAsync(ct);
            }

            var minutes = int.Parse(_cfg["Jwt:AccessTokenMinutes"]! ?? "15");
            var accessToken = IssueJwt(playerId, minutes, Enum.Parse<AccountRolesEnum>(player.Role));

            var refreshPlain = CreateRefreshToken();
            var refreshHash = Sha256Base64(refreshPlain);

            var existingRefreshToken = await _db.RefreshTokens
                .FirstOrDefaultAsync(x => x.PlayerId == playerId && x.RevokedAtUtc == null, ct);

            var refreshDays = int.Parse(_cfg["Jwt:RefreshTokenDays"] ?? "14");
            var rt = new RefreshToken()
            {
                Id = Guid.NewGuid(),
                PlayerId = playerId,
                TokenHash = refreshHash,
                CreatedAtUtc = DateTime.UtcNow,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(refreshDays),
                CreatedByIp = HttpContext.Connection.RemoteIpAddress?.ToString()
            };

            _db.RefreshTokens.Add(rt);
            await _db.SaveChangesAsync(ct);

            if (existingRefreshToken != null)
            {
                existingRefreshToken.RevokedAtUtc = DateTime.UtcNow;
                existingRefreshToken.RevokedReason = "New login";
                existingRefreshToken.RevokedByIp = HttpContext.Connection.RemoteIpAddress?.ToString();
                existingRefreshToken.ReplacedByTokenId = rt.Id;
                await _db.SaveChangesAsync(ct);
            }

            return Ok(new TokenResponseDto(accessToken, minutes * 60, refreshPlain));
        }

        public record RefreshRequestDto(string RefreshToken);

        [HttpPost("Refresh")]
        public async Task<ActionResult<TokenResponseDto>> Refresh([FromBody] RefreshRequestDto dto, CancellationToken ct)
        {
            var incominghash = Sha256Base64(dto.RefreshToken);
            var existing = await _db.RefreshTokens
                .Include(x => x.Player)
                .SingleOrDefaultAsync(x => x.TokenHash == incominghash, ct);

            if (existing == null)
                return Unauthorized(new { message = "Invalid Refresh Token" });

            if (existing.RevokedAtUtc != null)
                return Unauthorized(new { message = "Refresh Token Revoked" });

            if (existing.ExpiresAtUtc <= DateTime.UtcNow)
                return Unauthorized(new { message = "Refresh Expired" });

            var newPlain = CreateRefreshToken();
            var newHash = Sha256Base64(newPlain);

            var refreshDays = int.Parse(_cfg["Jwt:RefreshTokenDays"] ?? "14");

            var newToken = new RefreshToken()
            {
                Id = Guid.NewGuid(),
                PlayerId = existing.PlayerId,
                TokenHash = newHash,
                CreatedAtUtc = DateTime.UtcNow,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(refreshDays),
                CreatedByIp = HttpContext.Connection.RemoteIpAddress?.ToString(),
            };

            existing.RevokedAtUtc = DateTime.UtcNow;
            existing.RevokedReason = "Rotated";
            existing.RevokedByIp = HttpContext.Connection.RemoteIpAddress?.ToString();
            existing.ReplacedByTokenId = newToken.Id;

            _db.RefreshTokens.Add(newToken);
            await _db.SaveChangesAsync();

            var minutes = int.Parse(_cfg["Jwt:AccessTokenMinutes"] ?? "15");
            var role = Enum.Parse<AccountRolesEnum>(existing.Player.Role);
            var accessToken = IssueJwt(newToken.PlayerId, minutes, role);

            return Ok(new TokenResponseDto(accessToken, minutes, newPlain));
        }

        public record LogoutRequestDto(string refreshToken);


        [HttpPost("logout")]
        public async Task<ActionResult> Logout([FromBody] LogoutRequestDto dto,CancellationToken ct)
        {
            var hashRefresh = Sha256Base64(dto.refreshToken);

            var existing = await _db.RefreshTokens.FirstOrDefaultAsync(x => x.TokenHash == hashRefresh, ct);

            if (existing == null)
                return Ok();

            if (existing.RevokedAtUtc == null)
            {
                existing.RevokedAtUtc = DateTime.UtcNow;
                existing.RevokedReason = "LoggedOut";
                existing.RevokedByIp = HttpContext.Connection.RemoteIpAddress?.ToString();
                await _db.SaveChangesAsync();
            }

            return Ok();
        }

        private string CreateRefreshToken()
        {
            Span<byte> bytes = stackalloc byte[64];
            RandomNumberGenerator.Fill(bytes);
            return Convert.ToBase64String(bytes);
        }

        private string Sha256Base64(string input)
        {
            var bytes = Encoding.UTF8.GetBytes(input);
            var hash = SHA256.HashData(bytes);
            return Convert.ToBase64String(hash);
        }

        private string IssueJwt(Guid playerId, int minutes, AccountRolesEnum role)
        {
            var issuer = _cfg["Jwt:Issuer"]!;
            var audience = _cfg["Jwt:Audience"]!;
            var key = _cfg["Jwt:Key"]!;

            var claims = new[]
            {
                new Claim("player_id",playerId.ToString()),
                new Claim(ClaimTypes.Role, role.ToString())
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

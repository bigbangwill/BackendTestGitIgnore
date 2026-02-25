using FruitCopyBackTest.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace FruitCopyBackTest.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class PlayerController : Controller
    {
        private readonly AppDbContext _db;

        public PlayerController(AppDbContext db) => _db = db;

        [HttpGet("{playerId}")]
        public IActionResult GetPlayer(string playerId)
        {
            return Ok(new
            {
                playerId,
                fetchedAtUtc = DateTime.Now
            });
        }

        [HttpGet("top")]
        public IActionResult GetTopPlayers(
            [FromQuery] int count = 10,
            [FromQuery] int page = 1)
        {
            return Ok(new
            {
                count,
                page,
                fetchedAtUtc = DateTime.UtcNow
            });
        }

        [Authorize]
        [HttpPut("SetPlayerName")]
        public async Task<ActionResult> SetPlayerName([FromHeader] string playerName, CancellationToken ct)
        {
            var playerIdstr = User.FindFirstValue("player_id");
            if (string.IsNullOrWhiteSpace(playerIdstr) || !Guid.TryParse(playerIdstr, out var playerId))
                return Unauthorized(new { message = "Invalid player_id in token" });

            var player = await _db.Player.FirstOrDefaultAsync(x => x.Id == playerId);
            if (player == null)
                return NotFound(new { message = "Player not found" });

            player.Name = playerName;
            await _db.SaveChangesAsync(ct);
            return Ok(player);
        }
    }
}

using FruitCopyBackTest.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;

namespace FruitCopyBackTest.Controllers
{
    [ApiController]
    [Route("api/players/save")]
    public class PlayerSaveController : ControllerBase
    {
        private readonly AppDbContext _db;
        public PlayerSaveController(AppDbContext db)
        {
            _db = db;
        }

        public record SaveUpsertRequest([Required] string SaveJson, int Version);

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> Get()
        {
            var playerIdStr = User.FindFirstValue("player_id");
            if (string.IsNullOrWhiteSpace(playerIdStr) || !Guid.TryParse(playerIdStr, out Guid playerId))
                return Unauthorized(new { message = "UnAuthorized" });

            var save = await _db.PlayerSaves.AsNoTracking().FirstOrDefaultAsync(x => x.Id == playerId);

            if (save is null) 
                return NotFound(new { message = "No save found for player.", playerId });

            return Ok(new
            {
                saveJson = save.SaveJson,
                version = save.Version,
                updatedAtUrc = save.UpdatedAtUtc
            });
        }

        [Authorize]
        [HttpPut]
        public async Task<IActionResult> Put([FromBody] SaveUpsertRequest request)
        {
            var playerIdStr = User.FindFirstValue("player_id");
            if (string.IsNullOrWhiteSpace(playerIdStr) || !Guid.TryParse(playerIdStr, out Guid playerId))
                return Unauthorized(new { message = "UnAuthorized" });

            var save = await _db.PlayerSaves.FirstOrDefaultAsync(x => x.Id== playerId);

            if (save is null)
            {
                save = new()
                {
                    Id = playerId,
                    SaveJson = request.SaveJson,
                    Version = request.Version,
                    UpdatedAtUtc = DateTime.UtcNow
                };
                _db.PlayerSaves.Add(save);
            }
            else
            {
                save.SaveJson = request.SaveJson;
                save.Version = request.Version;
                save.UpdatedAtUtc = DateTime.UtcNow;
            }

            await _db.SaveChangesAsync();

            return Ok(new
            {
                message = "Save Stored.",
                version = save.Version,
                updatedAtUtc = save.UpdatedAtUtc
            });
        }
    }
}

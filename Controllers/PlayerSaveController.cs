using FruitCopyBackTest.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace FruitCopyBackTest.Controllers
{
    [ApiController]
    [Route("api/players/{playerId}/save")]
    public class PlayerSaveController : ControllerBase
    {
        private readonly AppDbContext _db;
        public PlayerSaveController(AppDbContext db)
        {
            _db = db;
        }

        public record SaveUpsertRequest([Required] string SaveJson, int Version);

        [HttpGet]
        public async Task<IActionResult> Get([FromRoute] string playerId)
        {
            var save = await _db.PlayerSaves.AsNoTracking().FirstOrDefaultAsync(x => x.PlayerId == playerId);

            if (save is null) return NotFound(new { message = "No save found for player.", playerId });

            return Ok(new
            {
                playerId = save.PlayerId,
                saveJson = save.SaveJson,
                version = save.Version,
                updatedAtUrc = save.UpdatedAtUtc
            });
        }

        [HttpPut]
        public async Task<IActionResult> Put([FromRoute] string playerId, [FromBody] SaveUpsertRequest request)
        {
            var save = await _db.PlayerSaves.FirstOrDefaultAsync(x => x.PlayerId == playerId);

            if (save is null)
            {
                save = new()
                {
                    PlayerId = playerId,
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
                playerId,
                version = save.Version,
                updatedAtUtc = save.UpdatedAtUtc
            });
        }
    }
}

using FruitCopyBackTest.Data;
using FruitCopyBackTest.DTO.Leaderboards;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using FruitCopyBackTest.Entities;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace FruitCopyBackTest.Controllers
{
    [ApiController]
    [Route("api/leaderboards")]
    public class LeaderboardsController : ControllerBase
    {
        private readonly AppDbContext _db;

        public LeaderboardsController(AppDbContext db) => _db = db;

        // POST /api/leaderboards/{key}/submit
        [HttpPost("{key}/submit")]
        public async Task<ActionResult> Submit(
            [FromRoute] string key,
            [FromBody] SubmitScoreRequest req,
            CancellationToken ct)
        {
            var leaderboard = await _db.Leaderboards.FirstOrDefaultAsync(x => x.Key == key, ct);

            if (leaderboard is null)
            {
                leaderboard = new Leaderboard() { Key = key };
                _db.Leaderboards.Add(leaderboard);
                await _db.SaveChangesAsync(ct);
            }

            var entry = await _db.LeaderboardEntries.FirstOrDefaultAsync(
                x => x.LeaderboardId == leaderboard.Id && x.PlayerId == req.PlayerId, ct);

            if (entry is null)
            {
                entry = new LeaderboardEntry()
                {
                    Leaderboard = leaderboard,
                    LeaderboardId = leaderboard.Id,
                    PlayerId = req.PlayerId,
                    Score = req.Score,
                    UpdatedAt = DateTimeOffset.UtcNow
                };
                _db.LeaderboardEntries.Add(entry);
            }
            else
            {
                if (req.Score > entry.Score)
                    entry.Score = req.Score;

                entry.UpdatedAt = DateTimeOffset.UtcNow;
            }

            await _db.SaveChangesAsync(ct);
            return Ok();
        }

        // GET api/leaderboards/{key}?page=1&pageSize=50
        [HttpGet("{key}")]
        public async Task<ActionResult<LeaderboardPageResponse>> GetPage(
            [FromRoute] string key,
            [FromQuery] int page,
            [FromQuery] int pageSize,
            CancellationToken ct)
        {
            page = Math.Max(1, page);
            pageSize = Math.Clamp(pageSize, 1, 100);

            var leaderboard = await _db.Leaderboards.AsNoTracking().FirstOrDefaultAsync(x => x.Key == key, ct);

            if (leaderboard is null)
            {
                return NotFound(new { message = "Leaderboard not found", key });
            }

            var skip = (page - 1) * pageSize;

            var rows = await _db.LeaderboardEntries
                .AsNoTracking()
                .Where(x => x.LeaderboardId == leaderboard.Id)
                .OrderByDescending(x => x.Score)
                .ThenBy(x => x.UpdatedAt)
                .Skip(skip)
                .Take(pageSize)
                .Select(x => new { x.PlayerId, x.Score, x.UpdatedAt })
                .ToListAsync(ct);

            var dtos = rows
                .Select((r, i) => new LeaderboardEntryDto(
                    r.PlayerId,
                    r.Score,
                    skip + i + 1,
                    r.UpdatedAt)).ToArray();

            return Ok(new LeaderboardPageResponse(
                LeaderboardKey: leaderboard.Key,
                Page: page,
                PageSize: pageSize,
                Returned: dtos.Length,
                Entries: dtos));
        }

        //GET api/Leaderboards/{key}/me?playerId=...
        [Authorize]
        [HttpGet("{key}/me")]
        public async Task<ActionResult<LeaderboardEntryDto>> GetMe(
            [FromRoute] string key,
            CancellationToken ct)
        {
            var playerIdStr = User.FindFirstValue("playerId");
            if(string.IsNullOrWhiteSpace(playerIdStr) || !Guid.TryParse(playerIdStr, out var playerId))
            {
                return Unauthorized(new { message = "Invalid playerId in token" });
            }

            var leaderboard = await _db.Leaderboards.AsNoTracking().FirstOrDefaultAsync(x => x.Key == key, ct);

            if (leaderboard is null)
                return NotFound(new { message = "Leaderboard Not Found", key });

            var myEntry = await _db.LeaderboardEntries
                .AsNoTracking()
                .FirstOrDefaultAsync(x => x.LeaderboardId == leaderboard.Id && x.PlayerId == playerId, ct);

            if (myEntry is null)
                return NotFound(new { message = "Entry for you didnt found", key });

            var count = await _db.LeaderboardEntries
                .AsNoTracking()
                .CountAsync(x =>
                x.LeaderboardId == leaderboard.Id &&
                (x.Score > myEntry.Score ||
                (x.Score == myEntry.Score && x.UpdatedAt > myEntry.UpdatedAt)), ct);

            int rank = count + 1;

            return Ok(new LeaderboardEntryDto(
                myEntry.PlayerId,
                myEntry.Score,
                rank,
                myEntry.UpdatedAt));
        }
    }
}
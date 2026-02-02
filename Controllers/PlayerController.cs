using Microsoft.AspNetCore.Mvc;

namespace FruitCopyBackTest.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class PlayerController : Controller
    {
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
    }
}

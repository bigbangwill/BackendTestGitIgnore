using Microsoft.AspNetCore.Mvc;

namespace FruitCopyBackTest.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class PingController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            return Ok(new
            {
                message = "Pong",
                serverTimeUTC = DateTime.UtcNow,
                Version = "1.0.0"
            });
        }
    }
}

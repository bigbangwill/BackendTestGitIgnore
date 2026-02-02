using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace FruitCopyBackTest.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class EchoController : ControllerBase
    {
        public record EchoRequest(
            [Required, MinLength(3)] string Message,
            int Number
        );

        [HttpPost]
        public IActionResult Post([FromBody] EchoRequest request)
        {
            return Ok(new
            {
                received = request,
                serverTimeUtc = DateTime.UtcNow
            });
        }
    }
}
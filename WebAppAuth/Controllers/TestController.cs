using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace WebAppAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        [Authorize]
        [HttpGet("private")]
        public IActionResult GetPrivate()
        {
            return Ok(new { Message = "This is a protected endpoint!" });
        }
        [HttpGet("public")]
        public IActionResult GetPublic()
        {
            return Ok(new { Message = "This is a public!" });
        }
    }
}

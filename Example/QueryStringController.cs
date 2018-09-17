using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Example
{   
    public class QueryStringController : ControllerBase
    {
        [HttpGet("/")]
        [Authorize(Policy = AuthorizationPolicies.PolicyString)]
        public IActionResult Simple()
        {
            return Ok();
        }
    }
}
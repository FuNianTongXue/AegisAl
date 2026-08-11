using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public sealed class CommandController : Controller
{
    public IActionResult Run()
    {
        var command = Request.Query["command"];
        Process.Start(command);
        return Ok();
    }
}

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SafeVault.Web.Controllers
{
    [AllowAnonymous] // Home page should be accessible to all (Guest/User/Admin)
    public class HomeController : Controller
    {
        [HttpGet]
        public IActionResult Index()
        {
            // You can pass view model later if needed
            return View();
        }
    }
}

using Dot6.Bserver.Cookie.Auth.Models.Auth;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Dot6.Bserver.Cookie.Auth.Areas.Identity.Pages.Account;

public class LoginModel : PageModel
{

    private readonly IHttpContextAccessor _accessor;
    private readonly IAccountLogic _accountLogic;
    public LoginModel(IHttpContextAccessor accessor, IAccountLogic accountLogic)
    {
        _accessor = accessor;
        _accountLogic = accountLogic;
    }
    [BindProperty]
    public LoginVm LoginVm { get; set; }
    public string ErrorMessage;
    public async Task<IActionResult> OnGetAsync()
    {
        if (_accessor.HttpContext.User.Identity.IsAuthenticated)
        {
            return Redirect("/");
        }
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        ErrorMessage = await _accountLogic.UserLoginAsyn(LoginVm);
        if (!string.IsNullOrEmpty(ErrorMessage))
        {
            return Page();
        }
        return Redirect("/");
    }

}
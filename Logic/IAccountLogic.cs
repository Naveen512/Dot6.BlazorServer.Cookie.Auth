using Dot6.Bserver.Cookie.Auth.Models.Auth;
public interface IAccountLogic
{
    Task<(bool Success, string Message)> UserRegistrationAsync(RegisterVm register);
    Task<string> UserLoginAsyn(LoginVm loginVm);
}
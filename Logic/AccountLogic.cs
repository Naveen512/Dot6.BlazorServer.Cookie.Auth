using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Dot6.Bserver.Cookie.Auth.Data;
using Dot6.Bserver.Cookie.Auth.Data.Entities;
using Dot6.Bserver.Cookie.Auth.Models.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;

namespace Dot6.Bserver.Cookie.Auth.Logic;

public class AccountLogic : IAccountLogic
{
    private readonly MyCookieAuthContext _myCookieAuthContext;
    private readonly IHttpContextAccessor _accessor;

    public AccountLogic(MyCookieAuthContext myCookieAuthContext,
    IHttpContextAccessor accessor)
    {
        _myCookieAuthContext = myCookieAuthContext;
        _accessor = accessor;
    }

    private string ResigstrationValidations(RegisterVm registerVm)
    {
        if (string.IsNullOrEmpty(registerVm.Email))
        {
            return "Eamil can't be empty";
        }

        string emailRules = @"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?";
        if (!Regex.IsMatch(registerVm.Email, emailRules))
        {
            return "Not a valid email";
        }

        if (_myCookieAuthContext.Users.Any(_ => _.Email.ToLower() == registerVm.Email.ToLower()))
        {
            return "user already exists";
        }

        if (string.IsNullOrEmpty(registerVm.Password)
            || string.IsNullOrEmpty(registerVm.ConfirmPassword))
        {
            return "Password Or ConfirmPasswor Can't be empty";
        }

        if (registerVm.Password != registerVm.ConfirmPassword)
        {
            return "Invalid confirm password";
        }



        // atleast one lower case letter
        // atleast one upper case letter
        // atleast one special character
        // atleast one number
        // atleast 8 character length
        string passwordRules = @"^.*(?=.{8,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!*@#$%^&+=]).*$";
        if (!Regex.IsMatch(registerVm.Password, passwordRules))
        {
            return "Not a valid password";
        }
        return string.Empty;
    }
    private string PasswordHash(string password)
    {
        byte[] salt = new byte[16];
        new RNGCryptoServiceProvider().GetBytes(salt);

        var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 1000);
        byte[] hash = pbkdf2.GetBytes(20);

        byte[] hashBytes = new byte[36];
        Array.Copy(salt, 0, hashBytes, 0, 16);
        Array.Copy(hash, 0, hashBytes, 16, 20);

        return Convert.ToBase64String(hashBytes);
    }

    public async Task<(bool Success, string Message)> UserRegistrationAsync(RegisterVm register)
    {
        string message = ResigstrationValidations(register);
        if (!string.IsNullOrEmpty(message))
        {
            return (false, message);
        }


        Users newUser = new();

        newUser.Email = register.Email;
        newUser.FirstName = register.FirstName;
        newUser.LastName = register.LastName;
        newUser.PasswordHash = PasswordHash(register.Password);

        _myCookieAuthContext.Users.Add(newUser);
        await _myCookieAuthContext.SaveChangesAsync();

        var role = await _myCookieAuthContext.Roles.Where(_ => _.Name.ToUpper() == "USER")
        .FirstOrDefaultAsync();

        if (role != null)
        {
            UserRoles userRoles = new();
            userRoles.RoleId = role.Id;
            userRoles.UserId = newUser.Id;

            _myCookieAuthContext.UserRoles.Add(userRoles);
            await _myCookieAuthContext.SaveChangesAsync();
        }

        return (true, string.Empty);
    }

    private bool ValidatePasswordHash(string password, string dbPassword)
    {
        byte[] dbPasswordHashBytes = Convert.FromBase64String(dbPassword);

        byte[] salt = new byte[16];
        Array.Copy(dbPasswordHashBytes, 0, salt, 0, 16);

        var userPasswordBytes = new Rfc2898DeriveBytes(password, salt, 1000);
        byte[] userPasswordHash = userPasswordBytes.GetBytes(20);

        for (int i = 0; i < 20; i++)
        {
            if (dbPasswordHashBytes[i + 16] != userPasswordHash[i])
            {
                return false;
            }
        }
        return true;
    }

    public async Task<string> UserLoginAsyn(LoginVm loginVm)
    {
        Users user = await _myCookieAuthContext.Users
        .Where(_ => _.Email.ToLower() == loginVm.Email.ToLower())
        .FirstOrDefaultAsync();

        if (user == null)
        {
            return "Invalid Credentials";
        }

        if (!ValidatePasswordHash(loginVm.Password, user.PasswordHash))
        {
            return "Invalid Credentials";
        }

        var claims = new List<Claim>();
        claims.Add(new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}"));
        claims.Add(new Claim(ClaimTypes.Email, user.Email));

        var userRoles = await _myCookieAuthContext.UserRoles.Join(_myCookieAuthContext.Roles,
                            ur => ur.RoleId,
                            u => u.Id,
                            (ur, u) => new { RoleId = ur.RoleId, RoleName = u.Name, UserId = ur.UserId }
                        )
                        .Where(_ => _.UserId == user.Id)
                        .ToListAsync();

        foreach (var ur in userRoles)
        {
            claims.Add(new Claim(ClaimTypes.Role, ur.RoleName));
        }

        var claimsIdentity = new ClaimsIdentity(
            claims, CookieAuthenticationDefaults.AuthenticationScheme);

        var authProperties = new AuthenticationProperties
        { };

        await _accessor.HttpContext.SignInAsync(
           CookieAuthenticationDefaults.AuthenticationScheme,
           new ClaimsPrincipal(claimsIdentity),
           authProperties);

        return string.Empty;
    }
}
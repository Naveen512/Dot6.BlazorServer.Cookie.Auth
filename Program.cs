using Dot6.Bserver.Cookie.Auth.Data;
using Dot6.Bserver.Cookie.Auth.Logic;
using Dot6.Bserver.Cookie.Auth.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddSingleton<WeatherForecastService>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IAccountLogic, AccountLogic>();
builder.Services.AddScoped<TokenProvider>();
builder.Services.AddDbContext<MyCookieAuthContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("MyCookieAuthConnect"));
});

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
.AddCookie(options =>
{
    options.ExpireTimeSpan = TimeSpan.FromDays(20);
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

app.Run();

using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

// =============================================================================
// IAM Lab — authorization server thật, dùng OpenIddict.
//
// Đây là bản đối chiếu cho mock chạy trong browser. Nhưng khác mock ở chỗ: đây
// là một authorization server đầy đủ, có nhiều flow, nhiều loại client, nhiều
// endpoint chuẩn OIDC — introspection, revocation, userinfo. Mục tiêu là bạn
// thấy được toàn bộ bề mặt của một server thật, không chỉ một luồng đăng nhập.
//
// Ba thứ được rút gọn có chủ ý, và đều ghi rõ:
//   1. Không có giao diện đăng nhập. /connect/authorize đăng nhập luôn thành alice.
//   2. SQLite file iamlab.db. Xoá file đó là reset sạch.
//   3. Access token để dạng JWS đọc được (production nên bật lại JWE).
// Mọi thứ còn lại — PKCE, phát code, ký JWT, JWKS, rotation, introspection — là
// OpenIddict thật làm.
// =============================================================================

var allowPlainPkce = Environment.GetEnvironmentVariable("LAB_ALLOW_PLAIN_PKCE") == "1";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<LabDbContext>(options =>
{
    // InMemory provider không hỗ trợ ExecuteUpdate, nên khi một authorization
    // code bị dùng lại, OpenIddict không thu hồi được cả chuỗi token của phiên -
    // đúng cái hành vi bảo mật đáng xem nhất lại bị mất. SQLite giữ được.
    options.UseSqlite("Data Source=iamlab.db");
    options.UseOpenIddict();
});

builder.Services.AddCors(options => options.AddDefaultPolicy(policy => policy
    .WithOrigins("http://localhost:5180", "http://127.0.0.1:5180")
    .AllowAnyHeader()
    .AllowAnyMethod()));

builder.Services.AddOpenIddict()
    .AddCore(options => options
        .UseEntityFrameworkCore()
        .UseDbContext<LabDbContext>())

    .AddServer(options =>
    {
        // ---- Các endpoint chuẩn OIDC ----
        options.SetAuthorizationEndpointUris("connect/authorize")
               .SetTokenEndpointUris("connect/token")
               .SetUserInfoEndpointUris("connect/userinfo")
               .SetIntrospectionEndpointUris("connect/introspect")
               .SetEndSessionEndpointUris("connect/logout")
               .SetRevocationEndpointUris("connect/revoke");

        // ---- Các flow được bật ----
        //   authorization_code : app có người dùng (SPA, MVC)
        //   client_credentials : máy-gọi-máy (M2M), không có người dùng
        //   refresh_token      : làm mới access token mà không đăng nhập lại
        options.AllowAuthorizationCodeFlow()
               .AllowClientCredentialsFlow()
               .AllowRefreshTokenFlow()
               .RequireProofKeyForCodeExchange();

        // RequireProofKeyForCodeExchange() chỉ ép PKCE phải CÓ, KHÔNG ép S256.
        // OpenIddict vẫn quảng cáo và vẫn nhận "plain" cho tới khi ta bỏ nó ra.
        if (!allowPlainPkce)
        {
            options.Configure(o => o.CodeChallengeMethods.Remove(CodeChallengeMethods.Plain));
        }

        options.RegisterScopes(
            Scopes.OpenId, Scopes.Profile, Scopes.OfflineAccess,
            "read:reports", "admin:reports", "reports.api");

        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        // JWS đọc được thay vì JWE, để lab mổ xẻ được token.
        options.DisableAccessTokenEncryption();

        options.SetAccessTokenLifetime(TimeSpan.FromMinutes(5))
               .SetIdentityTokenLifetime(TimeSpan.FromMinutes(5))
               .SetRefreshTokenLifetime(TimeSpan.FromDays(14));

        // Điểm mock-vs-real đáng xem: OpenIddict xoay refresh token mặc định,
        // NHƯNG để một "leeway" ~30s cho bản cũ vẫn dùng được (nhằm chịu được
        // request đồng thời khi mạng chập chờn). Trong khoảng đó, reuse KHÔNG bị
        // bắt. Đặt leeway = 0 để mỗi refresh xoay đúng một lần và dùng lại bản
        // cũ là bị thu hồi ngay - khớp hành vi của mock.
        options.SetRefreshTokenReuseLeeway(TimeSpan.Zero);

        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableUserInfoEndpointPassthrough()
               .EnableEndSessionEndpointPassthrough()
               .DisableTransportSecurityRequirement(); // chỉ vì lab chạy http trên localhost
    })

    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

builder.Services.AddHttpClient("no-redirect")
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
builder.Services.AddAuthorization();
builder.Services.AddAuthentication(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);

builder.Services.AddHostedService<SeedClients>();

var app = builder.Build();

app.UseCors();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

// ===========================================================================
//  ENDPOINT OIDC
// ===========================================================================

// ---- /connect/authorize — front channel ----
app.MapMethods("/connect/authorize", new[] { "GET", "POST" }, (HttpContext context) =>
{
    var request = GetRequest(context);

    var identity = new ClaimsIdentity(
        authenticationType: TokenValidationParameters.DefaultAuthenticationType,
        nameType: Claims.Name,
        roleType: Claims.Role);

    identity.SetClaim(Claims.Subject, "user-8f21")
            .SetClaim(Claims.Name, "Alice Nguyen")
            .SetClaim(Claims.Email, "alice@example.com")
            .SetClaim(Claims.PreferredUsername, "alice")
            .SetClaims(Claims.Role, ImmutableArray.Create("reader", "writer"));

    identity.SetScopes(request.GetScopes());
    identity.SetResources("https://api.example.com");
    identity.SetDestinations(Destinations1);

    return Results.SignIn(
        new ClaimsPrincipal(identity),
        properties: null,
        authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
});

// ---- /connect/token — back channel, xử lý cả 3 grant ----
app.MapPost("/connect/token", async (HttpContext context) =>
{
    var request = GetRequest(context);

    // --- Client credentials: máy-gọi-máy, không có người dùng ---
    if (request.IsClientCredentialsGrantType())
    {
        var identity = new ClaimsIdentity(
            TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);

        // Với M2M, "chủ thể" là chính client, không phải một con người.
        identity.SetClaim(Claims.Subject, request.ClientId!)
                .SetClaim(Claims.Name, request.ClientId);
        identity.SetScopes(request.GetScopes());
        identity.SetResources("https://api.example.com");
        identity.SetDestinations(_ => new[] { Destinations.AccessToken });

        return Results.SignIn(new ClaimsPrincipal(identity), null,
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    // --- Authorization code + refresh: có người dùng ---
    if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
    {
        var result = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (!result.Succeeded || result.Principal is null)
        {
            return Results.BadRequest(new
            {
                error = Errors.InvalidGrant,
                error_description = result.Failure?.Message
                    ?? "Grant không hợp lệ: code/refresh đã dùng, hết hạn, hoặc code_verifier không khớp.",
            });
        }

        var identity = new ClaimsIdentity(
            result.Principal.Claims,
            TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
        identity.SetDestinations(Destinations1);

        return Results.SignIn(new ClaimsPrincipal(identity), null,
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    return Results.BadRequest(new
    {
        error = Errors.UnsupportedGrantType,
        error_description = $"Grant type \"{request.GrantType}\" không được bật.",
    });
});

// ---- /connect/userinfo — thông tin user cho client đọc ----
app.MapMethods("/connect/userinfo", new[] { "GET", "POST" }, (HttpContext context) =>
{
    var user = context.User;
    if (user.Identity?.IsAuthenticated != true)
        return Results.Json(new { error = "invalid_token" }, statusCode: 401);

    var claims = new Dictionary<string, object?>
    {
        [Claims.Subject] = user.GetClaim(Claims.Subject),
    };
    if (user.HasScope(Scopes.Profile))
    {
        claims[Claims.Name] = user.GetClaim(Claims.Name);
        claims[Claims.PreferredUsername] = user.GetClaim(Claims.PreferredUsername);
    }
    return Results.Json(claims);
}).RequireAuthorization();

// ===========================================================================
//  RESOURCE API — cùng token do server này phát bảo vệ
// ===========================================================================

// Cần đăng nhập + scope read:reports.
app.MapGet("/api/me", (HttpContext ctx) => RequireScope(ctx, "read:reports", u => new
{
    sub = u.GetClaim(Claims.Subject),
    name = u.GetClaim(Claims.Name),
    roles = u.GetClaims(Claims.Role),
    scopes = ScopesOf(u),
    note = "Trả về bởi ASP.NET Core thật, xác thực bằng OpenIddict validation.",
})).RequireAuthorization();

// Báo cáo — cùng scope read:reports.
app.MapGet("/api/reports", (HttpContext ctx) => RequireScope(ctx, "read:reports", _ => new
{
    reports = new[] { new { id = 1, title = "Q4 revenue" }, new { id = 2, title = "Churn" } },
})).RequireAuthorization();

// Endpoint quyền cao — cần scope admin:reports mà SPA thường không xin.
app.MapGet("/api/admin", (HttpContext ctx) => RequireScope(ctx, "admin:reports", _ => new
{
    secret = "chỉ admin mới đọc được",
})).RequireAuthorization();

// Endpoint dành cho M2M — cần scope reports.api, không cần người dùng.
app.MapGet("/api/service", (HttpContext ctx) => RequireScope(ctx, "reports.api", u => new
{
    caller = u.GetClaim(Claims.Subject),
    note = "Được gọi bởi một client máy-gọi-máy, không có người dùng nào ở đây.",
})).RequireAuthorization();

// ===========================================================================
//  ENDPOINT RIÊNG CỦA LAB (không phải OAuth) — để UI đối chiếu
// ===========================================================================

// SPA ở origin khác không đọc được Location của redirect cross-origin, nên server
// tự gọi /connect/authorize rồi trả Location dạng JSON. Kiểm tra + phát code vẫn
// do OpenIddict làm y hệt.
app.MapGet("/lab/authorize", async (HttpContext context, IHttpClientFactory factory) =>
{
    var query = context.Request.QueryString.Value ?? string.Empty;
    var self = $"{context.Request.Scheme}://{context.Request.Host}/connect/authorize{query}";
    using var client = factory.CreateClient("no-redirect");
    client.DefaultRequestHeaders.Add("Accept", "*/*");
    using var upstream = await client.GetAsync(self, HttpCompletionOption.ResponseHeadersRead);
    var location = upstream.Headers.Location?.ToString();
    var body = location is null ? await upstream.Content.ReadAsStringAsync() : null;
    return Results.Json(new { status = (int)upstream.StatusCode, location, body = body?.Length > 600 ? body[..600] : body });
});

app.MapGet("/lab/config", () => Results.Json(new
{
    backend = "OpenIddict 6 trên ASP.NET Core 9",
    issuer = "http://localhost:5181/",
    grants = new[] { "authorization_code", "client_credentials", "refresh_token" },
    endpoints = new[] { "authorize", "token", "userinfo", "introspect", "revoke", "logout" },
    scopes = new[] { "openid", "profile", "offline_access", "read:reports", "admin:reports", "reports.api" },
    clients = new[]
    {
        new { id = "spa-dashboard", type = "public", note = "SPA, PKCE bắt buộc, không secret" },
        new { id = "service-worker", type = "confidential", note = "M2M, dùng client_credentials + secret" },
    },
    pkce_required = true,
    plain_pkce_allowed = allowPlainPkce,
    access_token_lifetime_seconds = 300,
    access_token_encrypted = false,
    login_ui = false,
    note = "Không có giao diện đăng nhập: /connect/authorize đăng nhập luôn thành alice.",
}));

app.MapFallbackToFile("index.html");

app.Run();

// ===========================================================================
//  HÀM PHỤ
// ===========================================================================

// Ánh xạ claim -> access token / id_token. Nhét hết vào cả hai là rò rỉ hồ sơ
// sang phía resource server, nên tách rõ.
static IEnumerable<string> Destinations1(Claim claim) => claim.Type switch
{
    Claims.Name or Claims.PreferredUsername => new[] { Destinations.AccessToken, Destinations.IdentityToken },
    Claims.Email => new[] { Destinations.IdentityToken },
    Claims.Role => new[] { Destinations.AccessToken },
    _ => new[] { Destinations.AccessToken },
};

static string[] ScopesOf(ClaimsPrincipal u) => u.GetClaim(Claims.Scope)?.Split(' ') ?? Array.Empty<string>();

// 401 nếu chưa xác thực, 403 nếu thiếu scope, ngược lại trả body. Đây chính là
// chỗ phân biệt "anh là ai" (401) với "anh không được phép" (403).
static IResult RequireScope(HttpContext ctx, string scope, Func<ClaimsPrincipal, object> body)
{
    var u = ctx.User;
    if (u.Identity?.IsAuthenticated != true)
        return Results.Json(new { error = "invalid_token", error_description = "Thiếu hoặc sai bearer token." }, statusCode: 401);
    var scopes = ScopesOf(u);
    if (!scopes.Contains(scope))
        return Results.Json(new
        {
            error = "insufficient_scope",
            error_description = $"Endpoint này cần scope \"{scope}\". Token mang [{string.Join(", ", scopes)}].",
        }, statusCode: 403);
    return Results.Json(body(u));
}

static OpenIddictRequest GetRequest(HttpContext context) =>
    context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction?.Request
        ?? throw new InvalidOperationException("Endpoint này không nằm trong một OpenIddict transaction.");

public class LabDbContext(DbContextOptions<LabDbContext> options) : DbContext(options);

/// <summary>
/// Đăng ký client lúc khởi động: một public client (SPA) và một confidential
/// client (M2M). Đây là bản C# tương ứng với registerClient() trong mock.
/// </summary>
public class SeedClients(IServiceProvider provider) : IHostedService
{
    public async Task StartAsync(CancellationToken ct)
    {
        using var scope = provider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<LabDbContext>();
        await context.Database.EnsureCreatedAsync(ct);

        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        // ---- Public client: SPA, PKCE bắt buộc, KHÔNG có secret ----
        if (await manager.FindByClientIdAsync("spa-dashboard", ct) is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "spa-dashboard",
                ClientType = ClientTypes.Public,
                ConsentType = ConsentTypes.Implicit,
                DisplayName = "IAM Lab SPA",
                RedirectUris = { new Uri("http://localhost:5180/callback"), new Uri("http://localhost:5181/callback") },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.EndSession,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Profile,
                    Permissions.Prefixes.Scope + "read:reports",
                    Permissions.Prefixes.Scope + "admin:reports",
                },
                // Client này BẮT BUỘC PKCE, dù cấu hình chung có nới ra hay không.
                Requirements = { Requirements.Features.ProofKeyForCodeExchange },
            }, ct);
        }

        // ---- Confidential client: M2M, có secret, dùng client_credentials ----
        if (await manager.FindByClientIdAsync("service-worker", ct) is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "service-worker",
                // Confidential: giữ được secret, nên xác thực bằng secret.
                ClientType = ClientTypes.Confidential,
                ClientSecret = "s3rv1ce-s3cr3t", // production: đừng hardcode
                DisplayName = "Báo cáo tự động (M2M)",
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.Prefixes.Scope + "reports.api",
                },
            }, ct);
        }
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}

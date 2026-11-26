using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace PhoneBox.Agent;

/// <summary>
/// Username/password gate for the Settings web UI (port 1766), with Admin and User roles.
/// Passwords are stored only as PBKDF2 hashes; never logged.
/// </summary>
public sealed class SettingsAuth
{
    public const string CookieName = "pb_settings_session";
    public const string ItemKey = "SettingsUser";
    public const string RoleAdmin = "Admin";
    public const string RoleUser = "User";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private static readonly Regex UsernameRe = new(@"^[A-Za-z0-9._-]{1,64}$", RegexOptions.Compiled);
    private readonly object _gate = new();
    private readonly string _path;
    private readonly ConcurrentDictionary<string, Session> _sessions = new(StringComparer.Ordinal);
    private UsersFile _file;

    public SettingsAuth(string? configDir = null)
    {
        var dir = string.IsNullOrEmpty(configDir) ? AppPaths.ConfigDir : configDir;
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "settings-users.json");
        _file = Load();
    }

    public bool NeedsSetup
    {
        get { lock (_gate) return _file.Users.Count == 0; }
    }

    public IReadOnlyList<UserPublic> ListUsers()
    {
        lock (_gate)
            return _file.Users.Select(ToPublic).ToList();
    }

    public UserPublic? FindPublic(string id)
    {
        lock (_gate)
            return _file.Users.FirstOrDefault(u => u.Id == id) is { } u ? ToPublic(u) : null;
    }

    public bool TryAuthenticate(string? username, string? password, out UserPublic? user, out string? error)
    {
        user = null;
        error = null;
        username = NormalizeUsername(username);
        if (username is null || string.IsNullOrEmpty(password))
        {
            error = "Username and password are required";
            return false;
        }
        SettingsUser? record;
        lock (_gate)
            record = _file.Users.FirstOrDefault(u => u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        if (record is null || !VerifyPassword(password, record.PasswordHash))
        {
            error = "Invalid username or password";
            return false;
        }
        user = ToPublic(record);
        return true;
    }

    public bool TrySetup(string? username, string? password, out UserPublic? user, out string? error)
    {
        user = null;
        lock (_gate)
        {
            if (_file.Users.Count > 0)
            {
                error = "Setup already completed";
                return false;
            }
            if (!ValidateNewUser(username, password, RoleAdmin, out var name, out error))
                return false;
            var created = new SettingsUser
            {
                Id = Guid.NewGuid().ToString("N"),
                Username = name!,
                PasswordHash = HashPassword(password!),
                Role = RoleAdmin,
            };
            _file.Users.Add(created);
            PersistUnlocked();
            user = ToPublic(created);
            return true;
        }
    }

    public bool TryCreate(string? username, string? password, string? role, out UserPublic? user, out string? error)
    {
        user = null;
        lock (_gate)
        {
            if (!ValidateNewUser(username, password, role, out var name, out error))
                return false;
            if (_file.Users.Any(u => u.Username.Equals(name, StringComparison.OrdinalIgnoreCase)))
            {
                error = "That username is already taken";
                return false;
            }
            var created = new SettingsUser
            {
                Id = Guid.NewGuid().ToString("N"),
                Username = name!,
                PasswordHash = HashPassword(password!),
                Role = NormalizeRole(role)!,
            };
            _file.Users.Add(created);
            PersistUnlocked();
            user = ToPublic(created);
            return true;
        }
    }

    public bool TryUpdate(string id, string? username, string? password, string? role, out UserPublic? user, out string? error)
    {
        user = null;
        error = null;
        lock (_gate)
        {
            var record = _file.Users.FirstOrDefault(u => u.Id == id);
            if (record is null)
            {
                error = "User not found";
                return false;
            }
            if (username is not null)
            {
                var name = NormalizeUsername(username);
                if (name is null)
                {
                    error = "Username must be 1–64 letters, digits, '.', '_' or '-'";
                    return false;
                }
                if (_file.Users.Any(u => u.Id != id && u.Username.Equals(name, StringComparison.OrdinalIgnoreCase)))
                {
                    error = "That username is already taken";
                    return false;
                }
                record.Username = name;
            }
            if (password is not null)
            {
                if (!ValidatePassword(password, out error))
                    return false;
                record.PasswordHash = HashPassword(password);
            }
            if (role is not null)
            {
                var r = NormalizeRole(role);
                if (r is null)
                {
                    error = "Role must be Admin or User";
                    return false;
                }
                if (record.Role == RoleAdmin && r == RoleUser && AdminCountUnlocked() <= 1)
                {
                    error = "Keep at least one Admin account";
                    return false;
                }
                record.Role = r;
            }
            PersistUnlocked();
            user = ToPublic(record);
            return true;
        }
    }

    public bool TryDelete(string id, out string? error)
    {
        error = null;
        lock (_gate)
        {
            var record = _file.Users.FirstOrDefault(u => u.Id == id);
            if (record is null)
            {
                error = "User not found";
                return false;
            }
            if (record.Role == RoleAdmin && AdminCountUnlocked() <= 1)
            {
                error = "Keep at least one Admin account";
                return false;
            }
            _file.Users.Remove(record);
            PersistUnlocked();
            foreach (var kv in _sessions.Where(s => s.Value.UserId == id).ToList())
                _sessions.TryRemove(kv.Key, out _);
            return true;
        }
    }

    public string CreateSession(UserPublic user)
    {
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        _sessions[token] = new Session(user.Id, user.Username, user.Role, DateTimeOffset.UtcNow.AddDays(14));
        return token;
    }

    public void RevokeSession(string? token)
    {
        if (!string.IsNullOrEmpty(token))
            _sessions.TryRemove(token, out _);
    }

    public UserPublic? GetSessionUser(string? token)
    {
        if (string.IsNullOrEmpty(token)) return null;
        if (!_sessions.TryGetValue(token, out var session)) return null;
        if (session.ExpiresUtc < DateTimeOffset.UtcNow)
        {
            _sessions.TryRemove(token, out _);
            return null;
        }
        lock (_gate)
        {
            var record = _file.Users.FirstOrDefault(u => u.Id == session.UserId);
            if (record is null)
            {
                _sessions.TryRemove(token, out _);
                return null;
            }
            return ToPublic(record);
        }
    }

    public static bool IsAnonymousPath(PathString path, string method)
    {
        if (path == "/api/auth/status") return HttpMethods.IsGet(method);
        if (path == "/api/auth/login" || path == "/api/auth/setup") return HttpMethods.IsPost(method);
        if (path == "/api/info") return HttpMethods.IsGet(method); // setup.ps1 health check
        if (path == "/favicon.ico") return HttpMethods.IsGet(method);
        return false;
    }

    /// <summary>Whether this Settings-UI request is allowed for the signed-in role.</summary>
    public static bool IsAllowedForRole(string role, string method, PathString path)
    {
        if (role == RoleAdmin) return true;
        if (role != RoleUser) return false;

        // User: browse Pages / live panel only — no settings writes, pairing, updates, or user admin.
        if (path.StartsWithSegments("/api/users") || path.StartsWithSegments("/api/auth/setup"))
            return false;
        if (HttpMethods.IsGet(method) || HttpMethods.IsHead(method))
        {
            if (path == "/" || path.StartsWithSegments("/panel") || path == "/favicon.ico") return true;
            if (path.StartsWithSegments("/api/auth")) return true;
            if (path == "/api/settings" || path == "/api/info" || path == "/api/catalog") return true;
            if (path == "/api/state" || path.StartsWithSegments("/api/stream") || path.StartsWithSegments("/api/art")
                || path.StartsWithSegments("/api/media") || path == "/api/wallpaper" || path == "/api/lyrics"
                || path.StartsWithSegments("/api/widget") || path.StartsWithSegments("/api/photos")
                || path.StartsWithSegments("/api/feeds") || path.StartsWithSegments("/api/calendar")
                || path.StartsWithSegments("/api/batteries") || path.StartsWithSegments("/api/docker")
                || path.StartsWithSegments("/api/obs") || path.StartsWithSegments("/api/discord")
                || path == "/api/steam" || path == "/api/steam/avatar" || path == "/api/steam/library" || path == "/api/steam/cover"
                || path.StartsWithSegments("/api/ha/states") || path == "/api/spectrum"
                || path.StartsWithSegments("/api/controls") || path.StartsWithSegments("/api/quotas")
                || path.StartsWithSegments("/api/work") || path.StartsWithSegments("/api/procs")
                || path.StartsWithSegments("/api/apps") || path.StartsWithSegments("/api/shortcuts/icon"))
                return true;
            return false;
        }
        // logout only
        return path == "/api/auth/logout" && HttpMethods.IsPost(method);
    }

    public static void SetSessionCookie(HttpResponse res, string token, bool secure)
    {
        res.Cookies.Append(CookieName, token, new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = secure,
            Path = "/",
            MaxAge = TimeSpan.FromDays(14),
            IsEssential = true,
        });
    }

    public static void ClearSessionCookie(HttpResponse res, bool secure)
    {
        res.Cookies.Append(CookieName, "", new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = secure,
            Path = "/",
            Expires = DateTimeOffset.UnixEpoch,
            IsEssential = true,
        });
    }

    public static string? ReadSessionCookie(HttpRequest req) =>
        req.Cookies.TryGetValue(CookieName, out var v) ? v : null;

    internal static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100_000, HashAlgorithmName.SHA256, 32);
        return $"pbkdf2$100000${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    internal static bool VerifyPassword(string password, string encoded)
    {
        var parts = encoded.Split('$');
        if (parts.Length != 4 || parts[0] != "pbkdf2" || !int.TryParse(parts[1], out var iter) || iter < 10_000)
            return false;
        byte[] salt, expected;
        try
        {
            salt = Convert.FromBase64String(parts[2]);
            expected = Convert.FromBase64String(parts[3]);
        }
        catch { return false; }
        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iter, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private UsersFile Load()
    {
        if (!File.Exists(_path)) return new UsersFile();
        try
        {
            AppPaths.RestrictToOwner(_path);
            var file = JsonSerializer.Deserialize<UsersFile>(File.ReadAllText(_path), JsonOpts) ?? new UsersFile();
            file.Users ??= [];
            foreach (var u in file.Users)
            {
                u.Id = string.IsNullOrWhiteSpace(u.Id) ? Guid.NewGuid().ToString("N") : u.Id;
                u.Username = (u.Username ?? "").Trim();
                u.Role = NormalizeRole(u.Role) ?? RoleUser;
            }
            file.Users = file.Users.Where(u => UsernameRe.IsMatch(u.Username) && !string.IsNullOrEmpty(u.PasswordHash)).ToList();
            return file;
        }
        catch
        {
            return new UsersFile();
        }
    }

    private void PersistUnlocked()
    {
        var json = JsonSerializer.Serialize(_file, JsonOpts);
        AppPaths.WriteAllTextPrivate(_path, json);
    }

    private int AdminCountUnlocked() => _file.Users.Count(u => u.Role == RoleAdmin);

    private static UserPublic ToPublic(SettingsUser u) => new(u.Id, u.Username, u.Role);

    private static string? NormalizeUsername(string? username)
    {
        var n = (username ?? "").Trim();
        return UsernameRe.IsMatch(n) ? n : null;
    }

    private static string? NormalizeRole(string? role) =>
        string.Equals(role, RoleAdmin, StringComparison.OrdinalIgnoreCase) ? RoleAdmin
        : string.Equals(role, RoleUser, StringComparison.OrdinalIgnoreCase) ? RoleUser
        : null;

    private static bool ValidatePassword(string? password, out string? error)
    {
        error = null;
        if (string.IsNullOrEmpty(password) || password.Length < 8)
        {
            error = "Password must be at least 8 characters";
            return false;
        }
        if (password.Length > 200)
        {
            error = "Password is too long";
            return false;
        }
        return true;
    }

    private static bool ValidateNewUser(string? username, string? password, string? role, out string? name, out string? error)
    {
        name = NormalizeUsername(username);
        if (name is null)
        {
            error = "Username must be 1–64 letters, digits, '.', '_' or '-'";
            return false;
        }
        if (!ValidatePassword(password, out error))
            return false;
        if (NormalizeRole(role) is null)
        {
            error = "Role must be Admin or User";
            return false;
        }
        return true;
    }

    private sealed class UsersFile
    {
        public List<SettingsUser> Users { get; set; } = [];
    }

    private sealed class SettingsUser
    {
        public string Id { get; set; } = "";
        public string Username { get; set; } = "";
        public string PasswordHash { get; set; } = "";
        public string Role { get; set; } = RoleUser;
    }

    private sealed record Session(string UserId, string Username, string Role, DateTimeOffset ExpiresUtc);

    public sealed record UserPublic(string Id, string Username, string Role);
}

using PhoneBox.Agent;
using Xunit;

public sealed class SettingsAuthTests
{
    private static SettingsAuth NewAuth()
    {
        var dir = Directory.CreateTempSubdirectory("phonebox-auth-").FullName;
        return new SettingsAuth(dir);
    }

    [Fact]
    public void HashAndVerifyRoundTrip()
    {
        var hash = SettingsAuth.HashPassword("correct-horse");
        Assert.StartsWith("pbkdf2$", hash);
        Assert.True(SettingsAuth.VerifyPassword("correct-horse", hash));
        Assert.False(SettingsAuth.VerifyPassword("wrong-password", hash));
        Assert.DoesNotContain("correct-horse", hash, StringComparison.Ordinal);
    }

    [Fact]
    public void FirstRunSetupCreatesAdminAndBlocksSecondSetup()
    {
        var auth = NewAuth();
        Assert.True(auth.NeedsSetup);
        Assert.True(auth.TrySetup("admin", "password1", out var user, out var err));
        Assert.Null(err);
        Assert.Equal("admin", user!.Username);
        Assert.Equal(SettingsAuth.RoleAdmin, user.Role);
        Assert.False(auth.NeedsSetup);
        Assert.False(auth.TrySetup("other", "password1", out _, out err));
        Assert.Equal("Setup already completed", err);
    }

    [Fact]
    public void LoginSessionAndRolePermissions()
    {
        var auth = NewAuth();
        Assert.True(auth.TrySetup("boss", "password1", out var admin, out _));
        Assert.True(auth.TryCreate("viewer", "password1", SettingsAuth.RoleUser, out var viewer, out _));

        Assert.True(auth.TryAuthenticate("boss", "password1", out var ok, out _));
        Assert.Equal(admin!.Id, ok!.Id);
        Assert.False(auth.TryAuthenticate("boss", "nope-nope", out _, out var bad));
        Assert.Equal("Invalid username or password", bad);

        var token = auth.CreateSession(viewer!);
        Assert.Equal("viewer", auth.GetSessionUser(token)!.Username);
        auth.RevokeSession(token);
        Assert.Null(auth.GetSessionUser(token));

        Assert.True(SettingsAuth.IsAllowedForRole(SettingsAuth.RoleAdmin, "PUT", "/api/settings"));
        Assert.False(SettingsAuth.IsAllowedForRole(SettingsAuth.RoleUser, "PUT", "/api/settings"));
        Assert.True(SettingsAuth.IsAllowedForRole(SettingsAuth.RoleUser, "GET", "/api/settings"));
        Assert.True(SettingsAuth.IsAllowedForRole(SettingsAuth.RoleUser, "GET", "/panel/index.html"));
        Assert.False(SettingsAuth.IsAllowedForRole(SettingsAuth.RoleUser, "GET", "/api/users"));
        Assert.True(SettingsAuth.IsAnonymousPath("/api/info", "GET"));
        Assert.True(SettingsAuth.IsAnonymousPath("/api/auth/login", "POST"));
    }

    [Fact]
    public void CannotDeleteLastAdmin()
    {
        var auth = NewAuth();
        Assert.True(auth.TrySetup("solo", "password1", out var admin, out _));
        Assert.False(auth.TryDelete(admin!.Id, out var err));
        Assert.Equal("Keep at least one Admin account", err);
        Assert.True(auth.TryCreate("helper", "password1", SettingsAuth.RoleAdmin, out var helper, out _));
        Assert.True(auth.TryDelete(admin.Id, out _));
        Assert.False(auth.TryUpdate(helper!.Id, null, null, SettingsAuth.RoleUser, out _, out err));
        Assert.Equal("Keep at least one Admin account", err);
    }

    [Fact]
    public void PersistsUsersAcrossReload()
    {
        var dir = Directory.CreateTempSubdirectory("phonebox-auth-persist-").FullName;
        var auth = new SettingsAuth(dir);
        Assert.True(auth.TrySetup("keep", "password1", out _, out _));
        var again = new SettingsAuth(dir);
        Assert.False(again.NeedsSetup);
        Assert.True(again.TryAuthenticate("keep", "password1", out var u, out _));
        Assert.Equal(SettingsAuth.RoleAdmin, u!.Role);
        var json = File.ReadAllText(Path.Combine(dir, "settings-users.json"));
        Assert.DoesNotContain("password1", json, StringComparison.Ordinal);
        Assert.Contains("passwordHash", json, StringComparison.OrdinalIgnoreCase);
    }
}

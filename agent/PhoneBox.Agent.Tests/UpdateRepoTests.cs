using System.Text.Json;
using PhoneBox.Agent;
using Xunit;

public sealed class UpdateRepoTests
{
    [Theory]
    [InlineData("G-Tech-marksman/phonebox", "G-Tech-marksman/phonebox")]
    [InlineData("https://github.com/G-Tech-marksman/phonebox", "G-Tech-marksman/phonebox")]
    [InlineData("https://github.com/G-Tech-marksman/phonebox/", "G-Tech-marksman/phonebox")]
    [InlineData("https://github.com/G-Tech-marksman/phonebox/tree/main", "G-Tech-marksman/phonebox")]
    [InlineData("github.com/foo/bar", "foo/bar")]
    [InlineData("  owner/name  ", "owner/name")]
    public void NormalizeRepoAcceptsOwnerNameAndUrls(string input, string expected) =>
        Assert.Equal(expected, UpdateService.NormalizeRepo(input));

    [Theory]
    [InlineData("")]
    [InlineData("noslash")]
    [InlineData("a/b/c")]
    [InlineData("https://gitlab.com/owner/name")]
    [InlineData("https://github.com/onlyowner")]
    public void NormalizeRepoRejectsJunk(string input) =>
        Assert.Null(UpdateService.NormalizeRepo(input));
}

public sealed class LanAdvertiseTests
{
    [Fact]
    public void AdvertiseHostsAcceptPublicDnsAndRejectLoopback()
    {
        Assert.True(Lan.IsAdvertiseHost("203.0.113.10"));
        Assert.True(Lan.IsAdvertiseHost("home.example.com"));
        Assert.True(Lan.IsAdvertiseHost("desk.tail1234.ts.net"));
        Assert.True(Lan.IsAdvertiseHost("vpn2-g-tech.tech"));
        Assert.True(Lan.IsAdvertiseHost("192.168.1.10"));
        Assert.False(Lan.IsAdvertiseHost("127.0.0.1"));
        Assert.False(Lan.IsAdvertiseHost("localhost"));
        Assert.False(Lan.IsAdvertiseHost("169.254.1.1"));
        Assert.False(Lan.IsAdvertiseHost(""));
    }

    [Fact]
    public void NormalizeAdvertiseHostsDedupesAndCaps()
    {
        var list = Lan.NormalizeAdvertiseHosts(["home.example.com", " home.example.com ", "203.0.113.10", "127.0.0.1", "a,b"]);
        Assert.Equal(["home.example.com", "203.0.113.10", "a", "b"], list);
    }

    [Fact]
    public void AdvertisedHostsPutsUserRemoteHostsFirst()
    {
        var lan = new LanConfig
        {
            Enabled = true,
            Port = 1766,
            AdvertiseHosts = ["vpn2-g-tech.tech", "192.168.1.10"],
        };
        var hosts = Lan.AdvertisedHosts(lan);
        Assert.Equal("vpn2-g-tech.tech", hosts[0]);
        Assert.Contains("vpn2-g-tech.tech", hosts);
        Assert.True(hosts.Count <= 8);
    }

    [Fact]
    public void PersistGeneratedMigratesLegacyLanPortToFixed1766()
    {
        var dir = Directory.CreateTempSubdirectory("phonebox-lan-port-").FullName;
        try
        {
            var path = Path.Combine(dir, "config.json");
            File.WriteAllText(path, """{"lan":{"enabled":true,"port":8766,"token":"phone-tok","webhookToken":"hook-tok"},"updates":{"repo":"G-Tech-marksman/phonebox"}}""");
            var store = new ConfigStore(path);
            Assert.Equal(8766, JsonSerializer.Deserialize<AgentConfig>(File.ReadAllText(path), ConfigStore.ReadOpts)!.Lan.Port);
            Assert.Equal(LanConfig.FixedPort, store.Get().Lan.Port);
            store.PersistGenerated();
            var saved = JsonSerializer.Deserialize<AgentConfig>(File.ReadAllText(path), ConfigStore.ReadOpts)!;
            Assert.Equal(LanConfig.FixedPort, saved.Lan.Port);
            Assert.Equal("phone-tok", saved.Lan.Token);
            Assert.True(saved.Lan.Enabled);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }
}

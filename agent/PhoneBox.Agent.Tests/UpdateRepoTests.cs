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
    public void IsAllowedSettingsHostAcceptsLoopbackLanAndAdvertiseDns()
    {
        var lan = new LanConfig { Enabled = true, AdvertiseHosts = ["vpn2-g-tech.tech"] };
        Assert.True(Lan.IsAllowedSettingsHost("127.0.0.1", lan));
        Assert.True(Lan.IsAllowedSettingsHost("localhost", lan));
        Assert.True(Lan.IsAllowedSettingsHost("192.168.1.101", lan));
        Assert.True(Lan.IsAllowedSettingsHost("10.0.0.5", lan));
        Assert.True(Lan.IsAllowedSettingsHost("vpn2-g-tech.tech", lan));
        Assert.True(Lan.IsAllowedSettingsHost("home.example.com", lan)); // valid advertise-shaped DNS
        Assert.False(Lan.IsAllowedSettingsHost("169.254.1.1", lan));
        Assert.False(Lan.IsAllowedSettingsHost("", lan));
        Assert.False(Lan.IsAllowedSettingsHost(null, lan));
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
    public void WifiBindAddressesOmitsLoopbackAndLinkLocal()
    {
        foreach (var ip in Lan.WifiBindAddresses())
        {
            Assert.Equal(System.Net.Sockets.AddressFamily.InterNetwork, ip.AddressFamily);
            var b = ip.GetAddressBytes();
            Assert.NotEqual(127, b[0]);
            Assert.False(b[0] == 169 && b[1] == 254);
        }
    }

    [Fact]
    public void TryProbeBindAcceptsLoopbackOnEphemeralPort()
    {
        // Bind port 0 to learn a free port, release, then probe that port on loopback.
        int port;
        using (var s = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp))
        {
            s.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
            port = ((System.Net.IPEndPoint)s.LocalEndPoint!).Port;
        }
        Assert.True(Lan.TryProbeBind(System.Net.IPAddress.Loopback, port));
        Assert.False(Lan.TryProbeBind(System.Net.IPAddress.Loopback, 1)); // typically privileged / refused
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

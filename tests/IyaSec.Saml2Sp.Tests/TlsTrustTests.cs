// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IyaSec.Saml;

namespace IyaSec.Saml2Sp.Tests;

// iya-sts's TLS listener presents leaf, TLS issuing CA, intermediate and root,
// and GET /tls/server-certificate answers the same chain, which the setup script
// saves where tls.Ca names it. The library must take every certificate in that
// file, and, since its validation callback replaces the platform's whole
// decision, it must check the listener's name itself. The server below sends
// only its leaf, so the chain can be built only through the file.
public class TlsTrustTests
{
    sealed class Chain
    {
        public X509Certificate2 Leaf = null!;
        public string Pem = "";
        public string RootPem = "";
    }

    static Chain MakeChain(string name, Action<SubjectAlternativeNameBuilder> names)
    {
        var now = DateTimeOffset.UtcNow;
        X509Certificate2 Ca(string cn, X509Certificate2? issuer, RSA key)
        {
            var req = new CertificateRequest("CN=" + cn, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
            if (issuer == null) return req.CreateSelfSigned(now.AddDays(-1), now.AddDays(30));
            req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
            return req.Create(issuer, now.AddDays(-1), now.AddDays(29), RandomNumberGenerator.GetBytes(12));
        }
        using var rootKey = RSA.Create(2048);
        using var midKey = RSA.Create(2048);
        using var issuingKey = RSA.Create(2048);
        using var root = Ca(name + " Root CA", null, rootKey);
        using var mid = Ca(name + " Intermediate CA", root, midKey);
        using var midWithKey = mid.CopyWithPrivateKey(midKey);
        using var issuing = Ca(name + " TLS Issuing CA", midWithKey, issuingKey);
        using var issuingWithKey = issuing.CopyWithPrivateKey(issuingKey);
        var leafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=" + name, leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        names(san);
        leafReq.CertificateExtensions.Add(san.Build());
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        leafReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuingWithKey, true, false));
        using var leaf = leafReq.Create(issuingWithKey, now.AddDays(-1), now.AddDays(28), RandomNumberGenerator.GetBytes(12));
        using var leafWithKey = leaf.CopyWithPrivateKey(leafKey);
        string Pem(X509Certificate2 cert) => new string(PemEncoding.Write("CERTIFICATE", cert.RawData)) + "\n";
        return new Chain
        {
            Leaf = new X509Certificate2(leafWithKey.Export(X509ContentType.Pkcs12)),
            Pem = Pem(leaf) + Pem(issuing) + Pem(mid) + Pem(root),
            RootPem = Pem(root),
        };
    }

    // The names an iya-sts TLS listener certificate carries.
    static void IyaStsNames(SubjectAlternativeNameBuilder san)
    {
        san.AddDnsName("localhost");
        san.AddDnsName("sts");
        san.AddDnsName("sts-mock");
        san.AddDnsName("sts.example.com");
        san.AddIpAddress(IPAddress.Loopback);
    }

    // A one-connection-at-a-time HTTPS server that presents only the leaf, or the
    // leaf followed by `extra`. `answer` maps a path to a body (null is a 404).
    sealed class TlsServer : IDisposable
    {
        readonly TcpListener _tcp = new(IPAddress.Loopback, 0);
        public int Port => ((IPEndPoint)_tcp.LocalEndpoint).Port;

        public TlsServer(X509Certificate2 leaf, Func<string, string?>? answer = null, X509Certificate2Collection? extra = null)
        {
            var context = extra == null ? null : SslStreamCertificateContext.Create(leaf, extra, offline: true);
            _tcp.Start();
            new Thread(() =>
            {
                while (true)
                {
                    TcpClient client;
                    try { client = _tcp.AcceptTcpClient(); }
                    catch { return; }
                    try
                    {
                        using (client)
                        using (var tls = new SslStream(client.GetStream()))
                        {
                            if (context == null) tls.AuthenticateAsServer(leaf, false, false);
                            else tls.AuthenticateAsServer(new SslServerAuthenticationOptions { ServerCertificateContext = context });
                            var head = new StringBuilder();
                            var one = new byte[1];
                            while (!head.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal) && tls.Read(one, 0, 1) == 1)
                                head.Append((char)one[0]);
                            var path = head.ToString().Split(' ', 3)[1];
                            var body = answer == null ? "ok" : answer(path);
                            var bytes = Encoding.UTF8.GetBytes(body ?? "Not found");
                            var status = body == null ? "404 Not Found" : "200 OK";
                            tls.Write(Encoding.ASCII.GetBytes("HTTP/1.1 " + status + "\r\ncontent-type: text/plain\r\ncontent-length: " + bytes.Length + "\r\nconnection: close\r\n\r\n"));
                            tls.Write(bytes);
                        }
                    }
                    catch { }
                }
            }) { IsBackground = true }.Start();
        }

        public void Dispose() => _tcp.Stop();
    }

    static SamlException? Fetch(Chain chain, string host, string? caPem = null)
    {
        using var server = new TlsServer(chain.Leaf);
        try
        {
            var answer = HttpSend.Send("https://" + host + ":" + server.Port + "/", "GET", new Dictionary<string, string>(), "", new TlsOptions { Ca = caPem ?? chain.Pem }, "metadata");
            Assert.Equal(200, answer.Status);
            Assert.Equal("ok", answer.Body);
            return null;
        }
        catch (SamlException err) { return err; }
    }

    [Fact]
    public void TheWholeChainFileIsTheTrustStore()
    {
        // The leaf comes first in the file; reading only the first block left
        // no anchor to build to.
        var chain = MakeChain("sts", IyaStsNames);
        Assert.Null(Fetch(chain, "127.0.0.1"));
        Assert.Equal(4, HttpSend.TrustStore(chain.Pem).Count);
    }

    [Fact]
    public void TheRootAloneCannotBuildALeafOnlyChain()
    {
        // The server here sends only its leaf, so the root alone cannot build
        // the chain; this pins that the anchor is the root, not every block.
        var chain = MakeChain("sts", IyaStsNames);
        Assert.NotNull(Fetch(chain, "127.0.0.1", chain.RootPem));
    }

    [Fact]
    public void AChainFromAnotherRootIsRefused()
    {
        var chain = MakeChain("sts", IyaStsNames);
        var other = MakeChain("other", IyaStsNames);
        var err = Fetch(chain, "127.0.0.1", other.Pem);
        Assert.NotNull(err);
        Assert.Equal("metadata", err!.Code);
    }

    // The chain is good; the name is not. The custom callback replaces the
    // platform's decision, name check included, so it has to refuse this itself.
    [Fact]
    public void AListenerNamingAnotherHostIsRefusedThoughItChainsToTheAnchor()
    {
        var chain = MakeChain("sts", san => san.AddDnsName("other.example.com"));
        var err = Fetch(chain, "localhost");
        Assert.NotNull(err);
        Assert.Equal("metadata", err!.Code);
    }

    [Fact]
    public void AnIpLiteralMustMatchAnIpAddressSan()
    {
        var chain = MakeChain("sts", san => san.AddDnsName("localhost"));
        Assert.NotNull(Fetch(chain, "127.0.0.1"));
    }

    [Fact]
    public void TheIyaStsListenerIsAcceptedByItsDnsNameAndByItsIpAddress()
    {
        var chain = MakeChain("sts", IyaStsNames);
        Assert.Null(Fetch(chain, "localhost"));
        Assert.Null(Fetch(chain, "127.0.0.1"));
    }

    [Fact]
    public void TheIyaStsListenerIsRefusedUnderANameItDoesNotCarry()
    {
        var chain = MakeChain("sts", san => { san.AddDnsName("sts.example.com"); san.AddIpAddress(IPAddress.Parse("10.9.8.7")); });
        Assert.NotNull(Fetch(chain, "localhost"));
        Assert.NotNull(Fetch(chain, "127.0.0.1"));
    }

    [Fact]
    public void ANameMismatchReportedByThePlatformIsRefused()
    {
        var chain = MakeChain("sts", IyaStsNames);
        var store = HttpSend.TrustStore(chain.Pem);
        Assert.True(HttpSend.Accept(chain.Leaf, SslPolicyErrors.RemoteCertificateChainErrors, store, "127.0.0.1"));
        Assert.False(HttpSend.Accept(chain.Leaf, SslPolicyErrors.RemoteCertificateNameMismatch, store, "127.0.0.1"));
        Assert.False(HttpSend.Accept(chain.Leaf, SslPolicyErrors.None, store, "sts.other.test"));
    }

    // Pin matching: the presented LEAF must chain to the file. A server that sends a
    // forged leaf (same names, the real issuing CA's name and key identifier, signed
    // by another key) followed by the real, public CA certificates must be refused:
    // the CA certificates matching the file is not a reason to accept.
    [Fact]
    public void AForgedLeafFollowedByTheRealCaCertificatesIsRefused()
    {
        var chain = MakeChain("sts", IyaStsNames);
        var real = new X509Certificate2Collection();
        real.ImportFromPem(chain.Pem);
        var cas = new X509Certificate2Collection();
        for (var i = 1; i < real.Count; i++) cas.Add(real[i]);
        var issuing = real[1];
        var now = DateTimeOffset.UtcNow;
        using var attacker = RSA.Create(2048);
        var leafKey = RSA.Create(2048);
        var req = new CertificateRequest("CN=sts", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        IyaStsNames(san);
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuing, true, false));
        using var forged = req.Create(issuing.SubjectName, X509SignatureGenerator.CreateForRSA(attacker, RSASignaturePadding.Pkcs1), now.AddDays(-1), now.AddDays(10), RandomNumberGenerator.GetBytes(12));
        using var forgedWithKey = forged.CopyWithPrivateKey(leafKey);
        var forgedLeaf = new X509Certificate2(forgedWithKey.Export(X509ContentType.Pkcs12));
        using var server = new TlsServer(forgedLeaf, extra: cas);
        // The server really does send the real issuing CA certificate after its leaf.
        var presented = new List<string>();
        using (var tcp = new TcpClient("127.0.0.1", server.Port))
        using (var probe = new SslStream(tcp.GetStream(), false, (_, _, sent, _) =>
        {
            foreach (var item in sent?.ChainPolicy.ExtraStore ?? new X509Certificate2Collection()) presented.Add(item.Thumbprint);
            return true;
        }))
            probe.AuthenticateAsClient("127.0.0.1");
        Assert.Contains(issuing.Thumbprint, presented);
        SamlException? err = null;
        try { HttpSend.Send("https://127.0.0.1:" + server.Port + "/", "GET", new Dictionary<string, string>(), "", new TlsOptions { Ca = chain.Pem }, "metadata"); }
        catch (SamlException caught) { err = caught; }
        Assert.NotNull(err);
        Assert.Equal("metadata", err!.Code);
        Assert.False(HttpSend.Accept(forgedLeaf, SslPolicyErrors.None, HttpSend.TrustStore(chain.Pem), "127.0.0.1"));
    }

    // The install script writes the whole chain iya-sts publishes where idpCa
    // points, and the service provider takes that file, as written, as its trust
    // store for the metadata fetch.
    [Fact]
    public void TheScriptWritesTheWholeChainWhereIdpCaPointsAndTheLibraryTrustsIt()
    {
        var chain = MakeChain("sts", IyaStsNames);
        using var server = new TlsServer(chain.Leaf, path => path switch
        {
            "/tls/server-certificate" => chain.Pem,
            "/saml2/metadata" => World.IdpMetadata(),
            _ => null,
        });
        var dir = Directory.CreateTempSubdirectory("saml-chain-");
        try
        {
            var config = Path.Combine(dir.FullName, "saml.json");
            File.WriteAllText(config, """
            {
                "entityId": "http://localhost:3000/saml/metadata",
                "acsUrl": "http://localhost:3000/saml/acs",
                "privateKey": "file:generated/sp.key",
                "certificate": "file:generated/sp.crt",
                "idpMetadata": "file:generated/idp-metadata.xml",
                "idpCa": "file:generated/idp-ca.pem"
            }
            """);
            var (code, stdout) = Python("""
            import sys
            sys.path.insert(0, sys.argv[1])
            from configure_iya_sts import files_of, save_idp_ca
            files = files_of(sys.argv[2])
            save_idp_ca(sys.argv[3], files.idp_ca)
            print("wrote " + files.idp_ca)
            """, Path.Combine(RepoRoot(), "scripts"), config, "https://127.0.0.1:" + server.Port);
            Assert.True(code == 0, stdout);
            var saved = Path.Combine(dir.FullName, "generated", "idp-ca.pem");
            Assert.Contains("wrote " + saved, stdout);
            Assert.Contains("(4 certificate(s))", stdout);
            Assert.Contains("trust anchor CN=sts Root CA", stdout);
            var written = File.ReadAllText(saved);
            Assert.Equal(chain.Pem, written);
            Assert.Equal(4, written.Split("-----BEGIN CERTIFICATE-----").Length - 1);
            var sp = ServiceProvider.Create(World.TestConfig(new Dictionary<string, object?>
            {
                ["idpMetadata"] = "https://127.0.0.1:" + server.Port + "/saml2/metadata",
                ["idpCa"] = "file:generated/idp-ca.pem",
            }), dir.FullName, null);
            Assert.StartsWith(World.SsoUrl, sp.Login(new LoginOptions()).Url);
        }
        finally { dir.Delete(true); }
    }

    // rcbj's decision: a generated password is never printed. It is written to
    // <user>.password beside the key pair, mode 0600, and only the path is shown.
    [Fact]
    public void AGeneratedPasswordGoesToAnOwnerOnlyFileAndIsNotPrinted()
    {
        var dir = Directory.CreateTempSubdirectory("saml-password-");
        try
        {
            var stale = Path.Combine(dir.FullName, "saml-demo-user.password");
            File.WriteAllText(stale, "old\n");
            File.SetUnixFileMode(stale, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
            var (code, stdout) = Python("""
            import sys
            sys.path.insert(0, sys.argv[1])
            from configure_iya_sts import save_password
            print("saved " + str(save_password(sys.argv[2], "saml-demo-user", "s3cret-Generated")))
            """, Path.Combine(RepoRoot(), "scripts"), dir.FullName);
            Assert.True(code == 0, stdout);
            Assert.DoesNotContain("s3cret-Generated", stdout);
            Assert.Equal("s3cret-Generated\n", File.ReadAllText(stale));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(stale));
            var source = File.ReadAllText(Path.Combine(RepoRoot(), "scripts", "configure_iya_sts.py"));
            Assert.DoesNotContain("(shown once)", source);
        }
        finally { dir.Delete(true); }
    }

    static (int Code, string Output) Python(string code, params string[] args)
    {
        var psi = new ProcessStartInfo("python3") { RedirectStandardOutput = true, RedirectStandardError = true };
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(code);
        foreach (var arg in args) psi.ArgumentList.Add(arg);
        using var proc = Process.Start(psi)!;
        var stdout = proc.StandardOutput.ReadToEndAsync();
        var stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit();
        return (proc.ExitCode, stdout.Result + stderr);
    }

    static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "scripts", "configure_iya_sts.py"))) return dir.FullName;
            dir = dir.Parent;
        }
        throw new InvalidOperationException("configure_iya_sts.py was not found");
    }
}

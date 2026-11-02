// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IyaSec.Saml;

namespace IyaSec.Saml2Sp.Tests;

// Plain http is refused off loopback for every fetch (#19): the metadata URL,
// the ArtifactResolve and the Shared Signals transmitter.
public class PlainHttpTests
{
    const string PlainRefusal = "plain http is allowed only to a loopback host";

    sealed class QuietLog : ISignalLogger
    {
        public void Info(string message) { }
        public void Warn(string message) { }
        public void Error(string message) { }
    }

    // A raw TCP server on 127.0.0.1 that counts every connection and, when
    // given an answer, writes it and closes. On Linux, http://0.0.0.0:<port>
    // reaches it, so a count of zero after a refusal proves the refusal came
    // before any connection.
    sealed class RawServer : IDisposable
    {
        readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        int _accepted;
        public int Port { get; }
        public int Accepted => Volatile.Read(ref _accepted);

        public RawServer(Func<string>? answer = null, X509Certificate2? tls = null)
        {
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            new Thread(() =>
            {
                while (true)
                {
                    TcpClient client;
                    try { client = _listener.AcceptTcpClient(); }
                    catch { return; }
                    Interlocked.Increment(ref _accepted);
                    using (client)
                    {
                        if (answer == null) continue;
                        try
                        {
                            Stream stream = client.GetStream();
                            if (tls != null)
                            {
                                var secure = new SslStream(stream);
                                secure.AuthenticateAsServer(tls, false, false);
                                stream = secure;
                            }
                            var seen = new StringBuilder();
                            var buffer = new byte[4096];
                            while (!seen.ToString().Contains("\r\n\r\n"))
                            {
                                var n = stream.Read(buffer, 0, buffer.Length);
                                if (n == 0) break;
                                seen.Append(Encoding.ASCII.GetString(buffer, 0, n));
                            }
                            stream.Write(Encoding.UTF8.GetBytes(answer()));
                        }
                        catch { }
                    }
                }
            })
            { IsBackground = true }.Start();
        }

        public void AssertUntouched()
        {
            Thread.Sleep(200);
            Assert.True(Accepted == 0, "the listener saw " + Accepted + " connection(s); the refusal must come before connecting");
        }

        public void Dispose() => _listener.Stop();
    }

    static string Http(int status, string reason, string headers, string body) =>
        "HTTP/1.1 " + status + " " + reason + "\r\n" + headers + "Content-Length: " + Encoding.UTF8.GetByteCount(body) + "\r\nConnection: close\r\n\r\n" + body;

    static void MetadataFrom(string source) =>
        ServiceProvider.Create(World.TestConfig(new Dictionary<string, object?> { ["idpMetadata"] = source }), "", null);

    static void ArtifactThrough(string ars)
    {
        var sp = World.MustSp(null, ars);
        sp.Acs("GET", "/saml/acs?SAMLart=" + Uri.EscapeDataString(World.ArtifactFor()), null, new[] { "_r" });
    }

    static void TransmitterAt(string transmitter)
    {
        var receiver = SignalsReceiver.Create(new ReceiverOptions { Transmitter = transmitter, Log = new QuietLog(), OnEndSessions = (_, _) => null });
        try { receiver.Start(); }
        finally { receiver.Stop(); }
    }

    [Fact]
    public void RefusesPlainHttpOffLoopbackForEveryFetch()
    {
        World.Rejects(() => MetadataFrom("http://example.com/saml/metadata"), "metadata", @"^http://example\.com is refused: " + PlainRefusal);
        World.Rejects(() => ArtifactThrough("http://example.com/ars"), "artifact", @"^http://example\.com is refused: " + PlainRefusal);
        World.Rejects(() => TransmitterAt("http://example.com"), "ssf", @"^http://example\.com is refused: " + PlainRefusal);
    }

    [Fact]
    public void RefusesPlainHttpBeforeConnecting()
    {
        using var stub = new RawServer();
        var origin = "http://0.0.0.0:" + stub.Port;
        World.Rejects(() => MetadataFrom(origin + "/saml/metadata"), "metadata", PlainRefusal);
        World.Rejects(() => ArtifactThrough(origin + "/ars"), "artifact", PlainRefusal);
        World.Rejects(() => TransmitterAt(origin), "ssf", PlainRefusal);
        stub.AssertUntouched();
    }

    [Fact]
    public void UserinfoIsNeverLoopbackAndIsNotRepeated()
    {
        using var stub = new RawServer();
        var ex = Assert.Throws<SamlException>(() => MetadataFrom("http://alice:s3cret-pass@127.0.0.1:" + stub.Port + "/saml/metadata?token=q1"));
        Assert.Equal("metadata", ex.Code);
        Assert.Matches(@"^http://127\.0\.0\.1:" + stub.Port + " is refused: " + PlainRefusal, ex.Message);
        foreach (var leaked in new[] { "alice", "s3cret-pass", "/saml/metadata", "token", "q1" })
            Assert.DoesNotContain(leaked, ex.Message);
        World.Rejects(() => MetadataFrom("http://localhost:80@example.com/saml/metadata"), "metadata", @"^http://example\.com is refused: " + PlainRefusal);
        stub.AssertUntouched();
    }

    [Fact]
    public void PlainHttpToLoopbackStillWorks()
    {
        using var server = new RawServer(() => Http(200, "OK", "Content-Type: application/samlmetadata+xml\r\n", World.IdpMetadata()));
        foreach (var host in new[] { "127.0.0.1", "localhost" })
            MetadataFrom("http://" + host + ":" + server.Port + "/saml/metadata");
        foreach (var loopback in new[] { "http://127.255.0.9/", "http://[::1]:8/", "http://LOCALHOST/" })
            Assert.True(HttpSend.IsLoopbackHost(new Uri(loopback)), loopback);
        foreach (var other in new[] { "http://0.0.0.0/", "http://128.0.0.1/", "http://[::]/", "http://[::ffff:127.0.0.1]/", "http://localhost.example.com/", "http://example.com/" })
            Assert.False(HttpSend.IsLoopbackHost(new Uri(other)), other);
    }

    [Fact]
    public void DoesNotFollowARedirectFromPlainHttp()
    {
        using var stub = new RawServer();
        using var redirector = new RawServer(() => Http(302, "Found", "Location: http://0.0.0.0:" + stub.Port + "/saml/metadata\r\n", ""));
        World.Rejects(() => MetadataFrom("http://127.0.0.1:" + redirector.Port + "/saml/metadata"), "metadata", "answered HTTP 302");
        stub.AssertUntouched();
    }

    [Fact]
    public void HttpsToAnUnreachableHostIsAConnectionError()
    {
        var ex = Assert.Throws<SamlException>(() => MetadataFrom("https://127.0.0.1:1/saml/metadata"));
        Assert.Equal("metadata", ex.Code);
        Assert.DoesNotContain(PlainRefusal, ex.Message);
        Assert.Contains("refused", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // A self-signed certificate for 127.0.0.1, and its PEM as the trust anchor.
    static (X509Certificate2 Cert, string Pem) LoopbackCertificate()
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=127.0.0.1", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Loopback);
        req.CertificateExtensions.Add(san.Build());
        using var made = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var pem = new string(PemEncoding.Write("CERTIFICATE", made.RawData)) + "\n";
        return (new X509Certificate2(made.Export(X509ContentType.Pkcs12)), pem);
    }

    // Redirects to plain http are not followed: from loopback http none is,
    // and .NET never follows https to http. The 3xx is the answer, so the
    // metadata fetch fails on it and nothing reaches the redirect target.
    [Fact]
    public void DoesNotFollowARedirectToExampleComFromLoopbackOrHttps()
    {
        var away = Http(302, "Found", "Location: http://example.com/saml/metadata\r\n", "");
        using var plain = new RawServer(() => away);
        World.Rejects(() => MetadataFrom("http://127.0.0.1:" + plain.Port + "/saml/metadata"), "metadata", "answered HTTP 302");
        var (cert, pem) = LoopbackCertificate();
        using var secure = new RawServer(() => away, cert);
        var answer = HttpSend.Send("https://127.0.0.1:" + secure.Port + "/saml/metadata", "GET", new Dictionary<string, string>(), "", new TlsOptions { Ca = pem }, "metadata");
        Assert.Equal(302, answer.Status);
        using var stub = new RawServer();
        using var toStub = new RawServer(() => Http(302, "Found", "Location: http://0.0.0.0:" + stub.Port + "/saml/metadata\r\n", ""), cert);
        Assert.Equal(302, HttpSend.Send("https://127.0.0.1:" + toStub.Port + "/", "GET", new Dictionary<string, string>(), "", new TlsOptions { Ca = pem }, "metadata").Status);
        stub.AssertUntouched();
    }

    [Fact]
    public void RefusesAUrlWithWhitespaceOrAControlCharacter()
    {
        using var stub = new RawServer();
        var origin = "127.0.0.1:" + stub.Port;
        foreach (var raw in new[] { "http://" + origin + "/saml metadata", "http://" + origin + "\t@example.com/", "https://" + origin + "/a\r\nX-Injected: s3cret", "http://" + origin + "/a\u0000b", "http://" + origin + "/a\u00a0b" })
        {
            var ex = Assert.Throws<SamlException>(() => MetadataFrom(raw));
            Assert.Equal("metadata", ex.Code);
            Assert.Equal("a URL containing whitespace or a control character is refused", ex.Message);
        }
        // The configuration trims idpMetadata; Send itself does not.
        foreach (var raw in new[] { " http://" + origin + "/", "http://" + origin + "/\n" })
            World.Rejects(() => HttpSend.Send(raw, "GET", new Dictionary<string, string>(), "", null, "artifact"), "artifact", "^a URL containing whitespace or a control character is refused$");
        World.Rejects(() => TransmitterAt("http://" + origin + "\n"), "ssf", "whitespace or a control character");
        stub.AssertUntouched();
    }
}

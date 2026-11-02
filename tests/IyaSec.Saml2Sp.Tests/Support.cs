// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using IyaSec.Saml;

namespace IyaSec.Saml2Sp.Tests;

static class World
{
    public const string IdpEntity = "https://idp.test/saml2";
    public const string SpEntity = "https://sp.test/saml/metadata";
    public const string AcsUrl = "https://sp.test/saml/acs";
    public const string SsoUrl = "https://idp.test/saml2/sso";

    public static readonly KeyPair Sp = Keys.CreateSelfSignedKeyPair("sp.test", 30, 2048);
    public static readonly KeyPair Idp = Keys.CreateSelfSignedKeyPair("idp.test", 30, 2048);
    public static readonly RSA Tx = RSA.Create(2048);
    public static readonly RSA Other = RSA.Create(2048);

    public static string IsoOff(int ms) =>
        DateTimeOffset.UtcNow.AddMilliseconds(ms).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    public static string IdpMetadata(string ars = "")
    {
        if (ars.Length == 0) ars = "https://idp.test/saml2/ars";
        return "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"" + IdpEntity + "\">" +
               "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">" +
               "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + XmlUtil.PemBody(Idp.CertificatePem) + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>" +
               "<md:ArtifactResolutionService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\" Location=\"" + ars + "\" index=\"0\" isDefault=\"true\"/>" +
               "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"" + SsoUrl + "\"/>" +
               "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"" + SsoUrl + "\"/>" +
               "</md:IDPSSODescriptor></md:EntityDescriptor>";
    }

    public static Dictionary<string, object?> TestConfig(Dictionary<string, object?>? extra = null, string ars = "")
    {
        var config = new Dictionary<string, object?>
        {
            ["entityId"] = SpEntity,
            ["acsUrl"] = AcsUrl,
            ["privateKey"] = Sp.PrivateKeyPem,
            ["certificate"] = Sp.CertificatePem,
            ["idpMetadata"] = IdpMetadata(ars),
        };
        if (extra != null)
            foreach (var pair in extra) config[pair.Key] = pair.Value;
        return config;
    }

    public static ServiceProvider MustSp(Dictionary<string, object?>? extra = null, string ars = "")
    {
        try
        {
            return ServiceProvider.Create(TestConfig(extra, ars), "", null);
        }
        catch (Exception ex)
        {
            throw new Xunit.Sdk.XunitException("create: " + ex);
        }
    }

    public static void Rejects(Action fn, string code, string pattern)
    {
        var ex = Assert.Throws<SamlException>(fn);
        Assert.Equal(code, ex.Code);
        if (pattern.Length > 0) Assert.Matches(pattern, ex.Message);
    }

    public static (string Xml, string Id) AssertionXml(string inResponseTo = "", string nameId = "", string audience = "", string recipient = "", int notOnOrAfterMs = 0, bool hasExpiry = false, string issuer = "", string extra = "")
    {
        var aid = Ids.New();
        var irt = inResponseTo.Length == 0 ? "" : " InResponseTo=\"" + inResponseTo + "\"";
        if (nameId.Length == 0) nameId = "alice-1234";
        if (audience.Length == 0) audience = SpEntity;
        if (recipient.Length == 0) recipient = AcsUrl;
        var expiry = hasExpiry ? notOnOrAfterMs : 300000;
        if (issuer.Length == 0) issuer = IdpEntity;
        var xml = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"" + aid + "\" Version=\"2.0\" IssueInstant=\"" + IsoOff(0) + "\">" +
                  "<saml:Issuer>" + issuer + "</saml:Issuer>" +
                  "<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">" + nameId + "</saml:NameID>" +
                  "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" +
                  "<saml:SubjectConfirmationData Recipient=\"" + recipient + "\" NotOnOrAfter=\"" + IsoOff(expiry) + "\"" + irt + "/>" +
                  "</saml:SubjectConfirmation></saml:Subject>" +
                  "<saml:Conditions NotBefore=\"" + IsoOff(-5000) + "\" NotOnOrAfter=\"" + IsoOff(expiry) + "\">" +
                  "<saml:AudienceRestriction><saml:Audience>" + audience + "</saml:Audience></saml:AudienceRestriction></saml:Conditions>" +
                  "<saml:AuthnStatement AuthnInstant=\"" + IsoOff(-1000) + "\" SessionIndex=\"_session1\"><saml:AuthnContext>" +
                  "<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>" +
                  "</saml:AuthnContext></saml:AuthnStatement>" +
                  "<saml:AttributeStatement><saml:Attribute Name=\"urn:oid:0.9.2342.19200300.100.1.3\" FriendlyName=\"mail\">" +
                  "<saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>" +
                  "<saml:Attribute Name=\"groups\"><saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute>" +
                  extra + "</saml:AttributeStatement></saml:Assertion>";
        return (xml, aid);
    }

    public static string SignXml(string xml, string id, RSA? key = null, X509Certificate2? cert = null)
    {
        key ??= Idp.PrivateKey;
        cert ??= Idp.Certificate;
        return Canon.SignEnveloped(xml, id, key, cert);
    }

    public static (string Xml, string Id) SignedAssertion(string inResponseTo = "", string nameId = "", string audience = "", string recipient = "", int notOnOrAfterMs = 0, bool hasExpiry = false, string issuer = "", string extra = "")
    {
        var (xml, id) = AssertionXml(inResponseTo, nameId, audience, recipient, notOnOrAfterMs, hasExpiry, issuer, extra);
        return (SignXml(xml, id), id);
    }

    public static string ResponseXml(string inResponseTo = "", bool sign = false, string assertion = "", bool hasAssertion = false, string status = "", string destination = "", bool hasDestination = false, bool omitDestination = false, string issuer = "")
    {
        var rid = Ids.New();
        var irt = inResponseTo.Length == 0 ? "" : " InResponseTo=\"" + inResponseTo + "\"";
        var dest = "";
        if (!omitDestination)
        {
            var value = hasDestination ? destination : AcsUrl;
            dest = " Destination=\"" + value + "\"";
        }
        if (status.Length == 0) status = "urn:oasis:names:tc:SAML:2.0:status:Success";
        if (!hasAssertion)
            assertion = status.EndsWith("Success", StringComparison.Ordinal) ? SignedAssertion(inResponseTo).Xml : "";
        if (issuer.Length == 0) issuer = IdpEntity;
        var xml = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"" + rid + "\" Version=\"2.0\" IssueInstant=\"" + IsoOff(0) + "\"" + dest + irt + ">" +
                  "<saml:Issuer>" + issuer + "</saml:Issuer>" +
                  "<samlp:Status><samlp:StatusCode Value=\"" + status + "\"/></samlp:Status>" +
                  assertion + "</samlp:Response>";
        return sign ? SignXml(xml, rid) : xml;
    }

    public static SamlLogin PostAcs(ServiceProvider sp, string xml, string requestId, string? relay)
    {
        var body = new Dictionary<string, string> { ["SAMLResponse"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(xml)) };
        if (relay != null) body["RelayState"] = relay;
        IReadOnlyList<string>? ids = requestId.Length == 0 ? null : new[] { requestId };
        return sp.Acs("POST", "/saml/acs", body, ids);
    }

    public static bool VerifyOk(XmlElement root, X509Certificate2 cert)
    {
        try
        {
            return Canon.VerifySigned(root, new[] { cert }, "the message") != null;
        }
        catch
        {
            return false;
        }
    }

    public static string EncryptAssertion(string assertion, string cipherName = "", string transport = "", string wrapper = "")
    {
        if (cipherName.Length == 0) cipherName = "aes-256-gcm";
        if (transport.Length == 0) transport = "mgf1p";
        if (wrapper.Length == 0) wrapper = "EncryptedAssertion";
        var key = new byte[cipherName == "aes-256-gcm" ? 32 : 16];
        RandomNumberGenerator.Fill(key);
        byte[] blob;
        string alg;
        if (cipherName == "aes-256-gcm")
        {
            var iv = new byte[12];
            RandomNumberGenerator.Fill(iv);
            var plain = Encoding.UTF8.GetBytes(assertion);
            var cipher = new byte[plain.Length];
            var tag = new byte[16];
            using (var aes = new AesGcm(key, 16)) aes.Encrypt(iv, plain, cipher, tag);
            blob = iv.Concat(cipher).Concat(tag).ToArray();
            alg = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
        }
        else
        {
            var iv = new byte[16];
            RandomNumberGenerator.Fill(iv);
            var plain = Encoding.UTF8.GetBytes(assertion);
            var pad = 16 - (plain.Length % 16);
            var padded = plain.Concat(Enumerable.Repeat((byte)pad, pad)).ToArray();
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            using var enc = aes.CreateEncryptor();
            blob = iv.Concat(enc.TransformFinalBlock(padded, 0, padded.Length)).ToArray();
            alg = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
        }
        var wrapped = Sp.PrivateKey.Encrypt(key, transport == "mgf1p" ? RSAEncryptionPadding.OaepSHA1 : RSAEncryptionPadding.OaepSHA256);
        var keyMethod = "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/>";
        if (transport != "mgf1p")
            keyMethod = "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\">" +
                        "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>" +
                        "<xenc11:MGF xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" Algorithm=\"http://www.w3.org/2009/xmlenc11#mgf1sha256\"/>" +
                        "</xenc:EncryptionMethod>";
        return "<saml:" + wrapper + " xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" +
               "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\">" +
               "<xenc:EncryptionMethod Algorithm=\"" + alg + "\"/>" +
               "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedKey>" + keyMethod +
               "<xenc:CipherData><xenc:CipherValue>" + Convert.ToBase64String(wrapped) + "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>" +
               "<xenc:CipherData><xenc:CipherValue>" + Convert.ToBase64String(blob) + "</xenc:CipherValue></xenc:CipherData>" +
               "</xenc:EncryptedData></saml:" + wrapper + ">";
    }

    public static string RedirectResponseQuery(string xml, string relay, RSA? key = null)
    {
        key ??= Idp.PrivateKey;
        return Bindings.RedirectQuery("SAMLResponse", xml, relay, key);
    }

    public static string ArtifactFor(string entity = "")
    {
        if (entity.Length == 0) entity = IdpEntity;
        var raw = new byte[44];
        raw[1] = 4;
        Buffer.BlockCopy(SHA1.HashData(Encoding.UTF8.GetBytes(entity)), 0, raw, 4, 20);
        RandomNumberGenerator.Fill(raw.AsSpan(24));
        return Convert.ToBase64String(raw);
    }

    public static string B64Url(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static Dictionary<string, object?> Jwk(RSA key, string kid)
    {
        var parts = key.ExportParameters(false);
        return new Dictionary<string, object?>
        {
            ["kty"] = "RSA",
            ["n"] = B64Url(parts.Modulus!),
            ["e"] = B64Url(parts.Exponent!),
            ["kid"] = kid,
            ["alg"] = "RS256",
            ["use"] = "sig",
        };
    }

    public static string SignJws(Dictionary<string, object?> payload, RSA key, Dictionary<string, object?>? header = null)
    {
        header ??= new Dictionary<string, object?> { ["alg"] = "RS256", ["kid"] = "k1", ["typ"] = "secevent+jwt" };
        var h = B64Url(Encoding.UTF8.GetBytes(JsonMaps.Stringify(header)));
        var p = B64Url(Encoding.UTF8.GetBytes(JsonMaps.Stringify(payload)));
        var alg = header.TryGetValue("alg", out var raw) && raw is string text ? text : "";
        var sig = "";
        if (alg.Length > 0 && alg != "none" && alg != "HS256")
            sig = B64Url(key.SignData(Encoding.UTF8.GetBytes(h + "." + p), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        return h + "." + p + "." + sig;
    }
}

sealed class LoopServer : IDisposable
{
    public HttpListener Listener { get; }
    public string Origin { get; }
    readonly Thread _thread;

    public LoopServer(Action<HttpListenerContext> handle)
    {
        HttpListener? started = null;
        var origin = "";
        for (var i = 0; i < 40; i++)
        {
            var port = Random.Shared.Next(20000, 50000);
            var listener = new HttpListener();
            listener.Prefixes.Add("http://127.0.0.1:" + port + "/");
            try
            {
                listener.Start();
                started = listener;
                origin = "http://127.0.0.1:" + port;
                break;
            }
            catch
            {
                listener.Close();
            }
        }
        if (started == null) throw new InvalidOperationException("no local port");
        Listener = started;
        Origin = origin;
        _thread = new Thread(() =>
        {
            while (Listener.IsListening)
            {
                HttpListenerContext ctx;
                try { ctx = Listener.GetContext(); }
                catch { break; }
                try { handle(ctx); }
                catch { try { ctx.Response.Abort(); } catch { } }
            }
        })
        { IsBackground = true };
        _thread.Start();
    }

    public static void Write(HttpListenerContext ctx, int status, string body, string type)
    {
        var bytes = Encoding.UTF8.GetBytes(body);
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = type;
        ctx.Response.ContentLength64 = bytes.Length;
        ctx.Response.OutputStream.Write(bytes);
        ctx.Response.OutputStream.Close();
    }

    public static string ReadBody(HttpListenerRequest request)
    {
        using var reader = new StreamReader(request.InputStream, Encoding.UTF8);
        var text = reader.ReadToEnd();
        return text.Length > 2 * 1024 * 1024 ? text[..(2 * 1024 * 1024)] : text;
    }

    public void Dispose()
    {
        try { Listener.Stop(); } catch { }
        try { Listener.Close(); } catch { }
    }
}

sealed class ArsServer : IDisposable
{
    readonly object _gate = new();
    readonly Dictionary<string, string> _store = new();
    public readonly List<string> Resolved = new();
    public string Url { get; }
    readonly LoopServer _server;

    public ArsServer()
    {
        _server = new LoopServer(Handle);
        Url = _server.Origin + "/ars";
    }

    public void Put(string artifact, string response)
    {
        lock (_gate) _store[artifact] = response;
    }

    void Handle(HttpListenerContext ctx)
    {
        var raw = LoopServer.ReadBody(ctx.Request);
        var ok = false;
        var resolveId = "";
        var artifact = "";
        try
        {
            var root = XmlUtil.Parse(raw, "the ArtifactResolve");
            var found = XmlUtil.Descendants(root, XmlUtil.NsSamlp, "ArtifactResolve");
            if (found.Count > 0)
            {
                var body = found[0];
                resolveId = XmlUtil.AttrOr(body, "ID");
                var arts = XmlUtil.Children(body, XmlUtil.NsSamlp, "Artifact");
                if (arts.Count > 0) artifact = XmlUtil.IterText(arts[0]).Trim();
                var signed = Canon.VerifySigned(body, new[] { World.Sp.Certificate }, "the ArtifactResolve");
                ok = signed != null;
            }
        }
        catch
        {
            ok = false;
        }
        var message = "";
        lock (_gate)
        {
            if (ok && _store.TryGetValue(artifact, out var stored))
            {
                message = stored;
                _store.Remove(artifact);
                if (message.Length > 0) Resolved.Add(artifact);
            }
        }
        var answer = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>" +
                     "<samlp:ArtifactResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"" + Ids.New() + "\" Version=\"2.0\" IssueInstant=\"" + World.IsoOff(0) + "\" InResponseTo=\"" + resolveId + "\">" +
                     "<saml:Issuer>" + World.IdpEntity + "</saml:Issuer>" +
                     "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" +
                     message + "</samlp:ArtifactResponse></soap:Body></soap:Envelope>";
        LoopServer.Write(ctx, 200, answer, "text/xml");
    }

    public void Dispose() => _server.Dispose();
}

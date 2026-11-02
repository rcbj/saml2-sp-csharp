// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace IyaSec.Saml;

public sealed class TlsOptions
{
    public string Ca { get; init; } = "";
    public string Cert { get; init; } = "";
    public string Key { get; init; } = "";
}

static class HttpSend
{
    const int MaxBytes = 2 * 1024 * 1024;

    internal sealed class Answer
    {
        public int Status { get; init; }
        public string ContentType { get; init; } = "";
        public string Body { get; init; } = "";
    }

    internal static Answer Send(string rawUrl, string method, IReadOnlyDictionary<string, string> headers, string body, TlsOptions? tls, string code)
    {
        if (!(rawUrl.StartsWith("https://", StringComparison.Ordinal) || rawUrl.StartsWith("http://", StringComparison.Ordinal)))
            throw new SamlException(code, rawUrl + " is not an http(s) URL");
        using var handler = new HttpClientHandler { SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13 };
        if (rawUrl.StartsWith("https://", StringComparison.Ordinal) && tls != null && tls.Ca.Length > 0)
        {
            X509Certificate2Collection ca;
            try { ca = TrustStore(tls.Ca); }
            catch { throw new SamlException(code, rawUrl + ": the CA certificate cannot be read"); }
            var host = HostOf(rawUrl);
            handler.ServerCertificateCustomValidationCallback = (_, cert, _, errors) => Accept(cert, errors, ca, host);
        }
        if (tls != null && tls.Cert.Length > 0 && tls.Key.Length > 0)
        {
            try
            {
                using var leaf = X509Certificate2.CreateFromPem(tls.Cert, tls.Key);
                handler.ClientCertificates.Add(new X509Certificate2(leaf.Export(X509ContentType.Pfx)));
            }
            catch (Exception ex)
            {
                throw new SamlException(code, rawUrl + ": " + ex.Message, ex);
            }
        }
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
        using var request = new HttpRequestMessage(new HttpMethod(method), rawUrl);
        foreach (var pair in headers) request.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
        if (method is not "GET" and not "HEAD")
            request.Content = new StringContent(body, System.Text.Encoding.UTF8);
        if (request.Content != null && headers.TryGetValue("content-type", out var contentType))
            request.Content.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse(contentType);
        HttpResponseMessage response;
        try
        {
            response = client.Send(request);
        }
        catch (Exception ex)
        {
            var message = ex.ToString().ToLowerInvariant();
            if (message.Contains("timeout") || message.Contains("timed out"))
                throw new SamlException(code, rawUrl + " did not answer within 15 s", ex);
            throw new SamlException(code, rawUrl + ": " + ex.Message, ex);
        }
        using (response)
        {
            var payload = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
            if (payload.Length > MaxBytes)
                throw new SamlException(code, rawUrl + " answered more than " + MaxBytes + " bytes");
            var type = response.Content.Headers.ContentType?.ToString() ?? "";
            return new Answer { Status = (int)response.StatusCode, ContentType = type, Body = System.Text.Encoding.UTF8.GetString(payload) };
        }
    }
    // tls.Ca may be one certificate or a whole trust chain: iya-sts publishes its
    // listener chain (leaf, TLS issuing CA, intermediate, root) and the setup
    // script saves all of it. Every PEM block is read (CreateFromPem reads only
    // the first, the leaf). The self-signed ones are the trust anchors and the
    // rest are intermediates the chain may be built through. A file with no
    // self-signed certificate keeps the old meaning: every certificate in it is
    // an anchor.
    internal static X509Certificate2Collection TrustStore(string pem)
    {
        var all = new X509Certificate2Collection();
        all.ImportFromPem(pem);
        if (all.Count == 0) throw new CryptographicException("no certificate");
        return all;
    }

    static bool SelfSigned(X509Certificate2 cert) => cert.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData);

    // The callback replaces the platform's whole decision, the name check
    // included, so it makes that check itself: a certificate that chains to the
    // configured anchors but names another host is refused. An IP literal must
    // match an IP address SAN.
    internal static bool Accept(X509Certificate? cert, SslPolicyErrors errors, X509Certificate2Collection ca, string host)
    {
        if (cert == null) return false;
        if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) return false;
        if ((errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0) return false;
        using var leaf = new X509Certificate2(cert);
        if (!NameMatches(leaf, host)) return false;
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        var anchors = ca.Where(SelfSigned).ToList();
        if (anchors.Count == 0) anchors = ca.ToList();
        foreach (var item in ca)
        {
            if (anchors.Contains(item)) chain.ChainPolicy.CustomTrustStore.Add(item);
            else chain.ChainPolicy.ExtraStore.Add(item);
        }
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(leaf);
    }

    internal static string HostOf(string url)
    {
        var host = new Uri(url).IdnHost;
        if (host.StartsWith('[') && host.EndsWith(']')) host = host[1..^1];
        return host;
    }

    internal static bool NameMatches(X509Certificate2 leaf, string host)
    {
        if (string.IsNullOrEmpty(host)) return false;
        try { return leaf.MatchesHostname(host, allowWildcards: true, allowCommonName: false); }
        catch { return false; }
    }
}

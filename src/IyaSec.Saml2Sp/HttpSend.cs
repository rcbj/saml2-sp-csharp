// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Net.Security;
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
            X509Certificate2 ca;
            try { ca = X509Certificate2.CreateFromPem(tls.Ca); }
            catch { throw new SamlException(code, rawUrl + ": the CA certificate cannot be read"); }
            handler.ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
            {
                if (cert == null) return false;
                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(ca);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                return chain.Build(new X509Certificate2(cert));
            };
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
}

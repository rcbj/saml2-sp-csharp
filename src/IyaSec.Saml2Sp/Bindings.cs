// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace IyaSec.Saml;

public static class Bindings
{
    const int MaxInflated = 1024 * 1024;
    static readonly Regex B64 = new(@"^[A-Za-z0-9+/]+={0,2}$", RegexOptions.Compiled);

    public static string PostFormHtml(string action, IReadOnlyDictionary<string, string> fields, string? nonce = null, string? title = null, IReadOnlyList<string>? order = null)
    {
        title = string.IsNullOrEmpty(title) ? "Signing in" : title;
        var names = order?.ToList() ?? fields.Keys.OrderBy(name => name, StringComparer.Ordinal).ToList();
        var lines = new List<string>();
        foreach (var name in names)
        {
            if (!fields.TryGetValue(name, out var value)) continue;
            lines.Add("<input type=\"hidden\" name=\"" + XmlUtil.Escape(name) + "\" value=\"" + XmlUtil.Escape(value) + "\">");
        }
        var script = string.IsNullOrEmpty(nonce) ? "" : "\n    <script nonce=\"" + XmlUtil.Escape(nonce) + "\">document.forms[0].submit();</script>";
        return "<!doctype html>\n<html lang=\"en\">\n  <head><meta charset=\"utf-8\"><title>" + XmlUtil.Escape(title) + "</title></head>\n  <body>\n    <form method=\"post\" action=\"" + XmlUtil.Escape(action) + "\">\n      " + string.Join("\n      ", lines) + "\n      <noscript><p>Your browser is not running scripts. Press Continue to go on.</p></noscript>\n      <button type=\"submit\">Continue</button>\n    </form>" + script + "\n  </body>\n</html>\n";
    }

    internal static byte[] DeflateRaw(byte[] data)
    {
        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, CompressionLevel.Optimal, leaveOpen: true))
            deflate.Write(data, 0, data.Length);
        return output.ToArray();
    }

    internal static byte[] InflateRaw(byte[] data)
    {
        try
        {
            using var input = new MemoryStream(data);
            using var deflate = new DeflateStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            var buffer = new byte[8192];
            while (true)
            {
                var read = deflate.Read(buffer, 0, buffer.Length);
                if (read == 0) break;
                if (output.Length + read > MaxInflated)
                    throw new SamlException("binding", "the message inflates past the limit");
                output.Write(buffer, 0, read);
            }
            return output.ToArray();
        }
        catch (SamlException)
        {
            throw;
        }
    }

    internal static string RedirectQuery(string param, string xml, string? relayState, RSA key)
    {
        var encoded = Convert.ToBase64String(DeflateRaw(Encoding.UTF8.GetBytes(xml)));
        var parts = new List<string> { param + "=" + UriEscape(encoded) };
        if (relayState != null) parts.Add("RelayState=" + UriEscape(relayState));
        parts.Add("SigAlg=" + UriEscape(XmlUtil.RsaSha256));
        var signed = string.Join("&", parts);
        var sig = key.SignData(Encoding.UTF8.GetBytes(signed), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return signed + "&Signature=" + UriEscape(Convert.ToBase64String(sig));
    }

    internal sealed class RedirectMessage
    {
        public string Xml { get; init; } = "";
        public string? RelayState { get; init; }
        public bool Signed { get; init; }
    }

    internal static RedirectMessage ReadRedirect(string rawQuery, string param, IReadOnlyList<X509Certificate2> certs)
    {
        var query = rawQuery.StartsWith('?') ? rawQuery[1..] : rawQuery;
        var raw = new Dictionary<string, string>();
        foreach (var pair in query.Split('&'))
        {
            if (pair.Length == 0) continue;
            var eq = pair.IndexOf('=');
            var namePart = eq >= 0 ? pair[..eq] : pair;
            var value = eq >= 0 ? pair[(eq + 1)..] : "";
            var name = UriUnescape(namePart);
            if (raw.ContainsKey(name))
                throw new SamlException("binding", "the query string carries " + name + " twice");
            raw[name] = value;
        }
        if (!raw.TryGetValue(param, out var message))
            throw new SamlException("binding", "the query string carries no " + param);
        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(UriUnescape(message));
        }
        catch (Exception ex)
        {
            throw new SamlException("binding", param + " is not a DEFLATE-encoded message", ex);
        }
        byte[] inflated;
        try
        {
            inflated = InflateRaw(decoded);
        }
        catch (SamlException ex) when (ex.Message.Contains("inflates past", StringComparison.Ordinal))
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new SamlException("binding", param + " is not a DEFLATE-encoded message", ex);
        }
        string? relay = null;
        if (raw.TryGetValue("RelayState", out var rawRelay)) relay = UriUnescape(rawRelay);
        if (!raw.ContainsKey("Signature"))
            return new RedirectMessage { Xml = Encoding.UTF8.GetString(inflated), RelayState = relay, Signed = false };
        var sigAlg = raw.TryGetValue("SigAlg", out var rawAlg) ? UriUnescape(rawAlg) : "";
        if (sigAlg != XmlUtil.RsaSha256 && sigAlg != XmlUtil.RsaSha384 && sigAlg != XmlUtil.RsaSha512)
        {
            var shown = sigAlg.Length == 0 ? "(no SigAlg)" : sigAlg;
            throw new SamlException("signature", "the query is signed with " + shown + ", which is refused");
        }
        var hash = sigAlg == XmlUtil.RsaSha512 ? HashAlgorithmName.SHA512 : sigAlg == XmlUtil.RsaSha384 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;
        var signedParts = new List<string> { param + "=" + message };
        if (raw.ContainsKey("RelayState")) signedParts.Add("RelayState=" + raw["RelayState"]);
        signedParts.Add("SigAlg=" + raw["SigAlg"]);
        var data = Encoding.UTF8.GetBytes(string.Join("&", signedParts));
        byte[] sigBytes;
        try
        {
            sigBytes = Convert.FromBase64String(UriUnescape(raw["Signature"]));
        }
        catch (Exception ex)
        {
            throw new SamlException("signature", "the query string signature does not verify against the identity provider's certificate", ex);
        }
        foreach (var cert in certs)
        {
            using var pub = cert.GetRSAPublicKey();
            if (pub != null && pub.VerifyData(data, sigBytes, hash, RSASignaturePadding.Pkcs1))
                return new RedirectMessage { Xml = Encoding.UTF8.GetString(inflated), RelayState = relay, Signed = true };
        }
        throw new SamlException("signature", "the query string signature does not verify against the identity provider's certificate");
    }

    internal static string ReadPost(string value, string param)
    {
        var compact = string.Concat(value.Where(ch => !char.IsWhiteSpace(ch)));
        if (compact.Length == 0 || !B64.IsMatch(compact))
            throw new SamlException("binding", param + " is not base64");
        try
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(compact));
        }
        catch (FormatException)
        {
            throw new SamlException("binding", param + " is not base64");
        }
    }

    internal static string UriEscape(string value)
    {
        var b = new StringBuilder();
        foreach (var c in Encoding.UTF8.GetBytes(value))
        {
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || "-_.!~*'()".Contains((char)c))
                b.Append((char)c);
            else
                b.Append('%').Append(c.ToString("X2"));
        }
        return b.ToString();
    }

    internal static string UriUnescape(string value)
    {
        var text = value.Replace("+", "%20", StringComparison.Ordinal);
        if (BadPercent(text))
            throw new SamlException("binding", "the query string is not validly percent-encoded");
        try
        {
            return Uri.UnescapeDataString(text);
        }
        catch (Exception)
        {
            throw new SamlException("binding", "the query string is not validly percent-encoded");
        }
    }

    static bool BadPercent(string value)
    {
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] != '%') continue;
            if (i + 2 >= value.Length || !IsHex(value[i + 1]) || !IsHex(value[i + 2])) return true;
            i += 2;
        }
        return false;
    }

    static bool IsHex(char c) => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

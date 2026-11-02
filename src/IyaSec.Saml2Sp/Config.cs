// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace IyaSec.Saml;

public sealed class Config
{
    public string EntityId { get; init; } = "";
    public string AcsUrl { get; init; } = "";
    public RSA PrivateKey { get; init; } = null!;
    public string PrivateKeyPem { get; init; } = "";
    public X509Certificate2 Certificate { get; init; } = null!;
    public string CertificatePem { get; init; } = "";
    public string IdpMetadata { get; init; } = "";
    public string RequestBinding { get; init; } = "redirect";
    public string ResponseBinding { get; init; } = "post";
    public long ClockSkewMs { get; init; } = 60000;
    public bool WantAssertionsSigned { get; init; } = true;
    public bool WantAssertionsEncrypted { get; init; }
    public bool AllowUnsolicited { get; init; }
    public bool? Signals { get; init; }
    public string IdpCa { get; init; } = "";
    public string IdpEntityId { get; init; } = "";
    public string NameIdFormat { get; init; } = "";

    public bool Has(string key) => key == "signals" && Signals.HasValue;
}

public static class ConfigFile
{
    static readonly Regex AbsoluteUrl = new(@"^https?://", RegexOptions.Compiled);

    public static Config ResolveConfig(IReadOnlyDictionary<string, object?> config, string? baseDir) => Resolve(config, baseDir);

    public static Config Resolve(IReadOnlyDictionary<string, object?> config, string? baseDir)
    {
        if (config == null) throw new SamlException("config", "the configuration must be an object");
        var basePath = string.IsNullOrEmpty(baseDir) ? Directory.GetCurrentDirectory() : baseDir;
        if (config.TryGetValue("entityId", out var entityRaw) && entityRaw is string entity && entity.Trim().Length > 0)
        {
            var acs = Absolute(config.TryGetValue("acsUrl", out var acsRaw) ? acsRaw : null, "acsUrl");
            if (!config.TryGetValue("privateKey", out var keyRaw) || keyRaw is not string keyText ||
                !config.TryGetValue("certificate", out var certRaw) || certRaw is not string certText)
                throw new SamlException("config", "privateKey and certificate are required: every AuthnRequest is signed");
            var keyPem = Material(keyText, basePath, "privateKey");
            var certPem = Material(certText, basePath, "certificate");
            RSA privateKey;
            X509Certificate2 certificate;
            try
            {
                privateKey = Keys.LoadRsa(keyPem);
                certificate = Keys.LoadCertificate(certPem);
            }
            catch (SamlException ex) when (ex.Message.StartsWith("the private key is ", StringComparison.Ordinal) || ex.Message.Contains("cannot be read", StringComparison.Ordinal))
            {
                throw;
            }
            catch (SamlException ex)
            {
                throw new SamlException("config", "the private key or certificate cannot be read: " + (ex.InnerException?.Message ?? ex.Message), ex);
            }
            if (!Keys.SamePublic(privateKey, certificate))
                throw new SamlException("config", "the certificate is not for the private key");
            if (!config.TryGetValue("idpMetadata", out var metaRaw) || metaRaw is not string idpMeta || idpMeta.Trim().Length == 0)
                throw new SamlException("config", "idpMetadata is required");
            idpMeta = Expand(idpMeta.Trim());
            if (!AbsoluteUrl.IsMatch(idpMeta) && !idpMeta.StartsWith('<'))
            {
                if (!Path.IsPathRooted(idpMeta)) idpMeta = Path.GetFullPath(Path.Combine(basePath, idpMeta));
            }
            double skew = 60;
            if (config.TryGetValue("clockSkewSeconds", out var skewRaw) && skewRaw != null)
            {
                if (!TryNumber(skewRaw, out skew) || skew < 0 || skew > 600)
                    throw new SamlException("config", "clockSkewSeconds must be a number from 0 to 600");
            }
            if (config.ContainsKey("signals"))
            {
                var raw = config["signals"];
                if (raw is not bool)
                    throw new SamlException("config", "signals must be true or false");
            }
            var resolved = new Config
            {
                EntityId = entity,
                AcsUrl = acs,
                PrivateKey = privateKey,
                PrivateKeyPem = privateKey.ExportPkcs8PrivateKeyPem(),
                Certificate = certificate,
                CertificatePem = certificate.ExportCertificatePem(),
                IdpMetadata = idpMeta,
                ClockSkewMs = (long)(int)skew * 1000,
                WantAssertionsSigned = BoolOr(config, "wantAssertionsSigned", true),
                WantAssertionsEncrypted = BoolOr(config, "wantAssertionsEncrypted", false),
                AllowUnsolicited = BoolOr(config, "allowUnsolicited", false),
                RequestBinding = OneOf(config, "requestBinding", new[] { "redirect", "post" }, "redirect"),
                ResponseBinding = OneOf(config, "responseBinding", new[] { "post", "redirect", "artifact" }, "post"),
                Signals = config.TryGetValue("signals", out var sig) && sig is false ? false : null,
                IdpCa = config.TryGetValue("idpCa", out var ca) && ca is string caText && caText.Length > 0 ? Material(caText, basePath, "idpCa") : "",
                IdpEntityId = config.TryGetValue("idpEntityId", out var id) && id is string idText ? idText : "",
                NameIdFormat = config.TryGetValue("nameIdFormat", out var format) && format is string formatText ? formatText : "",
            };
            return resolved;
        }
        throw new SamlException("config", "entityId is required");
    }

    public static Dictionary<string, object?> ParseObject(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
            throw new SamlException("config", "the configuration must be an object");
        return (Dictionary<string, object?>)FromElement(doc.RootElement)!;
    }

    public static Config Read(string path, IReadOnlyDictionary<string, object?>? overrides)
    {
        string raw;
        try
        {
            raw = File.ReadAllText(path);
        }
        catch (Exception ex)
        {
            throw new SamlException("config", path + " cannot be read as JSON: " + ex.Message, ex);
        }
        Dictionary<string, object?> obj;
        try
        {
            using var doc = JsonDocument.Parse(raw);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                throw new SamlException("config", "the configuration must be an object");
            obj = (Dictionary<string, object?>)FromElement(doc.RootElement)!;
        }
        catch (SamlException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new SamlException("config", path + " cannot be read as JSON: " + ex.Message, ex);
        }
        if (overrides != null)
        {
            foreach (var pair in overrides)
                if (pair.Value != null) obj[pair.Key] = pair.Value;
        }
        return Resolve(obj, Path.GetDirectoryName(Path.GetFullPath(path)) ?? "");
    }

    internal static object? FromElement(JsonElement el) => el.ValueKind switch
    {
        JsonValueKind.String => el.GetString(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Number => el.TryGetInt64(out var n) ? n : el.GetDouble(),
        JsonValueKind.Null => null,
        JsonValueKind.Object => el.EnumerateObject().ToDictionary(p => p.Name, p => FromElement(p.Value)),
        JsonValueKind.Array => el.EnumerateArray().Select(FromElement).ToList(),
        _ => null,
    };

    static string Expand(string value)
    {
        var seen = 0;
        while (value.StartsWith("env:", StringComparison.Ordinal) || value.StartsWith("file:", StringComparison.Ordinal))
        {
            seen++;
            if (seen > 4) throw new SamlException("config", "the placeholder " + value + " is nested too deeply");
            if (value.StartsWith("env:", StringComparison.Ordinal))
            {
                var name = value[4..];
                var got = Environment.GetEnvironmentVariable(name);
                if (name.Length == 0 || got == null)
                {
                    var shown = name.Length == 0 ? value : name;
                    throw new SamlException("config", "environment variable " + shown + " is not set");
                }
                value = got;
                continue;
            }
            value = value[5..];
        }
        return value;
    }

    static string Material(string value, string baseDir, string what)
    {
        value = Expand(value);
        if (value.Contains("-----BEGIN ", StringComparison.Ordinal)) return value;
        var path = Path.IsPathRooted(value) ? value : Path.Combine(baseDir, value);
        path = Path.GetFullPath(path);
        try
        {
            return File.ReadAllText(path);
        }
        catch (Exception ex)
        {
            throw new SamlException("config", what + " is neither a PEM nor a readable file (" + path + ")", ex);
        }
    }

    static string Absolute(object? value, string what)
    {
        if (value is not string text || text.Trim().Length == 0)
            throw new SamlException("config", what + " is required");
        if (!AbsoluteUrl.IsMatch(text))
            throw new SamlException("config", what + " must be an absolute http(s) URL, not " + text);
        return text;
    }

    static string OneOf(IReadOnlyDictionary<string, object?> config, string key, string[] allowed, string fallback)
    {
        if (!config.TryGetValue(key, out var value) || value == null || value is "") return fallback;
        if (value is not string text)
            throw new SamlException("config", key + " must be one of " + string.Join(", ", allowed) + ", not " + JsonSerializer.Serialize(value));
        if (allowed.Contains(text)) return text;
        throw new SamlException("config", key + " must be one of " + string.Join(", ", allowed) + ", not " + text);
    }

    static bool BoolOr(IReadOnlyDictionary<string, object?> config, string key, bool fallback)
    {
        if (!config.TryGetValue(key, out var value) || value == null) return fallback;
        return value is bool flag ? flag : fallback;
    }

    static bool TryNumber(object value, out double number)
    {
        switch (value)
        {
            case byte or sbyte or short or ushort or int or uint or long or ulong or float or double or decimal:
                number = Convert.ToDouble(value, CultureInfo.InvariantCulture);
                return !double.IsNaN(number) && !double.IsInfinity(number);
            default:
                number = 0;
                return false;
        }
    }
}

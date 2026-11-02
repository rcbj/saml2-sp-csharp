// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace IyaSec.Saml;

public static class Jws
{
    const string Supported = "RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512";

    readonly struct Spec
    {
        public HashAlgorithmName Hash { get; init; }
        public string Kty { get; init; }
        public bool Pss { get; init; }
        public bool P1363 { get; init; }
        public int Size { get; init; }
    }

    static readonly Dictionary<string, Spec> Algs = new()
    {
        ["RS256"] = new Spec { Hash = HashAlgorithmName.SHA256, Kty = "RSA" },
        ["RS384"] = new Spec { Hash = HashAlgorithmName.SHA384, Kty = "RSA" },
        ["RS512"] = new Spec { Hash = HashAlgorithmName.SHA512, Kty = "RSA" },
        ["PS256"] = new Spec { Hash = HashAlgorithmName.SHA256, Kty = "RSA", Pss = true },
        ["PS384"] = new Spec { Hash = HashAlgorithmName.SHA384, Kty = "RSA", Pss = true },
        ["PS512"] = new Spec { Hash = HashAlgorithmName.SHA512, Kty = "RSA", Pss = true },
        ["ES256"] = new Spec { Hash = HashAlgorithmName.SHA256, Kty = "EC", P1363 = true, Size = 32 },
        ["ES384"] = new Spec { Hash = HashAlgorithmName.SHA384, Kty = "EC", P1363 = true, Size = 48 },
        ["ES512"] = new Spec { Hash = HashAlgorithmName.SHA512, Kty = "EC", P1363 = true, Size = 66 },
    };

    static readonly Regex B64Url = new("^[A-Za-z0-9_-]*$", RegexOptions.Compiled);

    public static (Dictionary<string, object?> Header, Dictionary<string, object?> Payload) VerifyCompact(string token, IReadOnlyList<Dictionary<string, object?>> keys)
    {
        var parts = token.Split('.');
        if (parts.Length != 3) throw new SamlException("signature", "the SET is not a compact JWS");
        var headerRaw = Decode(parts[0], "header");
        var payloadRaw = Decode(parts[1], "payload");
        object? header;
        object? payload;
        try
        {
            header = JsonMaps.Parse(Encoding.UTF8.GetString(headerRaw));
            payload = JsonMaps.Parse(Encoding.UTF8.GetString(payloadRaw));
        }
        catch (SamlException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new SamlException("signature", "the SET's header or payload is not JSON", ex);
        }
        if (header is not Dictionary<string, object?> headerObj || payload is not Dictionary<string, object?> payloadObj)
            throw new SamlException("signature", "the SET's header or payload is not a JSON object");
        var alg = headerObj.TryGetValue("alg", out var algRaw) && algRaw is string algText ? algText : "";
        if (!Algs.TryGetValue(alg, out var spec))
        {
            var shown = alg.Length == 0 ? "(no alg)" : alg;
            throw new SamlException("signature", "the SET is signed with " + shown + ", which this receiver does not verify (" + Supported + ")");
        }
        if (headerObj.ContainsKey("crit"))
            throw new SamlException("signature", "the SET's header has a crit member this receiver does not understand");
        var kid = headerObj.TryGetValue("kid", out var kidRaw) && kidRaw is string kidText ? kidText : "";
        var candidates = new List<Dictionary<string, object?>>();
        foreach (var key in keys)
        {
            if (kid.Length > 0 && Text(key, "kid") != kid) continue;
            if (Text(key, "kty") != spec.Kty) continue;
            var use = Text(key, "use");
            if (use.Length > 0 && use != "sig") continue;
            var keyAlg = Text(key, "alg");
            if (keyAlg.Length > 0 && keyAlg != alg) continue;
            candidates.Add(key);
        }
        if (candidates.Count == 0)
        {
            var which = kid.Length == 0 ? "" : " with kid " + kid;
            throw new SamlException("signature", "the transmitter publishes no " + spec.Kty + " signing key" + which);
        }
        var data = Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]);
        var signature = Decode(parts[2], "signature");
        foreach (var jwk in candidates)
        {
            if (Verify(jwk, spec, data, signature)) return (headerObj, payloadObj);
        }
        throw new SamlException("signature", "the SET's signature does not verify against the transmitter's keys");
    }

    static bool Verify(Dictionary<string, object?> jwk, Spec spec, byte[] data, byte[] signature)
    {
        try
        {
            if (spec.Kty == "RSA")
            {
                using var rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters
                {
                    Modulus = Unpad(Decode(Text(jwk, "n"), "key")),
                    Exponent = Unpad(Decode(Text(jwk, "e"), "key")),
                });
                var padding = spec.Pss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                return rsa.VerifyData(data, signature, spec.Hash, padding);
            }
            if (spec.Kty == "EC")
            {
                var curve = Text(jwk, "crv") switch
                {
                    "P-256" => ECCurve.NamedCurves.nistP256,
                    "P-384" => ECCurve.NamedCurves.nistP384,
                    "P-521" => ECCurve.NamedCurves.nistP521,
                    _ => throw new SamlException("signature", "the transmitter's key " + Text(jwk, "kid") + " cannot be read: unsupported curve"),
                };
                if (signature.Length != spec.Size * 2) return false;
                using var ec = ECDsa.Create(new ECParameters
                {
                    Curve = curve,
                    Q = new ECPoint { X = Fit(Decode(Text(jwk, "x"), "key"), spec.Size), Y = Fit(Decode(Text(jwk, "y"), "key"), spec.Size) },
                });
                return ec.VerifyData(data, signature, spec.Hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            return false;
        }
        catch (SamlException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    static byte[] Decode(string value, string what)
    {
        if (!B64Url.IsMatch(value))
            throw new SamlException("signature", "the SET's " + what + " is not base64url");
        var pad = (4 - value.Length % 4) % 4;
        try
        {
            return Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', pad));
        }
        catch (FormatException)
        {
            throw new SamlException("signature", "the SET's " + what + " is not base64url");
        }
    }

    static byte[] Unpad(byte[] value)
    {
        var start = 0;
        while (start < value.Length - 1 && value[start] == 0) start++;
        if (start == 0) return value;
        return value[start..];
    }

    static byte[] Fit(byte[] value, int size)
    {
        value = Unpad(value);
        if (value.Length == size) return value;
        if (value.Length > size) return value[^size..];
        var padded = new byte[size];
        Buffer.BlockCopy(value, 0, padded, size - value.Length, value.Length);
        return padded;
    }

    static string Text(Dictionary<string, object?> obj, string key) =>
        obj.TryGetValue(key, out var value) && value is string text ? text : "";
}

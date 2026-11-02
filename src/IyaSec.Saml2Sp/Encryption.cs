// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Xml;

namespace IyaSec.Saml;

static class Encryption
{
    const string OaepMgf1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
    const string Oaep11 = "http://www.w3.org/2009/xmlenc11#rsa-oaep";

    static readonly Dictionary<string, (string Name, bool Gcm, int KeyLen)> Ciphers = new()
    {
        ["http://www.w3.org/2009/xmlenc11#aes128-gcm"] = ("aes-128-gcm", true, 16),
        ["http://www.w3.org/2009/xmlenc11#aes192-gcm"] = ("aes-192-gcm", true, 24),
        ["http://www.w3.org/2009/xmlenc11#aes256-gcm"] = ("aes-256-gcm", true, 32),
        ["http://www.w3.org/2001/04/xmlenc#aes128-cbc"] = ("aes-128-cbc", false, 16),
        ["http://www.w3.org/2001/04/xmlenc#aes192-cbc"] = ("aes-192-cbc", false, 24),
        ["http://www.w3.org/2001/04/xmlenc#aes256-cbc"] = ("aes-256-cbc", false, 32),
    };

    static readonly Dictionary<string, string> Digests = new()
    {
        ["http://www.w3.org/2000/09/xmldsig#sha1"] = "sha1",
        ["http://www.w3.org/2001/04/xmlenc#sha256"] = "sha256",
        ["http://www.w3.org/2001/04/xmldsig-more#sha384"] = "sha384",
        ["http://www.w3.org/2001/04/xmlenc#sha512"] = "sha512",
    };

    static readonly Dictionary<string, string> Mgfs = new()
    {
        ["http://www.w3.org/2009/xmlenc11#mgf1sha1"] = "sha1",
        ["http://www.w3.org/2009/xmlenc11#mgf1sha256"] = "sha256",
        ["http://www.w3.org/2009/xmlenc11#mgf1sha384"] = "sha384",
        ["http://www.w3.org/2009/xmlenc11#mgf1sha512"] = "sha512",
    };

    internal static string DecryptElement(XmlElement encrypted, RSA key)
    {
        var data = XmlUtil.One(encrypted, XmlUtil.NsXenc, "EncryptedData") ?? throw Fail("<" + encrypted.LocalName + "> has no EncryptedData");
        var method = XmlUtil.One(data, XmlUtil.NsXenc, "EncryptionMethod");
        var alg = method == null ? "" : XmlUtil.AttrOr(method, "Algorithm");
        if (!Ciphers.TryGetValue(alg, out var spec))
            throw Fail("the content is encrypted with " + OrNone(alg) + ", which is not supported");
        var keys = XmlUtil.Descendants(encrypted, XmlUtil.NsXenc, "EncryptedKey");
        if (keys.Count == 0) throw Fail("<" + encrypted.LocalName + "> carries no EncryptedKey");
        var contentKey = Unwrap(keys[0], key);
        if (contentKey.Length != spec.KeyLen)
            throw Fail("the content key is " + contentKey.Length + " bytes; " + spec.Name + " needs " + spec.KeyLen);
        var cipherData = XmlUtil.One(data, XmlUtil.NsXenc, "CipherData");
        var cipherValue = cipherData == null ? null : XmlUtil.One(cipherData, XmlUtil.NsXenc, "CipherValue");
        byte[] blob;
        try
        {
            blob = Convert.FromBase64String(string.Concat(XmlUtil.TextOf(cipherValue).Where(ch => !char.IsWhiteSpace(ch))));
        }
        catch (Exception ex)
        {
            throw Fail("the content could not be decrypted", ex);
        }
        if (spec.Gcm)
        {
            if (blob.Length < 12 + 16) throw Fail("the ciphertext is too short");
            try
            {
                var plain = new byte[blob.Length - 12 - 16];
                using var aes = new AesGcm(contentKey, 16);
                aes.Decrypt(blob.AsSpan(0, 12), blob.AsSpan(12, plain.Length), blob.AsSpan(blob.Length - 16), plain);
                return System.Text.Encoding.UTF8.GetString(plain);
            }
            catch (SamlException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw Fail("the content could not be decrypted", ex);
            }
        }
        if (blob.Length < 32 || blob.Length % 16 != 0)
            throw Fail("the ciphertext is not a whole number of blocks");
        try
        {
            using var aes = Aes.Create();
            aes.Key = contentKey;
            aes.IV = blob[..16];
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            using var decryptor = aes.CreateDecryptor();
            var plain = decryptor.TransformFinalBlock(blob, 16, blob.Length - 16);
            if (plain.Length == 0) throw Fail("the decrypted content is not padded as XML Encryption pads it");
            var pad = plain[^1];
            if (pad < 1 || pad > 16 || pad > plain.Length) throw Fail("the decrypted content is not padded as XML Encryption pads it");
            for (var i = plain.Length - pad; i < plain.Length; i++)
                if (plain[i] != pad) throw Fail("the decrypted content is not padded as XML Encryption pads it");
            return System.Text.Encoding.UTF8.GetString(plain, 0, plain.Length - pad);
        }
        catch (SamlException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw Fail("the content could not be decrypted", ex);
        }
    }

    static byte[] Unwrap(XmlElement encryptedKey, RSA key)
    {
        var method = XmlUtil.One(encryptedKey, XmlUtil.NsXenc, "EncryptionMethod");
        var alg = method == null ? "" : XmlUtil.AttrOr(method, "Algorithm");
        if (alg != OaepMgf1P && alg != Oaep11)
            throw Fail("the content key is wrapped with " + OrNone(alg) + "; only RSA-OAEP is accepted");
        var digest = "sha1";
        if (method != null)
        {
            var digestMethod = XmlUtil.One(method, XmlUtil.NsDsig, "DigestMethod");
            if (digestMethod != null)
            {
                var digestAlg = XmlUtil.AttrOr(digestMethod, "Algorithm");
                if (!Digests.TryGetValue(digestAlg, out var found))
                    throw Fail("the OAEP digest " + digestAlg + " is not supported");
                digest = found!;
            }
        }
        var mgf = "sha1";
        if (alg == Oaep11 && method != null)
        {
            var mgfEl = XmlUtil.One(method, XmlUtil.NsXenc11, "MGF");
            if (mgfEl != null && XmlUtil.AttrOr(mgfEl, "Algorithm").Length > 0)
            {
                var mgfAlg = XmlUtil.AttrOr(mgfEl, "Algorithm");
                if (!Mgfs.TryGetValue(mgfAlg, out var found))
                    throw Fail("the OAEP mask generation function " + mgfAlg + " is not supported");
                mgf = found!;
            }
        }
        if (mgf != digest)
            throw Fail("OAEP with digest " + digest + " and MGF1 " + mgf + " is not supported; one hash is used for both");
        var values = XmlUtil.Descendants(encryptedKey, XmlUtil.NsXenc, "CipherValue");
        var raw = values.Count > 0 ? XmlUtil.TextOf(values[0]) : "";
        byte[] blob;
        try
        {
            blob = Convert.FromBase64String(string.Concat(raw.Where(ch => !char.IsWhiteSpace(ch))));
        }
        catch (Exception ex)
        {
            throw Fail("the content key could not be unwrapped with this service provider's key", ex);
        }
        try
        {
            var padding = digest == "sha256" ? RSAEncryptionPadding.OaepSHA256
                : digest == "sha384" ? RSAEncryptionPadding.OaepSHA384
                : digest == "sha512" ? RSAEncryptionPadding.OaepSHA512
                : RSAEncryptionPadding.OaepSHA1;
            return key.Decrypt(blob, padding);
        }
        catch (Exception ex)
        {
            throw Fail("the content key could not be unwrapped with this service provider's key", ex);
        }
    }

    static SamlException Fail(string message, Exception? cause = null) => new("decryption", message, cause);
    static string OrNone(string value) => value.Length == 0 ? "(none)" : value;
}

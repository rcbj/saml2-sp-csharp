// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace IyaSec.Saml;

static class Canon
{
    static readonly Dictionary<string, HashAlgorithmName> SignatureAlgs = new()
    {
        [XmlUtil.RsaSha256] = HashAlgorithmName.SHA256,
        [XmlUtil.RsaSha384] = HashAlgorithmName.SHA384,
        [XmlUtil.RsaSha512] = HashAlgorithmName.SHA512,
    };

    static readonly Dictionary<string, HashAlgorithmName> DigestAlgs = new()
    {
        [SignedXml.XmlDsigSHA256Url] = HashAlgorithmName.SHA256,
        [SignedXml.XmlDsigSHA384Url] = HashAlgorithmName.SHA384,
        [SignedXml.XmlDsigSHA512Url] = HashAlgorithmName.SHA512,
    };

    internal static string SignEnveloped(string xml, string elementId, RSA key, X509Certificate2 cert)
    {
        var root = XmlUtil.Parse(xml, "the message to sign");
        var target = XmlUtil.ElementById(root, elementId) ?? throw new SamlException("signature", "no element has ID " + elementId);
        var digest = Convert.ToBase64String(Hash(HashAlgorithmName.SHA256, Exclusive(target)));
        var signature = SignatureElement(root.OwnerDocument!, elementId, digest, cert);
        InsertAfterIssuer(target, signature);
        var signedInfo = XmlUtil.Children(signature, XmlUtil.NsDsig, "SignedInfo")[0];
        var value = key.SignData(Exclusive(signedInfo), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        XmlUtil.Children(signature, XmlUtil.NsDsig, "SignatureValue")[0].InnerText = Convert.ToBase64String(value);
        return root.OuterXml;
    }

    internal static string? VerifySigned(XmlElement element, IReadOnlyList<X509Certificate2> certs, string what)
    {
        var signatures = XmlUtil.Children(element, XmlUtil.NsDsig, "Signature");
        if (signatures.Count > 1)
            throw new SamlException("validation", "<" + element.LocalName + "> has more than one <Signature>");
        if (signatures.Count == 0) return null;
        var signature = signatures[0];
        var elementId = XmlUtil.AttrOr(element, "ID");
        if (elementId.Length == 0)
            throw new SamlException("signature", what + " is signed but has no ID for the signature to refer to");
        var signedInfo = XmlUtil.One(signature, XmlUtil.NsDsig, "SignedInfo") ?? throw new SamlException("signature", what + "'s signature has no SignedInfo");
        var c14n = AlgorithmOf(signedInfo, "CanonicalizationMethod");
        if (!AllowedC14N(c14n))
            throw new SamlException("signature", what + "'s signature uses the canonicalization " + OrNone(c14n) + ", which is refused");
        var sigAlg = AlgorithmOf(signedInfo, "SignatureMethod");
        if (!SignatureAlgs.TryGetValue(sigAlg, out var hash))
            throw new SamlException("signature", what + "'s signature uses " + OrNone(sigAlg) + ", which is refused (SHA-1 and non-RSA algorithms are not accepted)");
        var refs = XmlUtil.Children(signedInfo, XmlUtil.NsDsig, "Reference");
        if (refs.Count != 1)
            throw new SamlException("signature", what + "'s signature has " + refs.Count + " references; exactly one is accepted");
        var reference = refs[0];
        var uri = XmlUtil.AttrOr(reference, "URI");
        if (uri != "#" + elementId)
            throw new SamlException("signature", what + "'s signature refers to " + OrNothing(uri) + ", not to " + what + " itself (#" + elementId + ")");
        var digestAlg = AlgorithmOf(reference, "DigestMethod");
        if (!DigestAlgs.TryGetValue(digestAlg, out var digestHash))
            throw new SamlException("signature", what + "'s signature digests with " + OrNone(digestAlg) + ", which is refused");
        var transforms = new List<XmlElement>();
        var transformsEl = XmlUtil.One(reference, XmlUtil.NsDsig, "Transforms");
        if (transformsEl != null) transforms = XmlUtil.Children(transformsEl, XmlUtil.NsDsig, "Transform");
        foreach (var transform in transforms)
        {
            var alg = XmlUtil.AttrOr(transform, "Algorithm");
            if (alg != SignedXml.XmlDsigEnvelopedSignatureTransformUrl && !AllowedC14N(alg))
                throw new SamlException("signature", what + "'s signature uses the transform " + OrNone(alg) + ", which is refused");
        }
        if (certs.Count == 0)
            throw new SamlException("signature", "no signing certificate is known for the identity provider, so " + what + " cannot be verified");
        var signedBytes = Canonicalize(signedInfo, c14n, Inclusive(XmlUtil.One(signedInfo, XmlUtil.NsDsig, "CanonicalizationMethod")));
        var signatureValue = XmlUtil.One(signature, XmlUtil.NsDsig, "SignatureValue");
        byte[] sigBytes;
        try
        {
            sigBytes = Convert.FromBase64String(Compact(signatureValue));
        }
        catch (FormatException ex)
        {
            throw new SamlException("signature", what + "'s signature does not verify against the identity provider's certificate: the signature value is not base64", ex);
        }
        var verified = false;
        foreach (var cert in certs)
        {
            using var pub = cert.GetRSAPublicKey();
            if (pub == null) continue;
            if (pub.VerifyData(signedBytes, sigBytes, hash, RSASignaturePadding.Pkcs1))
            {
                verified = true;
                break;
            }
        }
        if (!verified)
            throw new SamlException("signature", what + "'s signature does not verify against the identity provider's certificate: the signature does not verify");
        signature.ParentNode!.RemoveChild(signature);
        byte[] referenceBytes;
        try
        {
            referenceBytes = Apply(element, transforms);
        }
        catch (SamlException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new SamlException("signature", what + "'s signature does not verify against the identity provider's certificate: the signature does not verify", ex);
        }
        var digestValue = XmlUtil.One(reference, XmlUtil.NsDsig, "DigestValue");
        byte[] got;
        try
        {
            got = Convert.FromBase64String(Compact(digestValue));
        }
        catch (FormatException ex)
        {
            throw new SamlException("signature", what + "'s signature does not verify against the identity provider's certificate: the digest is not base64", ex);
        }
        var want = Hash(digestHash, referenceBytes);
        if (!got.AsSpan().SequenceEqual(want))
            throw new SamlException("signature", what + "'s signature does not verify against the identity provider's certificate: the signature does not verify");
        return EncodingOf(Canonicalize(element, SignedXml.XmlDsigExcC14NTransformUrl, ""));
    }

    static byte[] Apply(XmlElement element, List<XmlElement> transforms)
    {
        if (transforms.Count == 0) return Canonicalize(element, SignedXml.XmlDsigC14NTransformUrl, "");
        XmlElement node = element;
        byte[]? data = null;
        for (var index = 0; index < transforms.Count; index++)
        {
            var alg = XmlUtil.AttrOr(transforms[index], "Algorithm");
            if (data != null)
            {
                node = XmlUtil.Parse(EncodingOf(data), "the transformed reference");
                data = null;
            }
            if (alg == SignedXml.XmlDsigEnvelopedSignatureTransformUrl)
            {
                foreach (var sig in XmlUtil.Children(node, XmlUtil.NsDsig, "Signature").ToList())
                    sig.ParentNode!.RemoveChild(sig);
                continue;
            }
            if (AllowedC14N(alg))
            {
                data = Canonicalize(node, alg, Inclusive(transforms[index]));
                if (index == transforms.Count - 1) return data;
            }
            else
            {
                throw new SamlException("signature", "the signature uses the transform " + OrNone(alg) + ", which is refused");
            }
        }
        return data ?? Canonicalize(node, SignedXml.XmlDsigC14NTransformUrl, "");
    }

    static byte[] Exclusive(XmlElement element) => Canonicalize(element, SignedXml.XmlDsigExcC14NTransformUrl, "");

    static byte[] Canonicalize(XmlElement element, string algorithm, string prefixList)
    {
        Transform transform = algorithm switch
        {
            SignedXml.XmlDsigExcC14NTransformUrl => prefixList.Length == 0 ? new XmlDsigExcC14NTransform() : new XmlDsigExcC14NTransform(prefixList),
            SignedXml.XmlDsigExcC14NWithCommentsTransformUrl => prefixList.Length == 0 ? new XmlDsigExcC14NWithCommentsTransform() : new XmlDsigExcC14NWithCommentsTransform(prefixList),
            SignedXml.XmlDsigC14NTransformUrl => new XmlDsigC14NTransform(),
            SignedXml.XmlDsigC14NWithCommentsTransformUrl => new XmlDsigC14NWithCommentsTransform(),
            _ => throw new SamlException("signature", "the signature uses the canonicalization " + OrNone(algorithm) + ", which is refused"),
        };
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(element.OuterXml);
        transform.LoadInput(doc);
        using var stream = (Stream)transform.GetOutput()!;
        if (stream.CanSeek) stream.Position = 0;
        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
    }

    static byte[] Hash(HashAlgorithmName name, byte[] data) => name.Name switch
    {
        "SHA384" => SHA384.HashData(data),
        "SHA512" => SHA512.HashData(data),
        _ => SHA256.HashData(data),
    };

    static bool AllowedC14N(string alg) =>
        alg is SignedXml.XmlDsigExcC14NTransformUrl or SignedXml.XmlDsigExcC14NWithCommentsTransformUrl
            or SignedXml.XmlDsigC14NTransformUrl or SignedXml.XmlDsigC14NWithCommentsTransformUrl;

    static string AlgorithmOf(XmlElement parent, string local)
    {
        var found = XmlUtil.One(parent, XmlUtil.NsDsig, local);
        return found == null ? "" : XmlUtil.AttrOr(found, "Algorithm");
    }

    static string Inclusive(XmlElement? transform)
    {
        if (transform == null) return "";
        foreach (XmlNode child in transform.ChildNodes)
            if (child is XmlElement el && el.LocalName == "InclusiveNamespaces")
                return XmlUtil.AttrOr(el, "PrefixList");
        return "";
    }

    static string Compact(XmlNode? el) => el == null ? "" : string.Join("", el.InnerText.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    static string EncodingOf(byte[] data) => System.Text.Encoding.UTF8.GetString(data);

    static string OrNone(string value) => value.Length == 0 ? "(none)" : value;
    static string OrNothing(string value) => value.Length == 0 ? "(nothing)" : value;

    static XmlElement SignatureElement(XmlDocument doc, string elementId, string digest, X509Certificate2 cert)
    {
        var xml = "<ds:Signature xmlns:ds=\"" + SignedXml.XmlDsigNamespaceUrl + "\"><ds:SignedInfo xmlns:ds=\"" + SignedXml.XmlDsigNamespaceUrl + "\">" +
                  "<ds:CanonicalizationMethod Algorithm=\"" + SignedXml.XmlDsigExcC14NTransformUrl + "\"></ds:CanonicalizationMethod>" +
                  "<ds:SignatureMethod Algorithm=\"" + SignedXml.XmlDsigRSASHA256Url + "\"></ds:SignatureMethod>" +
                  "<ds:Reference URI=\"#" + elementId + "\"><ds:Transforms>" +
                  "<ds:Transform Algorithm=\"" + SignedXml.XmlDsigEnvelopedSignatureTransformUrl + "\"></ds:Transform>" +
                  "<ds:Transform Algorithm=\"" + SignedXml.XmlDsigExcC14NTransformUrl + "\"></ds:Transform></ds:Transforms>" +
                  "<ds:DigestMethod Algorithm=\"" + SignedXml.XmlDsigSHA256Url + "\"></ds:DigestMethod>" +
                  "<ds:DigestValue>" + digest + "</ds:DigestValue></ds:Reference></ds:SignedInfo>" +
                  "<ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>" +
                  Keys.CertBody(cert) + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>";
        var holder = new XmlDocument { PreserveWhitespace = true };
        holder.LoadXml(xml);
        return (XmlElement)doc.ImportNode(holder.DocumentElement!, true);
    }

    static void InsertAfterIssuer(XmlElement target, XmlNode signature)
    {
        foreach (XmlNode child in target.ChildNodes)
        {
            if (!XmlUtil.Same(child, XmlUtil.NsSaml, "Issuer")) continue;
            target.InsertAfter(signature, child);
            return;
        }
        target.PrependChild(signature);
    }
}

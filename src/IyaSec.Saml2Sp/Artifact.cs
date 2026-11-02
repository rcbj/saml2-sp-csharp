// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace IyaSec.Saml;

static class Artifact
{
    internal readonly struct Parsed
    {
        public int EndpointIndex { get; init; }
        public byte[] SourceId { get; init; }
    }

    internal static Parsed Parse(string samlArt)
    {
        byte[] raw;
        try
        {
            raw = Convert.FromBase64String(string.Concat(samlArt.Where(ch => !char.IsWhiteSpace(ch))));
        }
        catch (FormatException)
        {
            throw Bad();
        }
        if (raw.Length != 44 || (raw[0] << 8 | raw[1]) != 0x0004) throw Bad();
        var source = new byte[20];
        Buffer.BlockCopy(raw, 4, source, 0, 20);
        return new Parsed { EndpointIndex = raw[2] << 8 | raw[3], SourceId = source };
    }

    internal static (string Xml, XmlElement Response) Resolve(string artifact, string entityId, string idpEntityId, IReadOnlyDictionary<int, string> services, string firstArs, IReadOnlyList<X509Certificate2> certs, RSA key, X509Certificate2 certificate, TlsOptions? tls)
    {
        var parsed = Parse(artifact);
        var sum = SHA1.HashData(System.Text.Encoding.UTF8.GetBytes(idpEntityId));
        if (!parsed.SourceId.AsSpan().SequenceEqual(sum))
            throw new SamlException("artifact", "the artifact was not issued by " + idpEntityId);
        if (!services.TryGetValue(parsed.EndpointIndex, out var location) && parsed.EndpointIndex == 0 && services.Count > 0)
            location = firstArs;
        if (string.IsNullOrEmpty(location))
            throw new SamlException("artifact", "the identity provider's metadata has no SOAP ArtifactResolutionService with index " + parsed.EndpointIndex);
        var elementId = Ids.New();
        var unsigned = "<samlp:ArtifactResolve xmlns:samlp=\"" + XmlUtil.NsSamlp + "\" xmlns:saml=\"" + XmlUtil.NsSaml + "\" ID=\"" + elementId + "\" Version=\"2.0\" IssueInstant=\"" + Ids.Iso(default) + "\" Destination=\"" + XmlUtil.Escape(location) + "\"><saml:Issuer>" + XmlUtil.Escape(entityId) + "</saml:Issuer><samlp:Artifact>" + XmlUtil.Escape(artifact) + "</samlp:Artifact></samlp:ArtifactResolve>";
        var signed = Canon.SignEnveloped(unsigned, elementId, key, certificate);
        var envelope = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><soap:Envelope xmlns:soap=\"" + XmlUtil.NsSoap + "\"><soap:Body>" + signed + "</soap:Body></soap:Envelope>";
        var answer = HttpSend.Send(location, "POST", new Dictionary<string, string>
        {
            ["content-type"] = "text/xml; charset=utf-8",
            ["soapaction"] = "\"http://www.oasis-open.org/committees/security\"",
            ["accept"] = "text/xml",
        }, envelope, tls, "artifact");
        if (answer.Status != 200)
            throw new SamlException("artifact", "the artifact resolution service answered HTTP " + answer.Status);
        var root = XmlUtil.Parse(answer.Body, "the ArtifactResponse");
        XmlUtil.AssertUniqueIds(root);
        XmlElement? body = null;
        if (XmlUtil.Same(root, XmlUtil.NsSoap, "Envelope"))
            body = XmlUtil.One(root, XmlUtil.NsSoap, "Body");
        XmlElement? artifactResponse = null;
        if (body != null) artifactResponse = XmlUtil.One(body, XmlUtil.NsSamlp, "ArtifactResponse");
        if (artifactResponse == null)
            throw new SamlException("artifact", "the artifact resolution service did not answer with a SOAP ArtifactResponse");
        var xml = answer.Body;
        var signedResponse = Canon.VerifySigned(artifactResponse, certs, "the ArtifactResponse");
        if (signedResponse != null)
        {
            xml = signedResponse;
            artifactResponse = XmlUtil.Parse(signedResponse, "the signed ArtifactResponse");
        }
        if (XmlUtil.AttrOr(artifactResponse, "InResponseTo") != elementId)
            throw new SamlException("artifact", "the ArtifactResponse does not answer this ArtifactResolve");
        var issuer = XmlUtil.One(artifactResponse, XmlUtil.NsSaml, "Issuer");
        if (issuer != null && XmlUtil.TextOf(issuer) != idpEntityId)
            throw new SamlException("artifact", "the ArtifactResponse was issued by " + XmlUtil.TextOf(issuer));
        var status = XmlUtil.One(artifactResponse, XmlUtil.NsSamlp, "Status");
        var code = "";
        if (status != null)
        {
            var codeEl = XmlUtil.One(status, XmlUtil.NsSamlp, "StatusCode");
            code = codeEl != null ? XmlUtil.AttrOr(codeEl, "Value") : XmlUtil.AttrOr(status, "Value");
        }
        if (code != XmlUtil.StatusSuccess)
        {
            var shown = code.Length == 0 ? "no status" : code;
            throw new SamlException("artifact", "the artifact resolution failed: " + shown);
        }
        var responses = XmlUtil.Children(artifactResponse, XmlUtil.NsSamlp, "Response");
        if (responses.Count == 0)
            throw new SamlException("artifact", "the identity provider did not resolve the artifact (unknown, expired, or already used)");
        return (xml, responses[0]);
    }

    static SamlException Bad() => new("artifact", "SAMLart is not a SAML 2.0 type 0x0004 artifact");
}

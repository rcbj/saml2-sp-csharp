// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using IyaSec.Saml;

namespace IyaSec.Saml2Sp.Tests;

public class SpTests
{
    [Fact]
    public void RefusesAConfigurationWithoutAKeyOrWithAnotherCertificate()
    {
        var bad = World.TestConfig();
        bad["privateKey"] = null;
        World.Rejects(() => ServiceProvider.Create(bad, "", null), "config", "privateKey");
        World.Rejects(() => ServiceProvider.Create(World.TestConfig(new Dictionary<string, object?> { ["certificate"] = World.Idp.CertificatePem }), "", null), "config", "not for the private key");
    }

    [Fact]
    public void ReadsTheIdentityProviderFromItsMetadata()
    {
        var sp = World.MustSp();
        Assert.Equal(World.IdpEntity, sp.Idp.EntityId);
        Assert.Equal(World.SsoUrl, sp.Idp.Sso["redirect"]);
        Assert.Single(sp.Idp.Certs);
    }

    [Fact]
    public void WritesMetadataWithASignedRequestsKeyAndTheAcsOnAllThreeBindings()
    {
        var sp = World.MustSp();
        var xml = sp.Metadata();
        var root = XmlUtil.Parse(xml, "metadata");
        var bindings = new List<string>();
        foreach (var item in XmlUtil.Descendants(root, XmlUtil.NsMd, "AssertionConsumerService"))
        {
            var binding = XmlUtil.AttrOr(item, "Binding");
            bindings.Add(binding[(binding.LastIndexOf(':') + 1)..]);
            Assert.Equal(World.AcsUrl, XmlUtil.AttrOr(item, "Location"));
        }
        Assert.Equal("HTTP-POST,HTTP-Redirect,HTTP-Artifact", string.Join(",", bindings));
        Assert.Matches("AuthnRequestsSigned=\"true\"", xml);
        Assert.Matches("<md:KeyDescriptor use=\"encryption\">[\\s\\S]*xmlenc11#aes256-gcm[\\s\\S]*</md:KeyDescriptor>", xml);
    }

    [Fact]
    public void OmitsSignalsUnlessItIsFalse()
    {
        var sp = World.MustSp();
        Assert.False(sp.Config.Has("signals"));
        Assert.Equal(World.SpEntity, sp.Config.EntityId);
        Assert.Equal(World.AcsUrl, sp.Config.AcsUrl);
        Assert.Equal("redirect", sp.Config.RequestBinding);
        Assert.Equal("post", sp.Config.ResponseBinding);
        var explicitTrue = World.MustSp(new Dictionary<string, object?> { ["signals"] = true });
        Assert.False(explicitTrue.Config.Has("signals"));
        Assert.Equal(sp.Config.EntityId, explicitTrue.Config.EntityId);
        Assert.Equal(sp.Config.AcsUrl, explicitTrue.Config.AcsUrl);
    }

    [Fact]
    public void RecordsSignalsFalseAndStillResolvesTheSamlFields()
    {
        var sp = World.MustSp(new Dictionary<string, object?> { ["signals"] = false, ["wantAssertionsEncrypted"] = true });
        Assert.True(sp.Config.Signals.HasValue);
        Assert.False(sp.Config.Signals!.Value);
        Assert.Equal(World.SpEntity, sp.Config.EntityId);
        Assert.Equal(World.AcsUrl, sp.Config.AcsUrl);
        Assert.Equal("redirect", sp.Config.RequestBinding);
        Assert.Equal("post", sp.Config.ResponseBinding);
        Assert.True(sp.Config.WantAssertionsSigned);
        Assert.True(sp.Config.WantAssertionsEncrypted);
        Assert.False(sp.Config.AllowUnsolicited);
        Assert.Equal(60000, sp.Config.ClockSkewMs);
        Assert.Equal(World.IdpEntity, sp.Idp.EntityId);
    }

    [Fact]
    public void RefusesASignalsValueThatIsNotTrueOrFalse()
    {
        World.Rejects(() => ServiceProvider.Create(World.TestConfig(new Dictionary<string, object?> { ["signals"] = "no" }), "", null), "config", "^signals must be true or false$");
        World.Rejects(() => ServiceProvider.Create(World.TestConfig(new Dictionary<string, object?> { ["signals"] = null }), "", null), "config", "^signals must be true or false$");
    }

    [Fact]
    public void RedirectAuthnRequestIsDeflatedAndSigned()
    {
        var sp = World.MustSp();
        var req = sp.Login(new LoginOptions { RelayState = "/home" });
        Assert.Equal("redirect", req.Binding);
        Assert.StartsWith(World.SsoUrl + "?", req.Url);
        var raw = req.Url.Split('?', 2)[1];
        var parts = raw.Split(new[] { "&Signature=" }, 2, StringSplitOptions.None);
        var sig = Convert.FromBase64String(Bindings.UriUnescape(parts[1]));
        Assert.True(sp.Config.PrivateKey.VerifyData(Encoding.UTF8.GetBytes(parts[0]), sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        var query = Query(raw);
        var xml = Encoding.UTF8.GetString(Bindings.InflateRaw(Convert.FromBase64String(query["SAMLRequest"])));
        Assert.Contains("ID=\"" + req.Id + "\"", xml);
        Assert.Contains("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"", xml);
        Assert.Contains("Destination=\"" + World.SsoUrl + "\"", xml);
        Assert.Equal("/home", query["RelayState"]);
    }

    [Fact]
    public void PostAuthnRequestIsAnEnvelopedSignatureInAForm()
    {
        var sp = World.MustSp(new Dictionary<string, object?> { ["requestBinding"] = "post" });
        var req = sp.Login(new LoginOptions { ResponseBinding = "artifact", Nonce = "abc" });
        Assert.Equal("post", req.Binding);
        var xml = Encoding.UTF8.GetString(Convert.FromBase64String(req.Fields!["SAMLRequest"]));
        Assert.Matches("<saml:Issuer>[^<]+</saml:Issuer><ds:Signature", xml);
        Assert.Contains("HTTP-Artifact", xml);
        var root = XmlUtil.Parse(xml, "the AuthnRequest");
        Assert.True(World.VerifyOk(root, sp.Config.Certificate));
        Assert.Matches("<script nonce=\"abc\">", req.Html);
        Assert.Matches("<button type=\"submit\">", req.Html);
    }

    [Fact]
    public void SubjectHintFollowsTheIssuerAndItsSignature()
    {
        var sp = World.MustSp(new Dictionary<string, object?> { ["requestBinding"] = "post" });
        var req = sp.Login(new LoginOptions { SubjectHint = "alice<&>", SubjectHintFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", ForceAuthn = true });
        var xml = Encoding.UTF8.GetString(Convert.FromBase64String(req.Fields!["SAMLRequest"]));
        Assert.Matches("</ds:Signature><saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">alice&lt;&amp;&gt;</saml:NameID></saml:Subject><samlp:NameIDPolicy", xml);
        Assert.Contains("ForceAuthn=\"true\"", xml);
        Assert.True(World.VerifyOk(XmlUtil.Parse(xml, "the AuthnRequest"), sp.Config.Certificate));
        var plain = sp.Login(new LoginOptions());
        Assert.DoesNotContain("<saml:Subject>", plain.Xml);
    }

    [Fact]
    public void RefusesARelayStateOver80Bytes()
    {
        var sp = World.MustSp();
        var ex = Assert.Throws<SamlException>(() => sp.Login(new LoginOptions { RelayState = new string('x', 81) }));
        Assert.Contains("80 bytes", ex.Message);
    }

    [Fact]
    public void SignedResponseAndSignedAssertion()
    {
        var sp = World.MustSp();
        var who = World.PostAcs(sp, World.ResponseXml(inResponseTo: "_req1", sign: true), "_req1", "/home");
        Assert.Equal("alice-1234", who.NameId);
        Assert.Equal("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", who.NameIdFormat);
        Assert.Equal("_session1", who.SessionIndex);
        Assert.Equal("/home", who.RelayState);
        Assert.Equal("post", who.Binding);
        Assert.Equal("staff,admins", string.Join(",", who.Attributes["groups"]));
        const string mail = "urn:oid:0.9.2342.19200300.100.1.3";
        Assert.Equal("alice@example.com", string.Join(",", who.Attributes[mail]));
        Assert.Equal("mail", who.AttributeFriendlyNames[mail]);
        Assert.Equal("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", who.AuthnContextClassRef);
    }

    [Fact]
    public void AcceptsASignedAssertionInAnUnsignedResponse()
    {
        var sp = World.MustSp();
        var who = World.PostAcs(sp, World.ResponseXml(inResponseTo: "_req1"), "_req1", null);
        Assert.Equal("alice-1234", who.NameId);
    }

    [Fact]
    public void RefusesAnUnsignedAssertionByDefault()
    {
        var sp = World.MustSp();
        var raw = World.AssertionXml(inResponseTo: "_r").Xml;
        var xml = World.ResponseXml(inResponseTo: "_r", sign: true, assertion: raw, hasAssertion: true);
        World.Rejects(() => World.PostAcs(sp, xml, "_r", null), "validation", "not signed");
        var lax = World.MustSp(new Dictionary<string, object?> { ["wantAssertionsSigned"] = false });
        var who = World.PostAcs(lax, xml, "_r", null);
        Assert.Equal("alice-1234", who.NameId);
    }

    [Fact]
    public void RefusesAResponseWithNothingSigned()
    {
        var sp = World.MustSp(new Dictionary<string, object?> { ["wantAssertionsSigned"] = false });
        var raw = World.AssertionXml(inResponseTo: "_r").Xml;
        var xml = World.ResponseXml(inResponseTo: "_r", assertion: raw, hasAssertion: true);
        World.Rejects(() => World.PostAcs(sp, xml, "_r", null), "validation", "neither");
    }

    [Fact]
    public void RefusesAnAssertionAlteredAfterItWasSigned()
    {
        var sp = World.MustSp();
        var xml = World.ResponseXml(inResponseTo: "_r").Replace("alice-1234", "mallory", StringComparison.Ordinal);
        World.Rejects(() => World.PostAcs(sp, xml, "_r", null), "signature", "");
    }

    [Fact]
    public void RefusesASignatureByAnotherKey()
    {
        var sp = World.MustSp();
        var (raw, id) = World.AssertionXml(inResponseTo: "_r");
        var signed = World.SignXml(raw, id, World.Sp.PrivateKey, World.Sp.Certificate);
        var xml = World.ResponseXml(inResponseTo: "_r", assertion: signed, hasAssertion: true);
        World.Rejects(() => World.PostAcs(sp, xml, "_r", null), "signature", "does not verify");
    }

    [Fact]
    public void IsNotFooledBySignatureWrapping()
    {
        var sp = World.MustSp();
        var (signed, id) = World.SignedAssertion(inResponseTo: "_r");
        var forged = World.AssertionXml(inResponseTo: "_r", nameId: "mallory").Xml;
        World.Rejects(() => World.PostAcs(sp, World.ResponseXml(inResponseTo: "_r", assertion: forged + signed, hasAssertion: true), "_r", null), "validation", "exactly one");
        var hidden = Regex.Replace(forged, "ID=\"[^\"]+\"", "ID=\"" + id + "\"");
        hidden = hidden.Replace("</saml:Assertion>", "<saml:Advice>" + signed + "</saml:Advice></saml:Assertion>", StringComparison.Ordinal);
        World.Rejects(() => World.PostAcs(sp, World.ResponseXml(inResponseTo: "_r", assertion: hidden, hasAssertion: true), "_r", null), "signature", "two elements");
        var sig = Regex.Match(signed, "<ds:Signature[\\s\\S]*</ds:Signature>").Value;
        var moved = Regex.Replace(forged, "(</saml:Issuer>)", "$1" + sig);
        World.Rejects(() => World.PostAcs(sp, World.ResponseXml(inResponseTo: "_r", assertion: moved, hasAssertion: true), "_r", null), "signature", "refers to");
    }

    [Fact]
    public void RefusesAResponseForAnotherAudienceAcsOrThatHasExpired()
    {
        var sp = World.MustSp();
        var audience = World.SignedAssertion(inResponseTo: "_r", audience: "https://other.test").Xml;
        World.Rejects(() => World.PostAcs(sp, World.ResponseXml(inResponseTo: "_r", assertion: audience, hasAssertion: true), "_r", null), "validation", "not for");
        var recipient = World.SignedAssertion(inResponseTo: "_r", recipient: "https://other.test/acs").Xml;
        World.Rejects(() => World.PostAcs(sp, World.ResponseXml(inResponseTo: "_r", assertion: recipient, hasAssertion: true), "_r", null), "validation", "Recipient");
        var expired = World.SignedAssertion(inResponseTo: "_r", hasExpiry: true, notOnOrAfterMs: -120000).Xml;
        World.Rejects(() => World.PostAcs(sp, World.ResponseXml(inResponseTo: "_r", assertion: expired, hasAssertion: true), "_r", null), "validation", "expired");
        World.Rejects(() => World.PostAcs(sp, World.ResponseXml(inResponseTo: "_r", hasDestination: true, destination: "https://other.test/acs"), "_r", null), "validation", "addressed to");
        var issuer = World.SignedAssertion(inResponseTo: "_r", issuer: "https://evil.test").Xml;
        World.Rejects(() => World.PostAcs(sp, World.ResponseXml(inResponseTo: "_r", assertion: issuer, hasAssertion: true), "_r", null), "validation", "issued by");
    }

    [Fact]
    public void RefusesAnAnswerToAnotherRequestAndAnUnsolicitedOne()
    {
        var sp = World.MustSp();
        World.Rejects(() => World.PostAcs(sp, World.ResponseXml(inResponseTo: "_r"), "_other", null), "validation", "not a request this browser");
        World.Rejects(() => World.PostAcs(sp, World.ResponseXml(inResponseTo: "_r"), "", null), "validation", "not a request this browser");
        World.Rejects(() => World.PostAcs(sp, World.ResponseXml(), "", null), "validation", "unsolicited");
        var open = World.MustSp(new Dictionary<string, object?> { ["allowUnsolicited"] = true });
        var who = World.PostAcs(open, World.ResponseXml(), "", null);
        Assert.Null(who.InResponseTo);
    }

    [Fact]
    public void RefusesTheSameAssertionTwice()
    {
        var sp = World.MustSp();
        var xml = World.ResponseXml(inResponseTo: "_r", sign: true);
        World.PostAcs(sp, xml, "_r", null);
        World.Rejects(() => World.PostAcs(sp, xml, "_r", null), "replay", "");
    }

    [Fact]
    public void ReportsANonSuccessStatus()
    {
        var sp = World.MustSp();
        var ex = Assert.Throws<SamlException>(() => World.PostAcs(sp, World.ResponseXml(inResponseTo: "_r", status: "urn:oasis:names:tc:SAML:2.0:status:Responder"), "_r", null));
        Assert.Equal("status", ex.Code);
        Assert.NotNull(ex.Status);
        Assert.Equal("urn:oasis:names:tc:SAML:2.0:status:Responder", ex.Status!.Code);
    }

    [Fact]
    public void RefusesADoctype()
    {
        var sp = World.MustSp();
        var xml = "<!DOCTYPE x [<!ENTITY e \"x\">]>" + World.ResponseXml(inResponseTo: "_r");
        World.Rejects(() => World.PostAcs(sp, xml, "_r", null), "xml", "DOCTYPE");
    }

    [Fact]
    public void DecryptsAnEncryptedAssertion()
    {
        var sp = World.MustSp();
        foreach (var cipherName in new[] { "aes-256-gcm", "aes-128-cbc" })
        {
            var made = World.SignedAssertion(inResponseTo: "_r").Xml;
            var who = World.PostAcs(sp, World.ResponseXml(inResponseTo: "_r", sign: true, assertion: World.EncryptAssertion(made, cipherName), hasAssertion: true), "_r", null);
            Assert.Equal("alice-1234", who.NameId);
            Assert.True(who.Encrypted);
        }
        var oaep = World.SignedAssertion(inResponseTo: "_r").Xml;
        var opened = World.PostAcs(sp, World.ResponseXml(inResponseTo: "_r", assertion: World.EncryptAssertion(oaep, "aes-256-gcm", "oaep256"), hasAssertion: true), "_r", null);
        Assert.Equal("alice-1234", opened.NameId);
    }

    [Fact]
    public void RefusesAPlaintextAssertionWhenEncryptionIsRequired()
    {
        var sp = World.MustSp(new Dictionary<string, object?> { ["wantAssertionsEncrypted"] = true });
        World.Rejects(() => World.PostAcs(sp, World.ResponseXml(inResponseTo: "_r", sign: true), "_r", null), "validation", "not encrypted");
        var made = World.SignedAssertion(inResponseTo: "_r").Xml;
        var who = World.PostAcs(sp, World.ResponseXml(inResponseTo: "_r", assertion: World.EncryptAssertion(made), hasAssertion: true), "_r", null);
        Assert.True(who.Encrypted);
    }

    [Fact]
    public void RefusesAnEncryptedAssertionWhoseCiphertextWasAltered()
    {
        var sp = World.MustSp();
        var made = World.SignedAssertion(inResponseTo: "_r").Xml;
        var enc = World.EncryptAssertion(made);
        var values = Regex.Matches(enc, "<xenc:CipherValue>([^<]+)</xenc:CipherValue>");
        var last = values[^1].Groups[1].Value;
        var blob = Convert.FromBase64String(last);
        blob[20] ^= 1;
        var xml = World.ResponseXml(inResponseTo: "_r", assertion: enc.Replace(last, Convert.ToBase64String(blob), StringComparison.Ordinal), hasAssertion: true);
        World.Rejects(() => World.PostAcs(sp, xml, "_r", null), "decryption", "");
    }

    [Fact]
    public void DecryptsAnEncryptedAttribute()
    {
        var sp = World.MustSp();
        var secret = World.EncryptAssertion("<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"employeeNumber\"><saml:AttributeValue>E-42</saml:AttributeValue></saml:Attribute>", "aes-256-gcm", "oaep256", "EncryptedAttribute");
        var (raw, id) = World.AssertionXml(inResponseTo: "_r", extra: secret);
        var who = World.PostAcs(sp, World.ResponseXml(inResponseTo: "_r", assertion: World.SignXml(raw, id), hasAssertion: true), "_r", null);
        Assert.Equal("E-42", string.Join(",", who.Attributes["employeeNumber"]));
    }

    [Fact]
    public void RedirectResponseVerifiesTheQuerySignature()
    {
        var sp = World.MustSp();
        var query = World.RedirectResponseQuery(World.ResponseXml(inResponseTo: "_r"), "/there");
        var who = sp.Acs("GET", "/saml/acs?" + query, null, new[] { "_r" });
        Assert.Equal("redirect", who.Binding);
        Assert.Equal("/there", who.RelayState);
    }

    [Fact]
    public void RefusesAQuerySignatureByAnotherKeyAndAChangedRelayState()
    {
        var sp = World.MustSp();
        var forged = World.RedirectResponseQuery(World.ResponseXml(inResponseTo: "_r"), "/x", World.Sp.PrivateKey);
        World.Rejects(() => sp.Acs("GET", "/saml/acs?" + forged, null, new[] { "_r" }), "signature", "");
        var changed = World.RedirectResponseQuery(World.ResponseXml(inResponseTo: "_r"), "/x").Replace("RelayState=%2Fx", "RelayState=%2Fy", StringComparison.Ordinal);
        World.Rejects(() => sp.Acs("GET", "/saml/acs?" + changed, null, new[] { "_r" }), "signature", "");
    }

    [Fact]
    public void ResolvesTheArtifact()
    {
        using var ars = new ArsServer();
        var sp = World.MustSp(new Dictionary<string, object?> { ["responseBinding"] = "artifact" }, ars.Url);
        var req = sp.Login(new LoginOptions());
        Assert.Contains("HTTP-Artifact", req.Xml);
        var artifact = World.ArtifactFor();
        ars.Put(artifact, World.ResponseXml(inResponseTo: req.Id));
        var who = sp.Acs("GET", "/saml/acs?SAMLart=" + Uri.EscapeDataString(artifact) + "&RelayState=%2Fa", null, new[] { req.Id });
        Assert.Equal("artifact", who.Binding);
        Assert.Equal("/a", who.RelayState);
        Assert.Equal("alice-1234", who.NameId);
        Assert.Equal(artifact, string.Join(",", ars.Resolved));
    }

    [Fact]
    public void AcceptsTheArtifactOnAPostAndFailsWhenAlreadyUsed()
    {
        using var ars = new ArsServer();
        var sp = World.MustSp(null, ars.Url);
        var artifact = World.ArtifactFor();
        ars.Put(artifact, World.ResponseXml(inResponseTo: "_r"));
        var who = sp.Acs("POST", "/saml/acs", "SAMLart=" + Uri.EscapeDataString(artifact), new[] { "_r" });
        Assert.Equal("artifact", who.Binding);
        World.Rejects(() => sp.Acs("POST", "/saml/acs", new Dictionary<string, string> { ["SAMLart"] = artifact }, new[] { "_r" }), "artifact", "did not resolve");
    }

    [Fact]
    public void RefusesAnArtifactFromAnotherIdentityProvider()
    {
        var sp = World.MustSp(null, "https://idp.test/saml2/ars");
        World.Rejects(() => sp.Acs("GET", "/saml/acs?SAMLart=" + Uri.EscapeDataString(World.ArtifactFor("https://evil.test")), null, new[] { "_r" }), "artifact", "not issued by");
    }

    [Fact]
    public void RefusesARequestWithNoSamlMessage()
    {
        var sp = World.MustSp();
        World.Rejects(() => sp.Acs("GET", "/saml/acs", null, null), "binding", "");
    }

    static Dictionary<string, string> Query(string raw)
    {
        var found = new Dictionary<string, string>();
        foreach (var part in raw.Split('&'))
        {
            var eq = part.IndexOf('=');
            found[Bindings.UriUnescape(part[..eq])] = Bindings.UriUnescape(part[(eq + 1)..]);
        }
        return found;
    }
}

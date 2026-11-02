// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Xml;

namespace IyaSec.Saml;

public sealed class SamlLogin
{
    public string NameId { get; init; } = "";
    public string NameIdFormat { get; init; } = "";
    public string NameQualifier { get; init; } = "";
    public string SpNameQualifier { get; init; } = "";
    public string SessionIndex { get; init; } = "";
    public DateTimeOffset? SessionNotOnOrAfter { get; init; }
    public DateTimeOffset AuthnInstant { get; init; }
    public string AuthnContextClassRef { get; init; } = "";
    public Dictionary<string, List<string>> Attributes { get; init; } = new();
    public Dictionary<string, string> AttributeFriendlyNames { get; init; } = new();
    public string Issuer { get; init; } = "";
    public string? InResponseTo { get; init; }
    public string? RelayState { get; init; }
    public string Binding { get; init; } = "";
    public bool Encrypted { get; init; }
    public string ResponseId { get; init; } = "";
    public string AssertionId { get; init; } = "";
}

static class ResponseValidator
{
    static readonly Regex DateTimeRe = new(@"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$", RegexOptions.Compiled);

    internal sealed class Received
    {
        public string Xml { get; init; } = "";
        public XmlElement Response { get; init; } = null!;
        public string Binding { get; init; } = "";
        public string? RelayState { get; init; }
        public bool AuthenticatedByBinding { get; init; }
    }

    internal sealed class Context
    {
        public string EntityId { get; init; } = "";
        public string AcsUrl { get; init; } = "";
        public string IdpEntityId { get; init; } = "";
        public List<X509Certificate2> IdpCertificates { get; init; } = new();
        public RSA DecryptionKey { get; init; } = null!;
        public long ClockSkewMs { get; init; }
        public bool WantAssertionsSigned { get; init; } = true;
        public bool WantAssertionsEncrypted { get; init; }
        public bool AllowUnsolicited { get; init; }
        public MemoryReplayCache Replay { get; init; } = null!;
        public IReadOnlyList<string> ExpectedRequestIds { get; init; } = Array.Empty<string>();
        public DateTimeOffset Now { get; init; }
    }

    internal static SamlLogin Validate(Received received, Context ctx)
    {
        var now = ctx.Now == default ? DateTimeOffset.UtcNow : ctx.Now;
        var nowMs = now.ToUnixTimeMilliseconds();
        var skew = ctx.ClockSkewMs;
        var response = received.Response;
        XmlUtil.AssertUniqueIds(XmlUtil.RootOf(response));
        if (!XmlUtil.Same(response, XmlUtil.NsSamlp, "Response"))
            throw Invalid("the message is a <" + response.LocalName + ">, not a Response");
        var signed = Canon.VerifySigned(response, ctx.IdpCertificates, "the Response");
        if (signed != null) response = XmlUtil.Parse(signed, "the signed Response");
        var responseAuthenticated = signed != null || received.AuthenticatedByBinding;
        var version = XmlUtil.AttrOr(response, "Version");
        if (version != "2.0")
            throw Invalid("the Response is version " + (version.Length == 0 ? "(none)" : version) + ", not 2.0");
        if (!XmlUtil.Attr(response, "ID", out var responseId) || responseId.Length == 0)
            throw Invalid("the Response has no ID");
        IssuerOf(response, false, ctx.IdpEntityId, "the Response");
        var hasDest = XmlUtil.Attr(response, "Destination", out var destination);
        if (hasDest && destination != ctx.AcsUrl)
            throw Invalid("the Response is addressed to " + destination + ", not to " + ctx.AcsUrl);
        if (!hasDest && responseAuthenticated && received.Binding != "artifact")
            throw Invalid("the Response is signed but has no Destination");
        string? inPtr = null;
        if (XmlUtil.Attr(response, "InResponseTo", out var inResponseTo))
        {
            inPtr = inResponseTo;
            if (!ctx.ExpectedRequestIds.Contains(inResponseTo))
                throw Invalid("the Response answers " + inResponseTo + ", which is not a request this browser has outstanding");
        }
        else if (!ctx.AllowUnsolicited)
            throw Invalid("the Response is unsolicited (it has no InResponseTo), and unsolicited Responses are not accepted");
        var status = StatusOf(response);
        if (status.Code != XmlUtil.StatusSuccess)
        {
            var detail = status.SubCode.Length > 0 ? status.SubCode : status.Code;
            var suffix = status.Message.Length > 0 ? ": " + status.Message : "";
            throw new SamlException("status", "the identity provider answered " + detail + suffix, status: status);
        }
        var plain = XmlUtil.Children(response, XmlUtil.NsSaml, "Assertion");
        var encrypted = XmlUtil.Children(response, XmlUtil.NsSaml, "EncryptedAssertion");
        if (plain.Count + encrypted.Count != 1)
            throw Invalid("the Response holds " + (plain.Count + encrypted.Count) + " assertions; exactly one is accepted");
        XmlElement assertion;
        var wasEncrypted = false;
        if (encrypted.Count == 1)
        {
            wasEncrypted = true;
            var assertionXml = Encryption.DecryptElement(encrypted[0], ctx.DecryptionKey);
            var doc = XmlUtil.Parse(assertionXml, "the decrypted assertion");
            XmlUtil.AssertUniqueIds(doc);
            assertion = doc;
            if (!XmlUtil.Same(assertion, XmlUtil.NsSaml, "Assertion"))
                throw Invalid("the EncryptedAssertion does not hold an Assertion");
        }
        else
        {
            if (ctx.WantAssertionsEncrypted)
                throw Invalid("the assertion is not encrypted, and wantAssertionsEncrypted is on");
            assertion = plain[0];
        }
        var signedAssertion = Canon.VerifySigned(assertion, ctx.IdpCertificates, "the assertion");
        if (signedAssertion != null) assertion = XmlUtil.Parse(signedAssertion, "the signed assertion");
        else if (ctx.WantAssertionsSigned) throw Invalid("the assertion is not signed, and wantAssertionsSigned is on");
        else if (!responseAuthenticated) throw Invalid("neither the Response nor its assertion is signed");
        if (XmlUtil.AttrOr(assertion, "Version") != "2.0") throw Invalid("the assertion is not version 2.0");
        if (!XmlUtil.Attr(assertion, "ID", out var assertionId) || assertionId.Length == 0)
            throw Invalid("the assertion has no ID");
        IssuerOf(assertion, true, ctx.IdpEntityId, "the assertion");
        var subject = XmlUtil.One(assertion, XmlUtil.NsSaml, "Subject") ?? throw Invalid("the assertion has no Subject");
        var nameId = XmlUtil.One(subject, XmlUtil.NsSaml, "NameID");
        var encryptedId = XmlUtil.One(subject, XmlUtil.NsSaml, "EncryptedID");
        if (nameId == null && encryptedId != null)
        {
            nameId = XmlUtil.Parse(Encryption.DecryptElement(encryptedId, ctx.DecryptionKey), "the decrypted NameID");
            if (!XmlUtil.Same(nameId, XmlUtil.NsSaml, "NameID")) throw Invalid("the EncryptedID does not hold a NameID");
        }
        if (nameId == null || XmlUtil.TextOf(nameId).Length == 0) throw Invalid("the assertion's Subject has no NameID");
        var reasons = new List<string>();
        DateTimeOffset? confirmedUntil = null;
        foreach (var confirmation in XmlUtil.Children(subject, XmlUtil.NsSaml, "SubjectConfirmation"))
        {
            if (XmlUtil.AttrOr(confirmation, "Method") != XmlUtil.Bearer)
            {
                reasons.Add("method " + XmlUtil.AttrOr(confirmation, "Method"));
                continue;
            }
            var data = XmlUtil.One(confirmation, XmlUtil.NsSaml, "SubjectConfirmationData");
            if (data == null)
            {
                reasons.Add("no SubjectConfirmationData");
                continue;
            }
            var recipient = XmlUtil.AttrOr(data, "Recipient");
            var notOnOrAfter = ParseInstant(XmlUtil.AttrOr(data, "NotOnOrAfter"), "SubjectConfirmationData NotOnOrAfter");
            var hasNotBefore = XmlUtil.Attr(data, "NotBefore", out _);
            var hasSc = XmlUtil.Attr(data, "InResponseTo", out var scIn);
            if (recipient != ctx.AcsUrl) reasons.Add("Recipient " + (recipient.Length == 0 ? "(none)" : recipient));
            else if (notOnOrAfter == null) reasons.Add("no NotOnOrAfter");
            else if (notOnOrAfter.Value.ToUnixTimeMilliseconds() <= nowMs - skew)
                reasons.Add("expired at " + Stamp(notOnOrAfter.Value));
            else if (hasNotBefore) reasons.Add("a NotBefore, which a bearer confirmation must not have");
            else if ((hasSc && (inPtr == null || scIn != inPtr)) || (!hasSc && inPtr != null))
                reasons.Add("InResponseTo " + (!hasSc || scIn.Length == 0 ? "(none)" : scIn));
            else
            {
                confirmedUntil = notOnOrAfter;
                break;
            }
        }
        if (confirmedUntil == null)
            throw Invalid("no bearer SubjectConfirmation of the assertion fits: " + (reasons.Count == 0 ? "there is none" : string.Join("; ", reasons)));
        var conditions = XmlUtil.One(assertion, XmlUtil.NsSaml, "Conditions") ?? throw Invalid("the assertion has no Conditions, so it names no audience");
        var notBeforeC = ParseInstant(XmlUtil.AttrOr(conditions, "NotBefore"), "Conditions NotBefore");
        var notOnOrAfterC = ParseInstant(XmlUtil.AttrOr(conditions, "NotOnOrAfter"), "Conditions NotOnOrAfter");
        if (notBeforeC != null && notBeforeC.Value.ToUnixTimeMilliseconds() > nowMs + skew)
            throw Invalid("the assertion is not valid before " + Stamp(notBeforeC.Value));
        if (notOnOrAfterC != null && notOnOrAfterC.Value.ToUnixTimeMilliseconds() <= nowMs - skew)
            throw Invalid("the assertion expired at " + Stamp(notOnOrAfterC.Value));
        var restrictions = XmlUtil.Children(conditions, XmlUtil.NsSaml, "AudienceRestriction");
        if (restrictions.Count == 0) throw Invalid("the assertion has no AudienceRestriction");
        foreach (var restriction in restrictions)
        {
            if (!XmlUtil.Children(restriction, XmlUtil.NsSaml, "Audience").Any(item => XmlUtil.TextOf(item) == ctx.EntityId))
                throw Invalid("the assertion is not for " + ctx.EntityId);
        }
        var authnStatements = XmlUtil.Children(assertion, XmlUtil.NsSaml, "AuthnStatement");
        if (authnStatements.Count == 0) throw Invalid("the assertion has no AuthnStatement");
        var authn = authnStatements[0];
        var authnInstant = ParseInstant(XmlUtil.AttrOr(authn, "AuthnInstant"), "AuthnInstant") ?? throw Invalid("the AuthnStatement has no AuthnInstant");
        var sessionNotOnOrAfter = ParseInstant(XmlUtil.AttrOr(authn, "SessionNotOnOrAfter"), "SessionNotOnOrAfter");
        if (sessionNotOnOrAfter != null && sessionNotOnOrAfter.Value.ToUnixTimeMilliseconds() <= nowMs - skew)
            throw Invalid("the identity provider's session has already ended");
        var contextEl = XmlUtil.One(authn, XmlUtil.NsSaml, "AuthnContext");
        var classRef = "";
        if (contextEl != null) classRef = XmlUtil.TextOf(XmlUtil.One(contextEl, XmlUtil.NsSaml, "AuthnContextClassRef"));
        var attributes = new Dictionary<string, List<string>>();
        var friendly = new Dictionary<string, string>();
        foreach (var statement in XmlUtil.Children(assertion, XmlUtil.NsSaml, "AttributeStatement"))
        {
            var decrypted = new List<XmlElement>();
            foreach (var enc in XmlUtil.Children(statement, XmlUtil.NsSaml, "EncryptedAttribute"))
            {
                var element = XmlUtil.Parse(Encryption.DecryptElement(enc, ctx.DecryptionKey), "the decrypted attribute");
                if (!XmlUtil.Same(element, XmlUtil.NsSaml, "Attribute"))
                    throw Invalid("an EncryptedAttribute does not hold an Attribute");
                decrypted.Add(element);
            }
            foreach (var attribute in XmlUtil.Children(statement, XmlUtil.NsSaml, "Attribute").Concat(decrypted))
            {
                var name = XmlUtil.AttrOr(attribute, "Name");
                if (name.Length == 0) continue;
                var values = XmlUtil.Children(attribute, XmlUtil.NsSaml, "AttributeValue").Select(XmlUtil.IterText).ToList();
                if (!attributes.TryGetValue(name, out var existing)) attributes[name] = existing = new List<string>();
                existing.AddRange(values);
                var friend = XmlUtil.AttrOr(attribute, "FriendlyName");
                if (friend.Length > 0) friendly[name] = friend;
            }
        }
        var keep = confirmedUntil.Value.ToUnixTimeMilliseconds();
        if (notOnOrAfterC != null && notOnOrAfterC.Value.ToUnixTimeMilliseconds() > keep)
            keep = notOnOrAfterC.Value.ToUnixTimeMilliseconds();
        keep += skew;
        if (ctx.Replay.CheckAndRecord(ctx.IdpEntityId + " " + assertionId, DateTimeOffset.FromUnixTimeMilliseconds(keep)))
            throw new SamlException("replay", "the assertion " + assertionId + " has been accepted before");
        return new SamlLogin
        {
            NameId = XmlUtil.TextOf(nameId),
            NameIdFormat = XmlUtil.AttrOr(nameId, "Format"),
            NameQualifier = XmlUtil.AttrOr(nameId, "NameQualifier"),
            SpNameQualifier = XmlUtil.AttrOr(nameId, "SPNameQualifier"),
            SessionIndex = XmlUtil.AttrOr(authn, "SessionIndex"),
            SessionNotOnOrAfter = sessionNotOnOrAfter,
            AuthnInstant = authnInstant,
            AuthnContextClassRef = classRef,
            Attributes = attributes,
            AttributeFriendlyNames = friendly,
            Issuer = ctx.IdpEntityId,
            InResponseTo = inPtr,
            RelayState = received.RelayState,
            Binding = received.Binding,
            Encrypted = wasEncrypted,
            ResponseId = responseId,
            AssertionId = assertionId,
        };
    }

    static SamlException Invalid(string message) => new("validation", message);

    static DateTimeOffset? ParseInstant(string value, string what)
    {
        if (value.Length == 0) return null;
        if (!DateTimeRe.IsMatch(value)) throw Invalid(what + " is not a UTC dateTime: " + value);
        if (!DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var parsed))
            throw Invalid(what + " is not a dateTime: " + value);
        return parsed.ToUniversalTime();
    }

    static string Stamp(DateTimeOffset when) => when.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    static void IssuerOf(XmlElement el, bool required, string expected, string what)
    {
        var issuer = XmlUtil.One(el, XmlUtil.NsSaml, "Issuer");
        if (issuer == null)
        {
            if (required) throw Invalid(what + " has no Issuer");
            return;
        }
        var form = XmlUtil.AttrOr(issuer, "Format");
        if (form.Length > 0 && form != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity")
            throw Invalid(what + "'s Issuer has the Format " + form);
        if (XmlUtil.TextOf(issuer) != expected)
            throw Invalid(what + " was issued by " + XmlUtil.TextOf(issuer) + ", not by " + expected);
    }

    static SamlStatus StatusOf(XmlElement response)
    {
        var status = XmlUtil.One(response, XmlUtil.NsSamlp, "Status") ?? throw Invalid("the Response has no Status");
        var top = XmlUtil.One(status, XmlUtil.NsSamlp, "StatusCode") ?? throw Invalid("the Response has no StatusCode");
        var sub = XmlUtil.One(top, XmlUtil.NsSamlp, "StatusCode");
        var message = XmlUtil.One(status, XmlUtil.NsSamlp, "StatusMessage");
        return new SamlStatus
        {
            Code = XmlUtil.AttrOr(top, "Value"),
            SubCode = sub != null ? XmlUtil.AttrOr(sub, "Value") : "",
            Message = XmlUtil.TextOf(message),
        };
    }
}

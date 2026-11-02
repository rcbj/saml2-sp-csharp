// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

namespace IyaSec.Saml;

public static class Events
{
    const string CaepPrefix = "https://schemas.openid.net/secevent/caep/event-type/";
    const string RiscPrefix = "https://schemas.openid.net/secevent/risc/event-type/";
    const string SsfPrefix = "https://schemas.openid.net/secevent/ssf/event-type/";

    public static readonly IReadOnlyDictionary<string, string> Event = new Dictionary<string, string>
    {
        ["session_revoked"] = CaepPrefix + "session-revoked",
        ["token_claims_change"] = CaepPrefix + "token-claims-change",
        ["credential_change"] = CaepPrefix + "credential-change",
        ["assurance_level_change"] = CaepPrefix + "assurance-level-change",
        ["device_compliance_change"] = CaepPrefix + "device-compliance-change",
        ["session_established"] = CaepPrefix + "session-established",
        ["session_presented"] = CaepPrefix + "session-presented",
        ["risk_level_change"] = CaepPrefix + "risk-level-change",
        ["account_credential_change_required"] = RiscPrefix + "account-credential-change-required",
        ["account_purged"] = RiscPrefix + "account-purged",
        ["account_disabled"] = RiscPrefix + "account-disabled",
        ["account_enabled"] = RiscPrefix + "account-enabled",
        ["identifier_changed"] = RiscPrefix + "identifier-changed",
        ["identifier_recycled"] = RiscPrefix + "identifier-recycled",
        ["credential_compromise"] = RiscPrefix + "credential-compromise",
        ["opt_in"] = RiscPrefix + "opt-in",
        ["opt_out_initiated"] = RiscPrefix + "opt-out-initiated",
        ["opt_out_cancelled"] = RiscPrefix + "opt-out-cancelled",
        ["opt_out_effective"] = RiscPrefix + "opt-out-effective",
        ["recovery_activated"] = RiscPrefix + "recovery-activated",
        ["recovery_information_changed"] = RiscPrefix + "recovery-information-changed",
        ["sessions_revoked"] = RiscPrefix + "sessions-revoked",
        ["verification"] = SsfPrefix + "verification",
        ["stream_updated"] = SsfPrefix + "stream-updated",
    };

    static readonly string[] Order =
    {
        "session_revoked", "token_claims_change", "credential_change", "assurance_level_change",
        "device_compliance_change", "session_established", "session_presented", "risk_level_change",
        "account_credential_change_required", "account_purged", "account_disabled", "account_enabled",
        "identifier_changed", "identifier_recycled", "credential_compromise", "opt_in",
        "opt_out_initiated", "opt_out_cancelled", "opt_out_effective", "recovery_activated",
        "recovery_information_changed", "sessions_revoked", "verification", "stream_updated",
    };

    public static IReadOnlyList<string> CaepEvents() => WithPrefix(CaepPrefix);

    public static IReadOnlyList<string> RiscEvents() => WithPrefix(RiscPrefix);

    public static IReadOnlyList<string> DefaultEventsRequested() => new[]
    {
        Event["session_revoked"], Event["credential_change"], Event["assurance_level_change"], Event["token_claims_change"],
        Event["account_disabled"], Event["account_enabled"], Event["account_purged"], Event["credential_compromise"],
        Event["sessions_revoked"], Event["account_credential_change_required"],
    };

    public static IReadOnlyList<string> DefaultEndingEvents() => new[]
    {
        Event["session_revoked"], Event["account_disabled"], Event["account_purged"], Event["credential_compromise"], Event["sessions_revoked"],
    };

    static List<string> WithPrefix(string prefix)
    {
        var list = new List<string>();
        foreach (var key in Order)
            if (Event[key].StartsWith(prefix, StringComparison.Ordinal)) list.Add(Event[key]);
        return list;
    }

    public static Dictionary<string, string> SubjectOf(object? subId, string issuer)
    {
        if (subId is not Dictionary<string, object?> obj) return new Dictionary<string, string>();
        var form = Str(obj, "format");
        if (form.Length == 0) form = Str(obj, "subject_type");
        if (form == "complex" || (form.Length == 0 && (obj.ContainsKey("user") || obj.ContainsKey("session"))))
        {
            var user = Simple(obj.TryGetValue("user", out var userRaw) ? userRaw : null, issuer);
            var session = Simple(obj.TryGetValue("session", out var sessionRaw) ? sessionRaw : null, issuer);
            var found = new Dictionary<string, string>();
            if (user.TryGetValue("sub", out var person) && person.Length > 0) found["person"] = person;
            if (user.TryGetValue("email", out var email) && email.Length > 0) found["email"] = email;
            var sessionId = session.TryGetValue("opaque", out var opaque) ? opaque : "";
            if (sessionId.Length == 0 && session.TryGetValue("sub", out var sub)) sessionId = sub;
            if (sessionId.Length > 0) found["idp_session"] = sessionId;
            return found;
        }
        var one = Simple(obj, issuer);
        var outMap = new Dictionary<string, string>();
        if (one.TryGetValue("sub", out var oneSub) && oneSub.Length > 0) outMap["person"] = oneSub;
        if (one.TryGetValue("email", out var oneEmail) && oneEmail.Length > 0) outMap["email"] = oneEmail;
        return outMap;
    }

    static Dictionary<string, string> Simple(object? identifier, string issuer)
    {
        if (identifier is not Dictionary<string, object?> obj) return new Dictionary<string, string>();
        var form = Str(obj, "format");
        if (form.Length == 0) form = Str(obj, "subject_type");
        switch (form)
        {
            case "iss_sub":
                var sub = Str(obj, "sub");
                var hasIss = obj.ContainsKey("iss") && obj["iss"] != null;
                if (sub.Length > 0 && (!hasIss || Str(obj, "iss") == issuer))
                    return new Dictionary<string, string> { ["sub"] = sub };
                break;
            case "email":
                var email = Str(obj, "email");
                if (email.Length > 0) return new Dictionary<string, string> { ["email"] = email };
                break;
            case "opaque":
                var id = Str(obj, "id");
                if (id.Length > 0) return new Dictionary<string, string> { ["opaque"] = id };
                break;
            case "aliases":
                var merged = new Dictionary<string, string>();
                if (obj.TryGetValue("identifiers", out var items) && items is List<object?> list)
                {
                    foreach (var item in list)
                        foreach (var pair in Simple(item, issuer))
                            merged[pair.Key] = pair.Value;
                }
                return merged;
        }
        return new Dictionary<string, string>();
    }

    static string Str(Dictionary<string, object?> obj, string key) =>
        obj.TryGetValue(key, out var value) && value is string text ? text : "";
}

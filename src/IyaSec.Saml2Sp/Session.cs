// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

namespace IyaSec.Saml;

public sealed class SessionRecord
{
    public string LocalId { get; init; } = "";
    public string Person { get; init; } = "";
    public string Email { get; init; } = "";
    public string IdpSession { get; init; } = "";
    public DateTimeOffset? ExpiresAt { get; init; }
}

public sealed class MemorySessionIndex
{
    readonly object _gate = new();
    readonly Dictionary<string, SessionRecord> _sessions = new();
    readonly List<string> _order = new();
    readonly int _max;

    public const string DefaultSubjectAttribute = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";

    static readonly string[] MailAttributes =
    {
        "urn:oid:0.9.2342.19200300.100.1.3",
        "mail",
        "email",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    };

    const string EmailNameId = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

    public MemorySessionIndex(int maxEntries = 0)
    {
        _max = maxEntries <= 0 ? 100000 : maxEntries;
    }

    public void Add(SessionRecord session)
    {
        lock (_gate)
        {
            if (!_sessions.ContainsKey(session.LocalId) && _sessions.Count >= _max)
            {
                var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                var expired = _order.Where(key => _sessions.TryGetValue(key, out var value) && value.ExpiresAt != null && value.ExpiresAt.Value.ToUnixTimeMilliseconds() <= now).ToList();
                foreach (var key in expired) Drop(key);
                while (_sessions.Count >= _max && _order.Count > 0) Drop(_order[0]);
            }
            if (session.Email.Length > 0)
                session = Copy(session, session.Email.ToLowerInvariant());
            if (!_sessions.ContainsKey(session.LocalId)) _order.Add(session.LocalId);
            _sessions[session.LocalId] = session;
        }
    }

    public void Remove(string localId)
    {
        lock (_gate) Drop(localId);
    }

    public List<string> ByPerson(string person)
    {
        lock (_gate) return Find(session => session.Person == person);
    }

    public List<string> ByEmail(string email)
    {
        var wanted = email.ToLowerInvariant();
        lock (_gate) return Find(session => session.Email == wanted);
    }

    public List<string> ByIdpSession(string idpSession)
    {
        lock (_gate) return Find(session => session.IdpSession == idpSession);
    }

    public static SessionRecord TrackedFrom(string localId, SamlLogin login, string? subjectAttribute, DateTimeOffset? expiresAt)
    {
        var attribute = string.IsNullOrEmpty(subjectAttribute) ? DefaultSubjectAttribute : subjectAttribute;
        var person = login.Attributes.TryGetValue(attribute, out var people) && people.Count > 0 ? people[0] : "";
        var email = "";
        foreach (var name in MailAttributes)
        {
            if (login.Attributes.TryGetValue(name, out var values) && values.Count > 0 && values[0].Length > 0)
            {
                email = values[0];
                break;
            }
        }
        if (email.Length == 0 && login.NameIdFormat == EmailNameId) email = login.NameId;
        return new SessionRecord
        {
            LocalId = localId,
            Person = person,
            Email = email,
            IdpSession = login.SessionIndex,
            ExpiresAt = expiresAt ?? login.SessionNotOnOrAfter,
        };
    }

    void Drop(string localId)
    {
        _sessions.Remove(localId);
        _order.RemoveAll(id => id == localId);
    }

    List<string> Find(Func<SessionRecord, bool> match)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var found = new List<string>();
        var keep = new List<string>();
        foreach (var key in _order)
        {
            if (!_sessions.TryGetValue(key, out var value)) continue;
            if (value.ExpiresAt != null && value.ExpiresAt.Value.ToUnixTimeMilliseconds() <= now)
            {
                _sessions.Remove(key);
                continue;
            }
            keep.Add(key);
            if (match(value)) found.Add(key);
        }
        _order.Clear();
        _order.AddRange(keep);
        return found;
    }

    static SessionRecord Copy(SessionRecord session, string email) => new()
    {
        LocalId = session.LocalId,
        Person = session.Person,
        Email = email,
        IdpSession = session.IdpSession,
        ExpiresAt = session.ExpiresAt,
    };
}

// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Globalization;
using System.Security.Cryptography;

namespace IyaSec.Saml;

static class Ids
{
    internal static string New()
    {
        var buf = new byte[20];
        RandomNumberGenerator.Fill(buf);
        return "_" + Convert.ToHexString(buf).ToLowerInvariant();
    }

    internal static string Iso(DateTimeOffset when)
    {
        if (when == default) when = DateTimeOffset.UtcNow;
        return when.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
    }
}

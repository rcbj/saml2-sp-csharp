// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

namespace IyaSec.Saml;

public sealed class SamlStatus
{
    public string Code { get; init; } = "";
    public string SubCode { get; init; } = "";
    public string Message { get; init; } = "";

    public override string ToString() =>
        $"SamlStatus(code=\"{Code}\", sub_code=\"{SubCode}\", message=\"{Message}\")";
}

public sealed class SamlException : Exception
{
    public string Code { get; }
    public SamlStatus? Status { get; }

    public SamlException(string code, string message, Exception? cause = null, SamlStatus? status = null)
        : base(message, cause)
    {
        Code = code;
        Status = status;
    }
}

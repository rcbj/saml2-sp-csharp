// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace IyaSec.Saml;

public sealed class KeyPair : IDisposable
{
    public string PrivateKeyPem { get; }
    public string CertificatePem { get; }
    public X509Certificate2 Certificate { get; }
    public RSA PrivateKey { get; }

    internal KeyPair(string privateKeyPem, string certificatePem, X509Certificate2 certificate, RSA privateKey)
    {
        PrivateKeyPem = privateKeyPem;
        CertificatePem = certificatePem;
        Certificate = certificate;
        PrivateKey = privateKey;
    }

    public string Fingerprint256()
    {
        var sum = SHA256.HashData(Certificate.RawData);
        return string.Join(":", sum.Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));
    }

    public string ValidTo()
    {
        var stamp = Certificate.NotAfter.ToUniversalTime().ToString("MMM dd HH:mm:ss yyyy 'GMT'", CultureInfo.InvariantCulture);
        return stamp.Replace(" 0", "  ", StringComparison.Ordinal);
    }

    public void Dispose()
    {
        Certificate.Dispose();
        PrivateKey.Dispose();
    }
}

public static class Keys
{
    public static KeyPair CreateSelfSignedKeyPair(string commonName, int days = 0, int bits = 0)
    {
        if (days <= 0) days = 1095;
        if (bits == 0) bits = 3072;
        var key = RSA.Create(bits);
        var notBefore = DateTimeOffset.UtcNow.AddSeconds(-60);
        var serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;
        if (serial.All(b => b == 0)) serial[15] = 1;
        var request = new CertificateRequest("CN=" + commonName, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        var oids = new OidCollection { new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oids, false));
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        var made = request.CreateSelfSigned(notBefore, notBefore.AddDays(days));
        var cert = new X509Certificate2(made.Export(X509ContentType.Cert));
        made.Dispose();
        return new KeyPair(key.ExportPkcs8PrivateKeyPem(), cert.ExportCertificatePem(), cert, key);
    }

    internal static RSA LoadRsa(string pem)
    {
        try
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return rsa;
        }
        catch (Exception ex) when (ex is not SamlException)
        {
            try
            {
                using var ec = ECDsa.Create();
                ec.ImportFromPem(pem);
                throw new SamlException("config", "the private key is ec; an RSA key is required");
            }
            catch (SamlException)
            {
                throw;
            }
            catch
            {
                throw new SamlException("config", "the private key or certificate cannot be read: unrecognized private key", ex);
            }
        }
    }

    internal static X509Certificate2 LoadCertificate(string pem)
    {
        try
        {
            return X509Certificate2.CreateFromPem(pem);
        }
        catch (Exception ex)
        {
            throw new SamlException("config", "the private key or certificate cannot be read: " + ex.Message, ex);
        }
    }

    internal static bool SamePublic(RSA key, X509Certificate2 cert)
    {
        using var pub = cert.GetRSAPublicKey();
        if (pub == null) return false;
        var left = key.ExportParameters(false);
        var right = pub.ExportParameters(false);
        return (left.Modulus ?? Array.Empty<byte>()).AsSpan().SequenceEqual(right.Modulus) &&
               (left.Exponent ?? Array.Empty<byte>()).AsSpan().SequenceEqual(right.Exponent);
    }

    internal static string CertBody(X509Certificate2 cert) => Convert.ToBase64String(cert.RawData);
}

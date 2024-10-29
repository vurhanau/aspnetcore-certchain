using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;

int port = 5001;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

X509Certificate2Collection c = [];
c.ImportFromPemFile("Cert/root.pem");
c.ImportFromPemFile("Cert/intermediate.pem");
c.ImportFromPemFile("Cert/leaf.pem");

X509Certificate2 rootCert = c[0];
X509Certificate2 intermediateCert = c[1];
X509Certificate2 leafCert = c[2];

using RSA rsa = RSA.Create();
rsa.ImportFromPem(File.ReadAllText("Cert/leaf.key"));
leafCert = leafCert.CopyWithPrivateKey(rsa);

builder.WebHost.UseKestrel(kestrel =>
{
    kestrel.Listen(IPAddress.Any, port, listenOptions =>
    {
        listenOptions.UseHttps(new TlsHandshakeCallbackOptions
        {
            OnConnection = ctx => ValueTask.FromResult(new SslServerAuthenticationOptions
            {
                ClientCertificateRequired = true,

                RemoteCertificateValidationCallback = (_, cert, chain, _) =>
                {
                    if (cert is null || chain is null)
                    {
                        return false;
                    }
                    chain.ChainPolicy.CustomTrustStore.Add(rootCert);
                    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

                    bool isValid = chain.Build(new(cert));
                    Console.WriteLine($"Client certificate is valid: {isValid}");
                    foreach (X509ChainStatus status in chain.ChainStatus)
                    {
                        Console.WriteLine($"Status: {status.Status}, StatusInformation: {status.StatusInformation}");
                    }

                    return isValid;
                },

                ServerCertificateContext = SslStreamCertificateContext.Create(leafCert, [intermediateCert, rootCert], true),
            }),
        });
    });
});

builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
                .AddCertificate(opts =>
                {
                    opts.RevocationMode = X509RevocationMode.NoCheck;
                    opts.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;
                    opts.CustomTrustStore.Add(rootCert);
                });


WebApplication app = builder.Build();
app.UseAuthentication();

app.MapGet("/", () => "Hello");

await app.RunAsync();

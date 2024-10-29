using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

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

using HttpClient http = new(new SocketsHttpHandler()
{
    SslOptions = new SslClientAuthenticationOptions
    {
        RemoteCertificateValidationCallback = (_, cert, chain, _) =>
        {
            if (cert is null || chain is null)
            {
                return false;
            }

            chain.ChainPolicy.CustomTrustStore.Add(rootCert);
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            
            bool isValid = chain.Build(new(cert));
            Console.WriteLine($"Server certificate is valid: {isValid}");
            foreach (X509ChainStatus status in chain.ChainStatus)
            {
                Console.WriteLine($"Status: {status.Status}, StatusInformation: {status.StatusInformation}");
            }

            return isValid;
        },

        ClientCertificateContext = SslStreamCertificateContext.Create(leafCert, [intermediateCert, rootCert], true),
    },
});

while (true)
{
    HttpResponseMessage resp = await http.GetAsync("https://localhost:5001");
    string content = await resp.Content.ReadAsStringAsync();
    Console.WriteLine($"{resp.StatusCode}: {content}");
    await Task.Delay(5000);
}

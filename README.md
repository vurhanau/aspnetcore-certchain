### Summary
`Microsoft.AspNetCore.Authentication.Certificate` authentication middleware fails to validate certificate chain ([issue](https://github.com/dotnet/aspnetcore/issues/53858)).

[CertificateAuthenticationHandler.BuildChain()](https://github.com/dotnet/aspnetcore/blob/d7130a2c5a99147005744969aab7f837c82659d5/src/Security/Authentication/Certificate/src/CertificateAuthenticationHandler.cs#L187) method ignores certificate chain sent by the client. There are cases when intermediate CA certificate is not known by the server ahead of time and sent by the client.

In this demo Client and Server establish mTLS connection sending a certificate chain (leaf, intermediate CA, root CA).

Kestrel server validates client certificate chain successfully.

Certificate authentication middleware fails to validate client chain.

### Steps to reproduce:
1. Run `dotnet run --project Server/Server.csproj`
2. Run `dotnet run --project Client/Client.csproj`
3. Observe the following warning in Server logs:
    ```
    warn: Microsoft.AspNetCore.Authentication.Certificate.CertificateAuthenticationHandler[2]
        Certificate validation failed, subject was CN=Test Leaf, C=US. PartialChain One or more certificates required to validate this certificate cannot be found.
    ```
    This warning indicates that intermediate certificate is ignored during certificate validation done by middleware.

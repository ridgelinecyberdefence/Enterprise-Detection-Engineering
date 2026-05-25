# Certificate Anomaly Fleet Hunt

Hunts for anomalous certificates in endpoint certificate stores: self-signed root CAs (potential MITM), expired certificates still in active use, certificates with weak key lengths, and certificates issued by unknown or untrusted CAs. Attackers install rogue CA certificates to intercept TLS traffic or to sign malicious code.

## ATT&CK Coverage

- T1553.004 — Subvert Trust Controls: Install Root Certificate
- T1557 — Adversary-in-the-Middle
- T1587.003 — Develop Capabilities: Digital Certificates

## Artifact

```yaml
name: Custom.Windows.Hunting.CertificateAnomalies
description: |
  Hunt for anomalous certificates in Windows certificate stores.
  Flags self-signed root CAs, untrusted issuers, weak keys,
  and expired certificates.

type: CLIENT

sources:
  - name: RootCACertificates
    description: All root CA certificates in the machine store
    query: |
      SELECT * FROM certificates(
        store="Root",
        storeLocation="LocalMachine"
      )

  - name: SelfSignedRootCAs
    description: Root CAs where Subject equals Issuer (self-signed)
    query: |
      SELECT Subject, Issuer, SerialNumber,
             NotBefore, NotAfter,
             KeyLength, SignatureAlgorithm,
             Thumbprint,
             if(condition=NotAfter < now(),
                then="EXPIRED", else="Active") AS Status,
             "Self-Signed Root CA" AS Finding
      FROM certificates(store="Root", storeLocation="LocalMachine")
      WHERE Subject = Issuer
        AND NOT Subject =~ "(?i)(Microsoft|DigiCert|VeriSign|Comodo|Let's Encrypt|GlobalSign|GoDaddy|Entrust|Sectigo|Baltimore|Thawte|GeoTrust|Starfield|Amazon|Apple|Google|USERTrust)"

  - name: WeakCertificates
    description: Certificates with weak key lengths
    query: |
      SELECT Subject, Issuer, KeyLength,
             SignatureAlgorithm, NotAfter,
             Thumbprint,
             "Weak Key" AS Finding
      FROM certificates(store="Root", storeLocation="LocalMachine")
      WHERE KeyLength < 2048
         OR SignatureAlgorithm =~ "(?i)(SHA1|MD5)"

  - name: RecentlyAdded
    description: Certificates added recently (last 30 days)
    query: |
      SELECT Subject, Issuer, NotBefore, NotAfter,
             KeyLength, Thumbprint,
             "Recently Added" AS Finding
      FROM certificates(store="Root", storeLocation="LocalMachine")
      WHERE NotBefore > now() - 2592000

  - name: PersonalCertificates
    description: Personal certificates (code signing, client auth)
    query: |
      SELECT Subject, Issuer, NotBefore, NotAfter,
             KeyLength, Thumbprint, EnhancedKeyUsage
      FROM certificates(store="My", storeLocation="CurrentUser")
```

## Why This Matters

A rogue root CA certificate in the trusted root store means an attacker can:
- Issue valid-looking certificates for any domain (MITM attacks)
- Sign malicious code that appears legitimate (code signing abuse)
- Decrypt TLS traffic if they control the network path

Any self-signed root CA not from a recognized vendor is a finding that needs explanation.

## Learn More

- [Entra ID Security — Certificate Management](https://training.ridgelinecyber.com/courses/entra-id-security/)
- [M365 Security Architecture — PKI and Certificate Trust](https://training.ridgelinecyber.com/courses/m365-security-architecture/)

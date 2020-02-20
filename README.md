OpenSSL C code to sign a certificate

<https://stackoverflow.com/questions/38949576/how-to-programmatically-create-a-certificate-signing-request-csr >

- root.key: CA's key
- ca.pem: CA's cert
- cert.key: user cert key, in PKCS#8 format, which means it has the algorithm type, option to encryption, etc
- cert.rsa: user cert raw key, in PKCS#1 format, key type is always RSA

## Generate a new key for a cert
```
openssl genrsa -out cert.rsa
openssl pkcs8 -topk8 -in cert.rsa -out cert.key -nocrypt
```


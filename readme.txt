https://stackoverflow.com/questions/38949576/how-to-programmatically-create-a-certificate-signing-request-csr 

root.key: CA's key
ca.pem: CA's cert
cert.key: user cert key, in PKCS#8 format, which means it has the algorithm type, option to encryption, etc
cert.rsa: user cert raw key, in PKCS#1 format, key type is always RSA




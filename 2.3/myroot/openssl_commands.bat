REM using Tutorial-10 slides

REM Generate myroot certificate and publicKey
REM openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:4096 -keyout myroot.key -out myroot.crt -subj "/C=CA/ST=Montreal/O=Assignment 2/CN=SOEN321"

REM Generate a 4096-bit RSA key in ca.key
openssl genrsa -aes256 SecureChat -out ca.key 4096 –aes256 SecureChat

REM Generate a self-signed x509v3 certificate valid for 20 years using SHA256 in ca.crt
openssl req -config openssl.cnf -key ca.key -new -x509 -days 7300 -sha256 -extensions v3_ca -out ca.crt -subj "/C=CA/ST=Montreal/ON=Concordia"


REM Generate leaf certificate

REM for Alice
openssl genrsa -aes256 alice -out alice.key 2048

REM Generate a Certificate Signing Request (CSR) in alice.csr using SHA256
openssl req -config openssl.cnf -key alice.key -new -sha256 -out alice.csr  -subj "/C=CA/ST=Montreal/ON=Concordia/CN=Alice"


REM for Bob
openssl genrsa -aes256 bob SecureChat -out bob.key 2048

REM Generate a Certificate Signing Request (CSR) in bob.csr using SHA256
openssl req -config openssl.cnf -key bob.key -new -sha256 -out bob.csr -subj "/C=CA/ST=Montreal/ON=Concordia/CN=Bob"


REM for Central server
openssl genrsa -aes256 server -out server.key 2048

REM Generate a Certificate Signing Request (CSR) in server.csr using SHA256
openssl req -config openssl.cnf -key server.key -new -sha256 -out server.csr -subj "/C=CA/ST=Montreal/ON=Concordia/CN=Server"
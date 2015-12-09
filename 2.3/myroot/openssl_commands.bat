REM using Tutorial-10 slides

REM Generate myroot certificate and publicKey
REM openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:4096 -keyout myroot.key -out myroot.crt -subj "/C=CA/ST=Montreal/O=Assignment 2/CN=SOEN321"

REM Generate a 4096-bit RSA key in ca.key
openssl genrsa -aes256 -out ca.key 4096
REM pwd chat
REM Generate a self-signed x509v3 certificate valid for 20 years using SHA256 in ca.crt
openssl req -config openssl.cnf -key ca.key -new -x509 -days 7300 -sha256 -extensions v3_ca -out ca.crt -subj "/C=CA/ST=Montreal/ON=Concordia/CN=MyRoot" 


REM Generate leaf certificate

REM for Alice
openssl genrsa -aes256 -out alice.key 2048

REM pwd alice

REM Generate a Certificate Signing Request (CSR) in alice.csr using SHA256
openssl req -config openssl.cnf -key alice.key -new -sha256 -out alice.csr  -subj "/C=CA/ST=Montreal/O=Concordia/CN=Alice"

openssl ca -config openssl.cnf -extensions usr_cert -days 365 -notext -md sha256 -in alice.csr -out alice.crt

REM for Bob
openssl genrsa -aes256 -out bob.key 2048
REM pwd bob
REM Generate a Certificate Signing Request (CSR) in bob.csr using SHA256
openssl req -config openssl.cnf -key bob.key -new -sha256 -out bob.csr -subj "/C=CA/ST=Montreal/O=Concordia/CN=Bob"

openssl ca -config openssl.cnf -extensions usr_cert -days 365 -notext -md sha256 -in bob.csr -out bob.crt

REM for Central server
openssl genrsa -aes256 -out server.key 2048
REM pwd server
REM Generate a Certificate Signing Request (CSR) in server.csr using SHA256
openssl req -config openssl.cnf -key server.key -new -sha256 -out server.csr -subj "/C=CA/ST=Montreal/O=Concordia/CN=Server"

openssl ca -config openssl.cnf -extensions server_cert -days 365 -notext -md sha256 -in server.csr -out server.crt

REM openssl pkcs8 -topk8 -in alice.key -out alice.pk8

REM pwd alice
REM openssl pkcs8 -topk8 -in bob.key -out bob.pk8
openssl pkcs8 -topk8 -inform PEM -outform DER -in alice.key -out alice.pk8 -nocrypt
REM pwd bobkey
REM openssl pkcs8 -topk8 -in server.key -out server.pk8
openssl pkcs8 -topk8 -inform PEM -outform DER -in bob.key -out bob.pk8 -nocrypt

REM pwd server
openssl pkcs8 -topk8 -inform PEM -outform DER -in server.key -out server.pk8 -nocrypt
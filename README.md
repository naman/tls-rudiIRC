# rudiIRC
An encrypted rudimentary IRC system for - CSE550 Network Security. The client-server software emulates an elementary IRC system which handles multiple clients. The clients can chat with another client or send a file easily. Additionally, all the conversations are encrypted using Public-Private Crypto using x509 certificates.

To install or test the software, see Install and Test section.

See the screenshot provided!

## Libraries
Posix threads library, fork()/exec(), socket io, OpenSSL

## Working Commands
`/cert`, `/tls`  

## Install and Test
Compile using the Makefile provided.

1. `make`
2. run `./server`
3. run multiple clients in different terminal windows/tabs using `./client`

## Assumptions

1. CA and intermediate CA keys/certs have been generated using openssl CLI ref https://jamielinux.com/docs/openssl-certificate-authority/. 

Server keys have also been setup using OpenSSL.

	Setting up server cert
	a. openssl genrsa -aes256 -out intermediate/pcrivate/server.key.pem 2048

	b. openssl req -config intermediate/openssl.conf -key intermediate/private/server.key.pem -new -sha256 -out intermediate/csr/server.csr.pem

	c. openssl ca -config intermediate/openssl.conf   -extensions server_cert -days 375 -notext -md sha256 -in intermediate/csr/server.csr.pem  -out intermediate/certs/server.cert.pem

	d.  chmod 444 intermediate/certs/server.cert.pem

2. User cert and csr are also generated using OpenSSL CLI (system()). Please type `/cert` if you are a new user (no previous certs).

3. No impersation of the certificate possible, since all client certs are being being signed by the Intermediate CA. Verification by both parties.

4. Clients converse/authenticate each other using x509 certs and the server which acts as an intermediary.

5. A modification is that the server connects the src and dst clients via 2 TLS connections (server relays the TLS encrypted packets to the dst). Mutual authentication is still taking place.  

## Attacks/Bugs/Errors (Corner Cases)
1. Prevents impersonation as client or a new client (using openssl s_client) cannot connect without a signed cert. Any adversary can't bruteforce or send fake packets.
2. Prevents impersonation of the Server or a new server (using openssl s_server) cannot connect without a signed cert. Any adversary can't bruteforce or send fake packets to act as the intermediary server.
3. An intermediate CA has been setup to prevent stealing of root CA's key, as CA's certs have been stored in a offline box (not present in the system, therefore no possibility of CA cert compromise).

References:

1. https://wiki.openssl.org/index.php/Simple_TLS_Server
2. https://wiki.openssl.org/index.php/SSL/TLS_Client
3. https://www.cs.utah.edu/~swalton/listings/articles/ssl_client.c
4. https://www.cs.utah.edu/~swalton/listings/articles/ssl_server.c
5. http://fm4dd.com/openssl/

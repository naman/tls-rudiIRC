#include <arpa/inet.h>
#include <asm-generic/errno-base.h>
#include <asm-generic/errno.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <pthread.h>
#include <resolv.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>


/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */
#define CERTF  HOME "safe/root/ca/intermediate/certs/server.cert.pem"
#define KEYF  HOME  "safe/root/ca/intermediate/private/server.key.pem"
#define CAfile HOME "safe/root/ca/intermediate/certs/intermediate.cert.pem"


/*Cipher list to be used*/
#define CIPHER_LIST "AES128-SHA"


#ifndef ALLOWED_CHAR_LENGTH
#define ALLOWED_CHAR_LENGTH 4096
#endif

#ifndef KEY_LEN
#define KEY_LEN 32 //BYTES
#endif

#ifndef BYTES_READ
#define BYTES_READ 512
#endif

#ifndef MAX_SIZE
#define MAX_SIZE 20000
#endif


void init_openssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
	EVP_cleanup();
}

SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

void configure_context(SSL_CTX *ctx)
{
	SSL_CTX_set_ecdh_auto(ctx, 1);

	if (SSL_CTX_use_certificate_file(ctx, "safe/root/ca/intermediate/certs/server.cert.pem", SSL_FILETYPE_PEM) < 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_default_passwd_cb_userdata(ctx, "server");

	if (SSL_CTX_use_PrivateKey_file(ctx, "safe/root/ca/intermediate/private/server.key.pem", SSL_FILETYPE_PEM) < 0 ) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}

void configure_client_context(SSL_CTX *ctx, char* username)
{
	printf("going in with %s\n", username);
	SSL_CTX_set_ecdh_auto(ctx, 1);

	char path_to_cert[ALLOWED_CHAR_LENGTH];
	strcpy(path_to_cert, "safe/root/ca/intermediate/certs/");
	strcat(path_to_cert, username);
	strcat(path_to_cert, ".cert.pem");

	char path_to_key[ALLOWED_CHAR_LENGTH];
	strcpy(path_to_key, "safe/root/ca/intermediate/private/");
	strcat(path_to_key, username);
	strcat(path_to_key, ".key.pem");

	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(ctx, path_to_cert, SSL_FILETYPE_PEM) < 0) {
		ERR_print_errors_fp(stderr);
		// exit(EXIT_FAILURE);
		printf("Please use /cert before /tls. \n");
	}

	/*Load the password for the Private Key*/
	SSL_CTX_set_default_passwd_cb_userdata(ctx, username);

	if (SSL_CTX_use_PrivateKey_file(ctx, path_to_key, SSL_FILETYPE_PEM) < 0 ) {
		ERR_print_errors_fp(stderr);
		// exit(EXIT_FAILURE);

		printf("Please use /cert before /tls. \n");
	}
}

char** splitline(char *line, char* delimiter) {
	int buffer = 64;
	int pos = 0;
	char **args = malloc(buffer * sizeof(char*));
	char *token;

	token = strtok(line, delimiter);
	while (token != NULL) {
		args[pos] = token;
		pos += 1;

		if (pos >= buffer) {
			buffer += buffer;
			args = realloc(args, buffer * sizeof(char*));
		}

		token = strtok(NULL, delimiter);
	}
	args[pos] = NULL;
	return args;
}


int recv_ssl_msg(char* username) {
	char path[ALLOWED_CHAR_LENGTH];
	strcpy(path, "texts/");
	strcat(path, username);

	FILE* file_pointer;
	file_pointer = fopen(path, "r");

	if (file_pointer == NULL) {
		errno = ECANCELED;
		printf("Can't access path %s\n", path);
		perror("Cannot open file!");
		return -1;
	}

	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	while ((read = getline(&line, &len, file_pointer)) != -1) {
		printf("%s\n", line);
	}

	if (line) {
		free(line);
	}

	fclose(file_pointer);

	remove(path);
	return 0;
}
int send_msg_ssl(char* username, char* dst_user, char* msg) {
	char path[ALLOWED_CHAR_LENGTH];
	strcpy(path, "texts/");
	strcat(path, dst_user);

	FILE* file_pointer;
	file_pointer = fopen(path, "w");

	if (file_pointer == NULL) {
		errno = ECANCELED;
		printf("Can't access path %s\n", path);
		perror("Cannot open file!");
		return -1;
	}

	char w[ALLOWED_CHAR_LENGTH];
	strcpy(w, username);
	strcat(w, " says (");
	strcat(w, msg);
	strcat(w, ")");

	char *usage = "Usage %s, [options] ... ";
	fprintf(file_pointer, w, usage);
	fclose(file_pointer);
	return 0;
}

int TLS_Server(int socket, char* username) {

	printf("Fill password for server!\n");
	SSL_CTX *ctx;

	init_openssl();
	ctx = create_context();

	configure_context(ctx);
	SSL *ssl;
	ssl = SSL_new(ctx);

	/*Set the Cipher List*/
	if (SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) <= 0) {
		printf("Error setting the cipher list.\n");
		exit(0);
	}

	SSL_set_fd(ssl, socket);

	printf("Verifying user cert!\n");

	char verify[ALLOWED_CHAR_LENGTH];
	strcpy(verify, "openssl verify -CAfile safe/root/ca/intermediate/certs/ca-chain.cert.pem safe/root/ca/intermediate/certs/");
	strcat(verify, username);
	strcat(verify, ".cert.pem");

	system(verify);

	printf("Verifying done!\n");
	printf("TLS serving\n");

	SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(CAfile));
	SSL_CTX_load_verify_locations(ctx, CAfile, NULL);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	X509 *cert = NULL;
	cert = SSL_get_peer_certificate(ssl);

	if (SSL_accept(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
	}


	printf("TLS is setup...\n");

	while (1) {
		char msg[ALLOWED_CHAR_LENGTH];
		int err = SSL_read (ssl, msg, sizeof(msg) - 1);
		msg[err] = '\0';

		if (strcmp(msg, "") == 0) break;
		else {
			char** line_break;
			line_break = splitline(msg, ":");
			printf ("to %s from %s: '%s'\n", line_break[0], username, line_break[1]);

			//relay to destn
			int rc = send_msg_ssl(username, line_break[0], line_break[1]);
			if (rc == 0)
			{
				printf("sent to destination\n");
			} else {
				printf("failed\n");
			}
		}

	}


	// BIO_printf(outbio, "Finished SSL/TLS connection with client: %s.\n", username);
	printf( "Finished SSL/TLS connection with client: %s.\n", username);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	cleanup_openssl();

}

int TLS_Client(int socket, char* username) {

	printf("Fill password for the client: %s!\n", username);

	char dest_url[] = "localhost";

	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();

	BIO  *certbio = NULL;
	BIO *outbio = NULL;
	certbio = BIO_new(BIO_s_file());
	outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);
	if (SSL_library_init() < 0)
		BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");

	const SSL_METHOD *method;
	method = SSLv23_client_method();
	
	SSL_CTX *ctx;
	if ( (ctx = SSL_CTX_new(method)) == NULL)
		BIO_printf(outbio, "Unable to create a new SSL context structure.\n");

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

	if (SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) <= 0) {
		printf("Error setting the cipher list.\n");
		exit(0);
	}

	SSL *ssl;
	ssl = SSL_new(ctx);

	//configure SSL context
	configure_client_context(ctx, username);

	SSL_set_fd(ssl, socket);

	if ( SSL_connect(ssl) != 1 )
		BIO_printf(outbio, "Error: Could not build a SSL session to: %s.\n", dest_url);
	else
		BIO_printf(outbio, "Successfully enabled SSL/TLS session to: %s.\n", dest_url);

	X509 *cert = NULL;
	cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL)
		BIO_printf(outbio, "Error: Could not get a certificate from: %s.\n", dest_url);
	else
		BIO_printf(outbio, "Retrieved the server's certificate from: %s.\n", dest_url);

	/**
	 * Verify
	 */
	char buff[ALLOWED_CHAR_LENGTH];
	X509_NAME_oneline(X509_get_subject_name(cert), buff, 256);
	X509_free(cert);

	printf("CERT: %s\n", buff);

	printf("Verifying server cert!\n");

	char verify[ALLOWED_CHAR_LENGTH];
	strcpy(verify, "openssl verify -CAfile safe/root/ca/intermediate/certs/ca-chain.cert.pem safe/root/ca/intermediate/certs/server.cert.pem");
	system(verify);

	printf("Verifying done!\n");

	printf("\n\nHit enter to receive messages!\n");

	printf("To: ");
	char dst_user[ALLOWED_CHAR_LENGTH];
	fgets(dst_user, ALLOWED_CHAR_LENGTH, stdin);
	strip_line_endings(dst_user);

	if (strcmp(dst_user, "") == 0 || strcmp(dst_user, username) == 0)
	{
		printf("Please start again by typing a valid username!\n");
	} else {

		while (1) {
			printf("Say *encr*: ");
			char msg[ALLOWED_CHAR_LENGTH];
			fgets(msg, ALLOWED_CHAR_LENGTH, stdin);
			strip_line_endings(msg);

			if (strcmp(msg, "") == 0)
			{
				printf("Receiving...\n");
				int rc = recv_ssl_msg(username);
			} else {
				char _msg[ALLOWED_CHAR_LENGTH];
				strcpy(_msg, dst_user);
				strcat(_msg, ":");
				strcat(_msg, msg);

				SSL_write (ssl, _msg, strlen(_msg));
			}
		}
	}

	SSL_free(ssl);
	SSL_CTX_free(ctx);
	BIO_printf(outbio, "Finished SSL/TLS connection with server: %s.\n", dest_url);
	return 0;
}


/* A 128 bit IV */
unsigned char *iv = (unsigned char *)"01234567890123456";

int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* plaintext) {

	EVP_CIPHER_CTX* ctx;

	int len;
	int plaintext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		ERR_print_errors_fp(stderr);

	// EVP_CIPHER_CTX_set_padding(&ctx, 0);

	/* Initialise the encryption operation.	AES encryption in CBC mode key length == 256 bit*/
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) //iv = ""
		ERR_print_errors_fp(stderr);

	/* Provide the encrypted message, and obtain the decrypted output.
	* EVP_DecryptUpdate can be called multiple times if necessary */
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		ERR_print_errors_fp(stderr);

	plaintext_len = len;

	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		ERR_print_errors_fp(stderr);

	plaintext_len += len;

	// BIO_dump_fp (stdout, (const char *)plaintext, plaintext_len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();

	return plaintext_len;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char* key, unsigned char* ciphertext) {

	EVP_CIPHER_CTX *ctx;

	int len;
	int ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		ERR_print_errors_fp(stderr);

	// EVP_CIPHER_CTX_set_padding(&ctx, 0);

	/*
		* Initialise the encryption operation. IMPORTANT - ensure you use a key
		* and IV size appropriate for your cipher
		* In this example we are using 256 bit AES (i.e. a 256 bit key). The
		* IV size for *most* modes is the same as the block size.
		* For AES this * is 128 bits
	*/

	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) //iv = ""
		ERR_print_errors_fp(stderr);

	/* Provide the message to be encrypted, and obtain the encrypted output. * EVP_EncryptUpdate can be
	called multiple times if necessary */

	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		ERR_print_errors_fp(stderr);

	ciphertext_len = len;

	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		ERR_print_errors_fp(stderr);

	ciphertext_len += len;

	// BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();

	return ciphertext_len;
}
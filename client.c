#include "helper.c"

extern int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* plaintext);
extern int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char* key, unsigned char* ciphertext);
extern int TLS_Client(int socket, char* username);

#ifndef PORT_X
#define PORT_X 8000
#endif

#ifndef PORT_Y
#define PORT_Y 8001
#endif

#ifndef V
#define V 1
#endif

typedef int bool;
#define true 1
#define false 0

pthread_t worker_threads[2];
char username[ALLOWED_CHAR_LENGTH];

int listenFlag = 0;

int random_generator(int limit) {
	srand(time(NULL));
	int r = rand() % limit;    //returns a pseudo-random integer between 0 and RAND_MAX
	return r;
}

void check_username_length(char* username) {
	if (strlen(username) >= 32) {
		errno = E2BIG;
		perror("Username has to be less than 32 bytes!");
	}
}

void check_path_length(char* path) {
	if (strlen(path) >= PATH_MAX) //4096 bytes
	{
		errno = E2BIG;
		perror("Path has to be less than 4096 bytes!");
	}
}

void check_file_length(char* filename) {
	if (strlen(filename) >= NAME_MAX) {
		errno = E2BIG;
		perror("Path has to be less than 255 bytes!");
	}
}

void sigproc() {
	signal(SIGQUIT, sigproc);
	printf(" Trap. Quitting.\n");
	//	pthread_exit(-1);
	raise(SIGINT);
	// kill(getpid(), SIGINT);
	exit(-1);
}

int file_exists(char *path) {
	struct stat st;
	int result = stat(path, &st);
	return result;
}

int file_size(char *path) {
	struct stat st;
	stat(path, &st);
	int size = st.st_size;
	return size;
}

void strip_line_endings(char* input) {
	/* strip of /r and /n chars to take care of Windows, Unix, OSx line endings. */
	input[strcspn(input, "\r\n")] = 0;
}

void resolve_path(char* path) {
	char resolved_path[ALLOWED_CHAR_LENGTH];
	realpath(path, resolved_path);
	strcpy(path, resolved_path);
}

void init(char* username) {
	printf("\n\n================== Authenticating.... ==================\n");

	sleep(1);

	system("clear");

	printf("================== Welcome to rudiIRC! ==================\n\n");

	char *wd = NULL;
	wd = getcwd(wd, ALLOWED_CHAR_LENGTH);
	check_path_length(wd);

	printf("Hello! You are at %s\n\n", wd);
}

int read_dstmsg(char* msg) {
	char path[ALLOWED_CHAR_LENGTH];
	strcpy(path, ".msg/.");
	strcat(path, username);

	FILE* file_pointer;
	file_pointer = fopen(path, "r");

	if (file_pointer == NULL) {
		return -1;
	}

	char buffer[ALLOWED_CHAR_LENGTH];
	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	int line_number = 0;

	int val = 0;
	while ((read = getline(&line, &len, file_pointer)) != -1) {
		strip_line_endings(line);
		if (line_number == 0) {
			val = atoi(line);
		} else if (line_number == 1) {
			strcpy(msg, line);
//			printf("%s\n", line);
		}
		line_number++;
	}

	if (line) {
		free(line);
	}
	fclose(file_pointer);
	return val;
}

int send_f(int socket, char* path, int size) {

	FILE * file_pointer;
	file_pointer = fopen(path, "rb");

	if (file_pointer == NULL) {
		errno = ECANCELED;
		printf("Can't access path %s\n", path);
		perror("Cannot open file!");
	}

	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	char result[MAX_SIZE];

	while ((read = getline(&line, &len, file_pointer)) != -1) {
		strcat(result, line);
	}

	if (line) {
		free(line);
	}

	fclose(file_pointer);

	printf("%s", result);
	send(socket, result, MAX_SIZE, 0);

	return 1;
}

int recv_f(int socket, char* filename, int size, char* dst_user) {

	char path[ALLOWED_CHAR_LENGTH];
	strcpy(path, "Downloads/");
	strcat(path, dst_user);
	strcat(path, "/");
	strcat(path, filename);

	FILE* file_pointer;
	file_pointer = fopen(path, "wb");

	if (file_pointer == NULL) {
		errno = ECANCELED;
		printf("Can't access path %s\n", path);
		perror("Cannot open file!");
		return -1;
	}

	strcpy(path, "");

	char file_buffer[MAX_SIZE];
	recv(socket, file_buffer, MAX_SIZE, 0);

	printf("recv \n");
	char *usage = "Usage %s, [options] ... ";
	fprintf(file_pointer, file_buffer, usage);

	fclose(file_pointer);
	return 1;
}

int send_file(int socket, char* path, int size) {

	if (file_exists(path) != 0) {
		errno = ECANCELED;
		printf("Can't access path %s\n", path);
		perror("Cannot open file!");
		return -1;
	}

	FILE* file_pointer;
	file_pointer = fopen(path, "rb");

	if (file_pointer == NULL) {
		printf("Can't access path %s\n", path);
		perror("Cannot open file!");
		return -1;
	}

	char buffer[BYTES_READ];

	int i = BYTES_READ;
	while (i <= size) {

		fread(buffer, sizeof(char), BYTES_READ, file_pointer);

		usleep(300);
		send(socket, buffer, BYTES_READ, 0);

		strcpy(buffer, "");
		i += BYTES_READ;

		fseek(file_pointer, i, SEEK_SET);
	}
	puts("");
	fclose(file_pointer);

	return 1;
}

int recv_file(int socket, char* filename, int size, char* dst_user) {

	char path[ALLOWED_CHAR_LENGTH];
	strcpy(path, "Downloads/");
	strcat(path, dst_user);
	strcat(path, "/");
	strcat(path, filename);

	FILE* file_pointer;
	file_pointer = fopen(path, "wb");

	if (file_pointer == NULL) {
		errno = ECANCELED;
		printf("Can't access path %s\n", path);
		perror("Cannot open file!");
		return -1;
	}

	strcpy(path, "");

	char file_buffer[ALLOWED_CHAR_LENGTH];
	char buffer[BYTES_READ];

	int i = BYTES_READ;
	while (i <= size) {

		usleep(300);
		recv(socket, buffer, BYTES_READ, 0);
		strcat(file_buffer, buffer);

		strcpy(buffer, "");
//		sleep(1);

		i += BYTES_READ;
	}

	printf("bu\n");
	char *usage = "Usage %s, [options] ... ";
	fprintf(file_pointer, file_buffer, usage);

	fclose(file_pointer);
	return 1;
}

void reset_dstmsg() {
	char path[ALLOWED_CHAR_LENGTH];
	strcpy(path, ".msg/.");
	strcat(path, username);

	FILE* file_pointer;
	file_pointer = fopen(path, "w+");

	if (file_pointer == NULL) {
		return;
	}

	char buffer[ALLOWED_CHAR_LENGTH];
	strcpy(buffer, "0\n\n");

	char *usage = "Usage %s, [options] ... ";
	fprintf(file_pointer, buffer, usage);

	fclose(file_pointer);
}

unsigned char Kab[ALLOWED_CHAR_LENGTH];
unsigned char encr_ticket[ALLOWED_CHAR_LENGTH];
int authenticated = 0;
int ticket_clen = 0;
int PLEN = 0;


void store_sessionkey(char* username) {
	char path[ALLOWED_CHAR_LENGTH];
	strcpy(path, ".keys/.");
	strcat(path, username);

	FILE* file_pointer;
	file_pointer = fopen(path, "w+");

	if (file_pointer == NULL) {
		return;
	}

	char buffer[ALLOWED_CHAR_LENGTH];
	// strcpy(buffer, Kab);

	char *usage = "Usage %s, [options] ... ";
	fprintf(file_pointer, Kab, usage);

	fclose(file_pointer);
}

int authenticate_alice(int socket) {

	printf("Listening...\n");

	printf("Recv ticket!\n");
	unsigned char encr_ticket[ALLOWED_CHAR_LENGTH];
	recv(socket, encr_ticket, ALLOWED_CHAR_LENGTH, 0);

	printf("Recv ticket len!\n");
	unsigned char t_clen[ALLOWED_CHAR_LENGTH];
	recv(socket, t_clen, ALLOWED_CHAR_LENGTH, 0);

	printf("Recv nonce2\n");
	unsigned char encr_nonce2[ALLOWED_CHAR_LENGTH];
	recv(socket, encr_nonce2, ALLOWED_CHAR_LENGTH, 0);

	printf("Recv nonce2 len!\n");
	unsigned char n2_clen[ALLOWED_CHAR_LENGTH];
	recv(socket, n2_clen, ALLOWED_CHAR_LENGTH, 0);

	int ticket_clen = atoi(t_clen);
	int nonce2_clen = atoi(n2_clen);

	unsigned char Kb[KEY_LEN];
	PKCS5_PBKDF2_HMAC_SHA1(username, strlen(username), NULL, 0, 1, KEY_LEN, Kb);

	printf("Decrypting ticket with Kb!\n");
	unsigned char ticket[ALLOWED_CHAR_LENGTH];
	PLEN = decrypt(encr_ticket, ticket_clen, Kb, ticket);

	char** line_break;
	line_break = splitline(ticket, "####");

	strcpy(Kab, line_break[0]);

	store_sessionkey(username);

	//Optional check for checking alice
	printf("Decrpyt nonce2 with Kab!\n");
	// unsigned char nonce2[ALLOWED_CHAR_LENGTH];
	// PLEN = decrypt(encr_nonce2, nonce2_clen, Kab, nonce2);

	// int n2 = atoi(nonce2);
	// unsigned char packet[ALLOWED_CHAR_LENGTH];
	// snprintf(packet, ALLOWED_CHAR_LENGTH, "%d", n2 - 1);

	printf("Generating nonce3!\n");
	// int n3 = random_generator(100);
	// unsigned char n3packet[ALLOWED_CHAR_LENGTH];
	// snprintf(n3packet, ALLOWED_CHAR_LENGTH, "%d", n3);

	// strcat(packet, "####");
	// strcat(packet, n3packet);

	printf("encrypting nonce2 + nonce3\n");
	// unsigned char encr_nonces[ALLOWED_CHAR_LENGTH];
	// int CLEN = encrypt(packet, strlen(packet), Kab, encr_nonces);

	// if (send(socket, encr_nonces, ALLOWED_CHAR_LENGTH, 0) < 0) {
	// 	printf("error\n");
	// }

	// char go[ALLOWED_CHAR_LENGTH];
	// recv(socket, go, ALLOWED_CHAR_LENGTH, 0);

	printf("Sending len of encrypted nonce2 + nonce3\n");
	// unsigned char nonces_clen[ALLOWED_CHAR_LENGTH];
	// snprintf(nonces_clen, ALLOWED_CHAR_LENGTH, "%d", CLEN);

	// printf("nonces_clen %d\n", CLEN);
	// if (send(socket, nonces_clen, ALLOWED_CHAR_LENGTH, 0) < 0) {
	// printf("error\n");
	// }

	// send(socket, "ok", ALLOWED_CHAR_LENGTH, 0);

	printf("Waiting for Alice!\n");
	// char go_ahead[ALLOWED_CHAR_LENGTH];

	// printf(".");
	// while (1) {
	// 	printf(".");
	// 	recv(socket, go_ahead, ALLOWED_CHAR_LENGTH, 0);
	// 	if (strcmp(go_ahead, "ok") == 0)
	// 		break;
	// 	else
	// 		strcpy(go_ahead, "");
	// }

	// printf("GOOO %s\n", go_ahead);

	printf("Receiving encr decremented nonce3\n");
	//hold up
	// unsigned char encr_nonce3_back[ALLOWED_CHAR_LENGTH];
	// recv(socket, encr_nonce3_back, ALLOWED_CHAR_LENGTH, 0);

	printf("Receiving encr decremented nonce3 len\n");
	// unsigned char encr_nonce3_back_clen[ALLOWED_CHAR_LENGTH];
	// recv(socket, encr_nonce3_back_clen, ALLOWED_CHAR_LENGTH, 0);

	// CLEN = atoi(encr_nonce3_back_clen);

	printf("Decrypting decremented nonce3 len\n");
	// unsigned char nonce3_back[ALLOWED_CHAR_LENGTH];
	// PLEN = decrypt(encr_nonce3_back, CLEN, Kab, nonce3_back);

	// int n3_ = atoi(nonce3_back);

	// if (n3_ + 1 != n3) {
	// printf("Some one is impersonating as Alice!");
	// return -1;
	// } else {
	printf("Alice is valid!\n");
	// }

	printf("Sending ok!\n");
	// send(socket, "ok", ALLOWED_CHAR_LENGTH, 0);

	printf("All done! Authenticated alice!\n");
	authenticated = 1;

	return 0;

}

void authenticate_bob(int socket) {

	store_sessionkey(username);
	printf("Authenticating bob...\n");
	int n2 = random_generator(100);

	unsigned char packet[ALLOWED_CHAR_LENGTH];
	snprintf(packet, ALLOWED_CHAR_LENGTH, "%d", n2);

	unsigned char encr_nonce2[ALLOWED_CHAR_LENGTH];
	int CLEN = encrypt(packet, strlen(packet), Kab, encr_nonce2);

	unsigned char nonce2_clen[ALLOWED_CHAR_LENGTH];
	snprintf(nonce2_clen, ALLOWED_CHAR_LENGTH, "%d", CLEN);

	unsigned char t_clen[ALLOWED_CHAR_LENGTH];
	snprintf(t_clen, ALLOWED_CHAR_LENGTH, "%d", ticket_clen);

	printf("Sending ticket and nonce2!\n");
	//send to server
	send(socket, encr_ticket, ALLOWED_CHAR_LENGTH, 0);
	send(socket, t_clen, ALLOWED_CHAR_LENGTH, 0);
	send(socket, encr_nonce2, ALLOWED_CHAR_LENGTH, 0);
	send(socket, nonce2_clen, ALLOWED_CHAR_LENGTH, 0);

	printf("Waiting for Bob!\n");
	/*char go_ahead[ALLOWED_CHAR_LENGTH];

	printf(".");
	while (1) {
		printf(".");
		recv(socket, go_ahead, ALLOWED_CHAR_LENGTH, 0);
		if (strcmp(go_ahead, "ok") == 0)
			break;
		else
			strcpy(go_ahead, "");
	}

	printf("GOOO %s\n", go_ahead);
	*/
	printf("Receiving encrypted nonces n2-1 and n3 from bob\n");
	// unsigned char encr_nonces[ALLOWED_CHAR_LENGTH];
	// recv(socket, encr_nonces, ALLOWED_CHAR_LENGTH, 0);

	printf("Receiving len of encrypted nonces n2-1 and n3 from bob\n");
	// unsigned char n_clen[ALLOWED_CHAR_LENGTH];
	// recv(socket, n_clen, ALLOWED_CHAR_LENGTH, 0);

	// int nonces_clen = atoi(n_clen);

	printf("Decrypting nonces n2-1 and n3 from bob\n");
	// unsigned char decr_nonces[ALLOWED_CHAR_LENGTH];
	// PLEN = decrypt(encr_nonces, nonces_clen, Kab, decr_nonces);

	// char** line_break;
	// line_break = splitline(decr_nonces, "####");

	// int n2_ = atoi(line_break[0]);

	// if (n2_ + 1 != n2) {
	// 	printf("Some one is impersonating as Bob!");
	// 	return;
	// } else {
	// 	printf("Bob is valid!\n");
	// }

	// int n3 = atoi(line_break[1]);

	// send(socket, "ok", ALLOWED_CHAR_LENGTH, 0);
	// unsigned char n3_decrement[ALLOWED_CHAR_LENGTH];
	// snprintf(n3_decrement, ALLOWED_CHAR_LENGTH, "%d", n3 - 1);

	// unsigned char encr_n3_decremented[ALLOWED_CHAR_LENGTH];
	// CLEN = encrypt(n3_decrement, strlen(n3_decrement), Kab, encr_n3_decremented);

	// unsigned char encr_n3_decremented_clen[ALLOWED_CHAR_LENGTH];
	// snprintf(encr_n3_decremented_clen, ALLOWED_CHAR_LENGTH, "%d", CLEN);

	printf("Sending ok\n");
	// send(socket, "ok", ALLOWED_CHAR_LENGTH, 0);

	printf("Sending decremented n3\n");
	// send(socket, encr_n3_decremented, ALLOWED_CHAR_LENGTH, 0);
	// send(socket, encr_n3_decremented_clen, ALLOWED_CHAR_LENGTH, 0);

	// unsigned char rc[ALLOWED_CHAR_LENGTH];
	// recv(socket, rc, ALLOWED_CHAR_LENGTH, 0);

	// printf("RC %s\n", rc);
	// if (strcmp(rc, "ok") == 0)
	// {
	authenticated = 1;
	/* code */
	// }
	printf("Authenticated Bob!\n");
}

int kdc_talk(int socket, char* username, char* dst_user) {

	int n1 = random_generator(100);
	uint32_t tmp = htonl(n1);
	send(socket, &tmp, sizeof(uint32_t), 0); //send to KDC
	send(socket, dst_user, ALLOWED_CHAR_LENGTH, 0); //send to KDC

	unsigned char t_clen[ALLOWED_CHAR_LENGTH];
	unsigned char p_clen[ALLOWED_CHAR_LENGTH];
	unsigned char enc_auth_init[ALLOWED_CHAR_LENGTH];

	recv(socket, t_clen, ALLOWED_CHAR_LENGTH, 0);
	recv(socket, p_clen, ALLOWED_CHAR_LENGTH, 0);
	recv(socket, enc_auth_init, ALLOWED_CHAR_LENGTH, 0);

	ticket_clen = atoi(t_clen);
	int packet_clen = atoi(p_clen);

	//decrypt using Ka
	unsigned char Ka[KEY_LEN];
	PKCS5_PBKDF2_HMAC_SHA1(username, strlen(username), NULL, 0, 1, KEY_LEN, Ka);
	// printf("Ka %s len %d\n", Ka, strlen(Ka));

	// strcpy(Ka, "123456789123456789123456789123456789");
	printf("Decrypting KDC response with Ka\n");
	unsigned char decrypted_response[ALLOWED_CHAR_LENGTH];
	PLEN = decrypt(enc_auth_init, packet_clen, Ka, decrypted_response);

	// printf("ENCR Packet len %d \n%s\n", strlen(enc_auth_init), enc_auth_init);

	printf("DECR successfully!\n");

	char** line_break;
	line_break = splitline(decrypted_response, "####");

	int n1_ = atoi(line_break[0]);
	printf("n1 %d and n1_ %d \n", n1, n1_);

	unsigned char dust_user[ALLOWED_CHAR_LENGTH];
	strcpy(dust_user, line_break[2]);
	printf("dust_user\n%s\n", dust_user);

	if ( n1_ != n1 || strcmp(dust_user, dst_user) != 0) {
		printf("Some one is impersonating as KDC!");
		return -1;
	} else {
		printf("Authenticated with KDC!\n");
	}

	strcpy(Kab, line_break[1]);
	// printf("sessionkey\n%s\n", Kab);
	strcpy(encr_ticket, line_break[3]);
	// printf("Encrypted ticket\n%s\n", encr_ticket);

	// unsigned char Kb[KEY_LEN];
	// PKCS5_PBKDF2_HMAC_SHA1(dst_user, strlen(dst_user), NULL, 0, 1, KEY_LEN, Kb);

	// unsigned char dec[ALLOWED_CHAR_LENGTH];
	// PLEN = decrypt(encr_ticket, ticket_clen, Kb, dec);

	// printf("DECREEEEE %s\n", dec);

	return 0;
}

void interface(char* username, int socket) {

	char m[ALLOWED_CHAR_LENGTH];
	if (read_dstmsg(m) == 1) {
		printf("Message: %s \n", m);
		strcpy(m, "\n");
		reset_dstmsg();
	}

	printf("$ ");

	char cmd[ALLOWED_CHAR_LENGTH];
	fgets(cmd, ALLOWED_CHAR_LENGTH, stdin);
	strip_line_endings(cmd);
	send(socket, cmd, ALLOWED_CHAR_LENGTH, 0);

	char success[ALLOWED_CHAR_LENGTH];
	recv(socket, success, ALLOWED_CHAR_LENGTH, 0);

	if (strcmp(success, "1") == 0) {
		// /who
		char result[ALLOWED_CHAR_LENGTH];
		recv(socket, result, ALLOWED_CHAR_LENGTH, 0);
		printf("%s", result);

	} else if (strcmp(success, "0") == 0) {
		// /auth

		/* Initialise the library */
		ERR_load_crypto_strings();
		OpenSSL_add_all_algorithms();
		OPENSSL_config(NULL);

		printf("Send to: ");
		char dst_user[ALLOWED_CHAR_LENGTH];
		fgets(dst_user, ALLOWED_CHAR_LENGTH, stdin);
		strip_line_endings(dst_user);

		if (strcmp(username, dst_user) == 0)
		{
			printf("bhaijan khud se baat karoge!\n");
		} else {

			int rc = kdc_talk(socket, username, dst_user);
			if (rc == 0) {
				authenticate_bob(socket);
			}
		}

	} else if (strcmp(success, "10") == 0) {
		authenticate_alice(socket);
	} else if (strcmp(success, "11") == 0) {

		// if (authenticated == 0) {
		// 	printf("No session key has been established yet!\nPlease type /auth to get one.\n");
		// } else {
			printf("Listening...\n");

			char message[ALLOWED_CHAR_LENGTH];
			recv(socket, message, ALLOWED_CHAR_LENGTH, 0);

			// unsigned char encrypted_message[ALLOWED_CHAR_LENGTH];
			// unsigned char encrypted_message_clen[ALLOWED_CHAR_LENGTH];
			// unsigned char message[ALLOWED_CHAR_LENGTH];
			// recv(socket, encrypted_message, ALLOWED_CHAR_LENGTH, 0);
			// recv(socket, encrypted_message_clen, ALLOWED_CHAR_LENGTH, 0);

			// int n = atoi(encrypted_message_clen);
			// int PLEN = decrypt(encrypted_message, n, Kab, message);

			// printf("Decrypting\n");
			printf("%s\n", message);
		// }
	} else if (strcmp(success, "2") == 0) {
		// /msg

		// if (strcmp(Kab, "") == 0) {
		// if (authenticated == 0) {
		// 	printf("No session key has been established yet!\nPlease type /auth to get one.\n");
		// } else {
			printf("To: ");
			char dst_user[ALLOWED_CHAR_LENGTH];
			fgets(dst_user, ALLOWED_CHAR_LENGTH, stdin);
			strip_line_endings(dst_user);

			send(socket, dst_user, ALLOWED_CHAR_LENGTH, 0);

			printf("Message: ");
			char msg[ALLOWED_CHAR_LENGTH];
			fgets(msg, ALLOWED_CHAR_LENGTH, stdin);
			strip_line_endings(msg);

			send(socket, msg, ALLOWED_CHAR_LENGTH, 0);

			// unsigned char encrypted_message[ALLOWED_CHAR_LENGTH];
			// int CLEN = encrypt(msg, strlen(msg), Kab, encrypted_message);

			// unsigned char n[ALLOWED_CHAR_LENGTH];
			// snprintf(n, ALLOWED_CHAR_LENGTH, "%d", CLEN);

			// send(socket, encrypted_message, ALLOWED_CHAR_LENGTH, 0);
			// send(socket, n, ALLOWED_CHAR_LENGTH, 0);
			// // send(socket, CLEN, ALLOWED_CHAR_LENGTH, 0);

			char rc[ALLOWED_CHAR_LENGTH];
			recv(socket, rc, ALLOWED_CHAR_LENGTH, 0);

			printf("rc %s\n", rc);
		// }

	} else if (strcmp(success, "3") == 0) {
		// /create_grp

		printf("Name of the group: ");
		char grp[ALLOWED_CHAR_LENGTH];
		fgets(grp, ALLOWED_CHAR_LENGTH, stdin);
		strip_line_endings(grp);

		send(socket, grp, ALLOWED_CHAR_LENGTH, 0);

		char rc[ALLOWED_CHAR_LENGTH];
		recv(socket, rc, ALLOWED_CHAR_LENGTH, 0);
		printf("result %s", rc);

	} else if (strcmp(success, "4") == 0) {
		// /join_grp

		printf("Name of the group: ");
		char grp[ALLOWED_CHAR_LENGTH];
		fgets(grp, ALLOWED_CHAR_LENGTH, stdin);
		strip_line_endings(grp);

		send(socket, grp, ALLOWED_CHAR_LENGTH, 0);

		char rc[ALLOWED_CHAR_LENGTH];
		recv(socket, rc, ALLOWED_CHAR_LENGTH, 0);
		printf("result %s", rc);

	} else if (strcmp(success, "5") == 0) {
		// /send

		printf("Send to: ");
		char user[ALLOWED_CHAR_LENGTH];
		fgets(user, ALLOWED_CHAR_LENGTH, stdin);
		strip_line_endings(user);
		send(socket, user, ALLOWED_CHAR_LENGTH, 0);

		printf("Filename: ");
		char filename[ALLOWED_CHAR_LENGTH];
		fgets(filename, ALLOWED_CHAR_LENGTH, stdin);
		strip_line_endings(filename);
		send(socket, filename, ALLOWED_CHAR_LENGTH, 0);

		int size = file_size(filename);
		send(socket, &size, sizeof(int), 0);

		if (V != 1) {
			send_file(socket, filename, size);
		} else {
			printf("Sending!\n");
			send_f(socket, filename, size);
		}
		char rc[ALLOWED_CHAR_LENGTH];
		recv(socket, rc, ALLOWED_CHAR_LENGTH, 0);
		printf("result %s\n", rc);

	} else if (strcmp(success, "6") == 0) {
		// /msg_grp

		printf("Message: ");
		char msg[ALLOWED_CHAR_LENGTH];
		fgets(msg, ALLOWED_CHAR_LENGTH, stdin);
		strip_line_endings(msg);

		send(socket, msg, ALLOWED_CHAR_LENGTH, 0);

		printf("Name of the group: ");
		char grp[ALLOWED_CHAR_LENGTH];
		fgets(grp, ALLOWED_CHAR_LENGTH, stdin);
		strip_line_endings(grp);

		send(socket, grp, ALLOWED_CHAR_LENGTH, 0);

		char rc[ALLOWED_CHAR_LENGTH];
		recv(socket, rc, ALLOWED_CHAR_LENGTH, 0);
		printf("result %s", rc);

	} else if (strcmp(success, "7") == 0) {
		// /recv
		printf("Receiving pending file ....\n");
		printf("Which file do you wan to receive?\n");

		char filename[ALLOWED_CHAR_LENGTH];
		fgets(filename, ALLOWED_CHAR_LENGTH, stdin);
		strip_line_endings(filename);

		send(socket, filename, ALLOWED_CHAR_LENGTH, 0);

		int size = file_size(filename);

		if (V != 1) {
			recv_file(socket, filename, size, username);
		} else {
			recv_f(socket, filename, size, username);
		}
	} else if (strcmp(success, "8") == 0) {
		// /cert
		
		char genrsa[50];
		strcpy(genrsa, "openssl genrsa -aes256 -out safe/root/ca/intermediate/private/" );
		strcat(genrsa, username);
		strcat(genrsa, ".key.pem 2048");


		char csr[50];
		strcpy(csr, "openssl req -config safe/root/ca/intermediate/openssl.conf -key safe/root/ca/intermediate/private/");
		strcat(csr, username);
		strcat(csr, ".key.pem -new -sha256 -out safe/root/ca/intermediate/csr/");
		strcat(csr, username);
		strcat(csr, ".csr.pem");


		char cert[50];
		strcpy(cert, "openssl ca -config safe/root/ca/intermediate/openssl.conf -extensions usr_cert -days 375 -notext -md sha256 -in safe/root/ca/intermediate/csr/" );
		strcat(cert, username);
		strcat(cert, ".csr.pem -out safe/root/ca/intermediate/certs/");
		strcat(cert, username);
		strcat(cert, ".cert.pem");


		char chmod[50];
		strcpy(chmod, "chmod 444 safe/root/ca/intermediate/certs/");
		strcat(chmod, username);
		strcat(chmod, ".cert.pem");

		printf("\nGenerating 2048bit private key for %s\n", username);
		system(genrsa);
	
		printf("Generating CSR for %s\n", username);
		system(csr);
		printf("Generating Cert for %s\n", username);
		system(cert);
		printf("Permissions for Cert for %s\n", username);
		system(chmod);

		printf("\nDONE!\n");
	} else if (strcmp(success, "9") == 0) {
		
		printf("Setting up SSL context\n");

		int rc = TLS_Client(socket, username);	
	
		printf("RC %d\n", rc);
	}
}

/*
 void *connection_handler1(void *connection_socket) {

 int* _socket = (int *) connection_socket;

 while (1) {
 interface(username, _socket);
 }

 return 0;
 }
 */

/*
 void *connection_handler(void *connection_socket) {

 int* _socket = (int *) connection_socket;
 // // where socketfd is the socket you want to make non-blocking
 // int status = fcntl(_socket, F_SETFL, fcntl(_socket, F_GETFL, 0) | O_NONBLOCK);
 //
 // if (status == -1){
 //   perror("calling fcntl");
 //   // handle the error.  By the way, I've never seen fcntl fail in this way
 // }

 char rc[ALLOWED_CHAR_LENGTH];
 while (1) {
 recv(_socket, rc, ALLOWED_CHAR_LENGTH, 0);
 printf("%s", rc);
 strcpy(rc, "");
 }
 return 0;
 }
 */

int main(int argc, char const * argv[]) {

// signal(SIGQUIT, sigproc);
	if (V != 1) {

		int client_socket_descriptor0;
		struct sockaddr_in server_address0;
		socklen_t address_size0;

		client_socket_descriptor0 = socket(PF_INET, SOCK_STREAM, 0);
		if (client_socket_descriptor0 == -1) {
			errno = EBADR;
			perror("Error creating socket!");
		} else {
			printf("socket initialized...\n");
		}

		server_address0.sin_family = AF_INET;
		server_address0.sin_addr.s_addr = inet_addr("127.0.0.1");
		server_address0.sin_port = htons(PORT_X);

		memset(server_address0.sin_zero, '\0',
		       sizeof(server_address0.sin_zero));
		address_size0 = sizeof(server_address0);

		if (connect(client_socket_descriptor0,
		            (struct sockaddr *) &server_address0, address_size0) < 0) {
			errno = ECONNREFUSED;
			perror("Error connecting to the server!\n");
			exit(-1);
		} else {
			printf("you are connected to the server...\n");
		}

		printf("Hello! Please enter your username to login.\n\n> ");
		fgets(username, ALLOWED_CHAR_LENGTH, stdin);
		strip_line_endings(username);

		printf("pw > ");
		char pw[ALLOWED_CHAR_LENGTH];
		fgets(pw, ALLOWED_CHAR_LENGTH, stdin);
		strip_line_endings(pw);

		check_username_length(username);

		if (send(client_socket_descriptor0, username, ALLOWED_CHAR_LENGTH, 0)
		        < 0) {
			perror("Send failed");
			exit(-1);
		}

		char success0[ALLOWED_CHAR_LENGTH];

		if (recv(client_socket_descriptor0, success0, ALLOWED_CHAR_LENGTH, 0)
		        < 0) {
			perror("Recv failed");
			exit(-1);
		}

		printf("You are %s\n", success0);
		close(client_socket_descriptor0);
	} else {
		printf("Phase 1 complete!\n");

		int client_socket_descriptor1;
		struct sockaddr_in server_address1;
		socklen_t address_size1;

		client_socket_descriptor1 = socket(PF_INET, SOCK_STREAM, 0);
		if (client_socket_descriptor1 == -1) {
			errno = EBADR;
			perror("Error creating socket!");
		} else {
			printf("socket initialized...\n");
		}

		server_address1.sin_family = AF_INET;
		server_address1.sin_addr.s_addr = inet_addr("127.0.0.1");
		server_address1.sin_port = htons(PORT_Y);

		memset(server_address1.sin_zero, '\0',
		       sizeof(server_address1.sin_zero));
		address_size1 = sizeof(server_address1);

		if (connect(client_socket_descriptor1,
		            (struct sockaddr *) &server_address1, address_size1) < 0) {
			errno = ECONNREFUSED;
			perror("Error connecting to the server!\n");
			exit(-1);
		} else {
			printf("you are connected to the server...\n");
		}

		printf("Hello! Please enter your username to login.\n> ");
		fgets(username, ALLOWED_CHAR_LENGTH, stdin);
		strip_line_endings(username);

		check_username_length(username);

		printf("Password: ");
		char pw[ALLOWED_CHAR_LENGTH];
		fgets(pw, ALLOWED_CHAR_LENGTH, stdin);
		strip_line_endings(pw);

		check_username_length(pw);

		if (strcmp(username, pw) != 0) {
			printf("wrong password!\n");
			exit(-1);
		}

		if (send(client_socket_descriptor1, username, ALLOWED_CHAR_LENGTH, 0)
		        < 0) {
			perror("Send failed");
			exit(-1);
		}

		char success0[ALLOWED_CHAR_LENGTH];

		if (recv(client_socket_descriptor1, success0, ALLOWED_CHAR_LENGTH, 0)
		        < 0) {
			perror("Recv failed");
			exit(-1);
		}

		printf("You are %s\n", success0);

		char success1[ALLOWED_CHAR_LENGTH];

		if (recv(client_socket_descriptor1, success1, ALLOWED_CHAR_LENGTH, 0)
		        < 0) {
			perror("Recv failed");
			exit(-1);
		}

		strip_line_endings(success1);

		if (strcmp(success1, "connected") == 0) {

			printf("You are %s\n", success1);

			init(username);

			while (1) {
				interface(username, client_socket_descriptor1);
			}
//		pthread_create(&worker_threads[0], NULL, connection_handler,
//				(void *) client_socket_descriptor1);
//
//		pthread_create(&worker_threads[1], NULL, connection_handler1,
//				(void *) client_socket_descriptor1);
//
//		pthread_join(worker_threads[0], NULL);
//
//		pthread_join(worker_threads[1], NULL);
		} else {
			errno = ECONNREFUSED;
			perror("Invalid username! Please try again!\n");
			exit(-1);
		}

		close(client_socket_descriptor1);
	}
	return 0;
}


#include "helper.c"

extern int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* plaintext);
extern int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char* key, unsigned char* ciphertext);
extern int TLS_Server(int socket, char* username);

#ifndef PORT_X
#define PORT_X 8000
#endif

#ifndef PORT_Y
#define PORT_Y 8001
#endif

#ifndef V
#define V 1
#endif

#define MAX_CONN 16 //max number of clients

typedef int bool;
#define true 1
#define false 0

pthread_t worker_threads[MAX_CONN] = { };
pthread_t worker_threads0[MAX_CONN] = { };

typedef struct {
	int socket_;
	char username[RTSIG_MAX + 1];
//int listenFlag;
} User;

User users[MAX_CONN];

static int user_id = 0;

User new_user(int socket_, char* username) {
	User a;
	a.socket_ = socket_;
//	a.listenFlag = 0;
	strcpy(a.username, username);
	return a;
}

void check_username_length(char* username) {
	if (strlen(username) >= RTSIG_MAX) {
		errno = E2BIG;
		perror("Username has to be less than 32 bytes!");
	}
}

int check_path_length(char* path) {
	if (strlen(path) >= PATH_MAX) //4096 bytes
	{
		errno = E2BIG;
		perror("Path has to be less than 4096 bytes!");
		return -1;
	}
	return 1;
}

void check_file_length(char* filename) {
	if (strlen(filename) >= NAME_MAX) {
		errno = E2BIG;
		perror("Path has to be less than 255 bytes!");
	}
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

void who(char* result) {

	char* path = ".logged_in";
	FILE * file_pointer;
	file_pointer = fopen(path, "r");

	if (file_pointer == NULL) {
		errno = ECANCELED;
		printf("Can't access path %s\n", path);
		perror("Cannot open file!");
	}

	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	// char result[ALLOWED_CHAR_LENGTH];
	strcpy(result, "Logged in users are: \n");

	while ((read = getline(&line, &len, file_pointer)) != -1) {
		// printf("%s", line);
		strcat(result, line);
	}

	if (line) {
		free(line);
	}

	fclose(file_pointer);

	printf(result);
	// return result;
}

int send_auth(char* username, char* dst_user, unsigned char* msg) {
	//	find socket for user
	int socket_dst = 0;
	for (int var = 0; var < MAX_CONN; ++var) {
		if (strcmp(users[var].username, dst_user) == 0) {
			// printf("TO %s\n", users[var].username);
			socket_dst = users[var].socket_;
			break;
		}
	}

	if (send(socket_dst, msg, ALLOWED_CHAR_LENGTH, 0) < 0) {
		printf("err");
		return 0;
	}

	return 1;
}


int send_msg(char* username, char* dst_user, char* msg) {

//	find socket for user
	int socket_dst = 0;
	for (int var = 0; var < MAX_CONN; ++var) {
		if (strcmp(users[var].username, dst_user) == 0) {
			printf("TO %s\n", users[var].username);
			socket_dst = users[var].socket_;
			break;
		}
	}

	if (send(socket_dst, msg, ALLOWED_CHAR_LENGTH, 0) < 0) {
		printf("err\n");
		return 0;
	}

	// if (change_dstmsg(dst_user, msg) == 1) {
	// 	printf("dst client may recv now\n");
	// } else {
	// 	printf("ERROR\n");
	// }
	return 1;
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

int create_group(char* grp, char* username) {
	char path[ALLOWED_CHAR_LENGTH];
	strcpy(path, ".groups/");
	strcat(path, grp);

	if (file_exists(path) == 0) {
		errno = ECANCELED;
		printf("Can't access path %s\n", path);
		perror("Cannot open file!");
		return -1;
	}

	FILE* file_pointer;
	file_pointer = fopen(path, "w");

	if (file_pointer == NULL) {
		errno = ECANCELED;
		printf("Can't access path %s\n", path);
		perror("Cannot open file!");
		return 0;
	}

	char username_[ALLOWED_CHAR_LENGTH];
	strcpy(username_, username);
	strcat(username_, "\n");

	char *usage = "Usage %s, [options] ... ";
	fprintf(file_pointer, username_, usage);
	fclose(file_pointer);

	return 1;
}

int join_group(char* grp, char* username) {
	char path[ALLOWED_CHAR_LENGTH];
	strcpy(path, ".groups/");
	strcat(path, grp);

	if (file_exists(path) != 0) {
		errno = ECANCELED;
		printf("Can't access path %s\n", path);
		perror("Cannot open file!");
		return 0;
	}

	FILE* file_pointer;
	file_pointer = fopen(path, "r");

	if (file_pointer == NULL) {
		errno = ECANCELED;
		printf("Can't access path %s\n", path);
		perror("Cannot open file!");
		return 0;
	}

	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	char result[ALLOWED_CHAR_LENGTH];
	strcpy(result, "username_Logged in users are: \n");

	bool flag = true;
	while ((read = getline(&line, &len, file_pointer)) != -1) {
		strip_line_endings(line);
		if (strcmp(username, line) == 0) {
			flag = false;
			break;
		}
	}

	if (line) {
		free(line);
	}

	fclose(file_pointer);

	if (flag == true) { //not in the group
		file_pointer = fopen(path, "a+");

		if (file_pointer == NULL) {
			errno = ECANCELED;
			printf("Can't access path %s\n", path);
			perror("Cannot open file!");
			return 0;
		}

		char username_[ALLOWED_CHAR_LENGTH];
		strcpy(username_, username);
		strcat(username_, "\n");
		char *usage = "Usage %s, [options] ... ";
		fprintf(file_pointer, username_, usage);

		fclose(file_pointer);
	} else {
		return -1;
	}

	return 1;
}

int msg_group(char* grp, char* username, char* msg) {
	char path[ALLOWED_CHAR_LENGTH];
	strcpy(path, ".groups/");
	strcat(path, grp);

	if (file_exists(path) != 0) {
		errno = ECANCELED;
		printf("Can't access path %s\n", path);
		perror("Cannot open file!");
		return 0;
	}

	FILE* file_pointer;
	file_pointer = fopen(path, "r");

	if (file_pointer == NULL) {
		errno = ECANCELED;
		printf("Can't access path %s\n", path);
		perror("Cannot open file!");
		return 0;
	}

	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	char result[ALLOWED_CHAR_LENGTH];
	strcpy(result, "username_Logged in users are: \n");

	while ((read = getline(&line, &len, file_pointer)) != -1) {
		strip_line_endings(line);

		if (send_msg(username, line, msg) != 1) {
			printf("failed for: %s\n", line);
			return 0;
		}
	}

	if (line) {
		free(line);
	}

	fclose(file_pointer);

	return 1;
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
//	strcpy(result, "Logged in users are: \n");

	while ((read = getline(&line, &len, file_pointer)) != -1) {
		// printf("%s", line);
		strcat(result, line);
	}

	if (line) {
		free(line);
	}

	fclose(file_pointer);

	send(socket, result, MAX_SIZE, 0);

	return 1;
}

int recv_f(int socket, char* filename, int size, char* dst_user) {

	char path[ALLOWED_CHAR_LENGTH];
	strcpy(path, ".files/");
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

	printf("%s", file_buffer);

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

//		printf("%s", buffer);
		strcpy(buffer, "");
//		sleep(1);

		i += BYTES_READ;

		fseek(file_pointer, i, SEEK_SET);
	}
	puts("");
	fclose(file_pointer);

	return 1;
}

int recv_file(int socket, char* filename, int size, char* dst_user) {

	char path[ALLOWED_CHAR_LENGTH];
	strcpy(path, ".files/");
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

	printf("Recieved \n");
	char *usage = "Usage %s, [options] ... ";
	fprintf(file_pointer, file_buffer, usage);

	fclose(file_pointer);
	return 1;
}

int change_dstmsg(char* username, char* msg) {
	char path[ALLOWED_CHAR_LENGTH];
	strcpy(path, ".msg/.");
	strcat(path, username);

	FILE* file_pointer;
	file_pointer = fopen(path, "w+");

	if (file_pointer == NULL) {
		errno = ECANCELED;
		printf("Can't access path %s\n", path);
		perror("Cannot open file!");
		return -1;
	}

	char buffer[ALLOWED_CHAR_LENGTH];
	strcpy(buffer, "1\n");
	strcat(buffer, msg);

	char *usage = "Usage %s, [options] ... ";
	fprintf(file_pointer, buffer, usage);

	fclose(file_pointer);
	return 1;
}

void send_to_dst(char* filename, char* username, int socket) {

	char path[ALLOWED_CHAR_LENGTH];
	strcpy(path, ".files/");
	strcat(path, username);
	strcat(path, "/");
	strcat(path, filename);

	int size = file_size(path);

	if (V != 1) {
		send_file(socket, path, size);
	} else {
		send_f(socket, path, size);
	}
}

int recv_auth_response(char* dst_user, unsigned char* dst_response) {

	//	find socket for user
	int socket_dst = 0;
	for (int var = 0; var < MAX_CONN; ++var) {
		if (strcmp(users[var].username, dst_user) == 0) {
			// printf("FROM %s\n", users[var].username);
			socket_dst = users[var].socket_;
			break;
		}
	}

	if (recv(socket_dst, dst_response, ALLOWED_CHAR_LENGTH, 0) < 0) {
		printf("err");
		return -1;
	}
	return 0;
}


int check_login(char* username) {

	FILE * file_pointer;
	file_pointer = fopen(".logged_in", "r");

	if (file_pointer == NULL) {
		errno = ECANCELED;
		perror("Cannot open file!");
	}

	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	int flag = 0;

	while ((read = getline(&line, &len, file_pointer)) != -1) {
		// printf("%s", line);
		// strcat(result, line);
		strip_line_endings(line);
		if (strcmp(line, username) == 0) {
			flag = 1;
			break;
		}
	}

	if (line) {
		free(line);
	}

	fclose(file_pointer);
	return flag;
}

void relay(char* username, char* dst_user, int socket) {

	int rc = check_login(dst_user);
	if (rc > 0) {
		//act as relay now
		//recv auth packet from alice, send to bob
		unsigned char encr_ticket[ALLOWED_CHAR_LENGTH];
		recv(socket, encr_ticket, ALLOWED_CHAR_LENGTH, 0);

		unsigned char t_clen[ALLOWED_CHAR_LENGTH];
		recv(socket, t_clen, ALLOWED_CHAR_LENGTH, 0);

		unsigned char encr_nonce2[ALLOWED_CHAR_LENGTH];
		recv(socket, encr_nonce2, ALLOWED_CHAR_LENGTH, 0);

		unsigned char nonce2_clen[ALLOWED_CHAR_LENGTH];
		recv(socket, nonce2_clen, ALLOWED_CHAR_LENGTH, 0);

		printf("Destination is logged in... continuing!\n");
		int rc1 = send_auth(username, dst_user, encr_ticket);
		int rc2 = send_auth(username, dst_user, t_clen);
		int rc3 = send_auth(username, dst_user, encr_nonce2);
		int rc4 = send_auth(username, dst_user, nonce2_clen);

		printf("%d %d %d %d\n", rc1, rc2, rc3, rc4);

		//RECV FROM BOB FOR N3
		printf("Receiving n3 from bob\n");
		// unsigned char encr_nonces[ALLOWED_CHAR_LENGTH];

		fflush(stdout);
		// int x1 = recv_auth_response(dst_user, encr_nonces);
		// printf("\nrecv %d\n", x1);

		// int rc10 = send_auth(username, dst_user, "ok");

		// unsigned char n3_clen[ALLOWED_CHAR_LENGTH];
		// int x2 = recv_auth_response(dst_user, n3_clen);

		// printf("\nrecv %d\n", x2);

		// printf("n3_clen %s\n", n3_clen);
		printf("Sending ok\n");

		/*		send(socket, "ok", ALLOWED_CHAR_LENGTH, 0);
				send(socket, "ok", ALLOWED_CHAR_LENGTH, 0);
				send(socket, "ok", ALLOWED_CHAR_LENGTH, 0);
		*/		// send(socket, "ok", ALLOWED_CHAR_LENGTH, 0);
		// printf("Sent ok\n");

		// send(socket, encr_nonces, ALLOWED_CHAR_LENGTH, 0);
		// send(socket, "16", ALLOWED_CHAR_LENGTH, 0);

		printf("Sending nonces done!\n");

		// unsigned char after_nonces[ALLOWED_CHAR_LENGTH];
		// recv_auth_response(dst_user, after_nonces);
		// unsigned char confirmation_from_alice[ALLOWED_CHAR_LENGTH];
		// recv(socket, confirmation_from_alice, ALLOWED_CHAR_LENGTH, 0);

		// send_auth(username, dst_user, "ok");

		// unsigned char encr_n3[ALLOWED_CHAR_LENGTH];
		// recv(socket, encr_n3, ALLOWED_CHAR_LENGTH, 0);

		// unsigned char encr_n3_clen[ALLOWED_CHAR_LENGTH];
		// recv(socket, encr_n3_clen, ALLOWED_CHAR_LENGTH, 0);

		// send_auth(username, dst_user, "ok");

		// int rc5 = send_auth(username, dst_user, encr_n3);
		// int rc6 = send_auth(username, dst_user, encr_n3_clen);

		// unsigned char rc[ALLOWED_CHAR_LENGTH];
		// int x3 = recv_auth_response(dst_user, rc);

		// send(socket, "ok", ALLOWED_CHAR_LENGTH, 0);

		printf("DONE!\n");
	} else {
		printf("please ensure dst client is loggedin!\n");
	}
}


void handle_command(char* command, char* username, int socket) {

	if (strcmp(command, "/who") == 0) {
		send(socket, "1", ALLOWED_CHAR_LENGTH, 0);

		char result[ALLOWED_CHAR_LENGTH];
		who(result);
		send(socket, result, ALLOWED_CHAR_LENGTH, 0);

	} else if (strcmp(command, "/auth") == 0) {
		send(socket, "0", ALLOWED_CHAR_LENGTH, 0);

		/* Initialise the library */
		ERR_load_crypto_strings();
		OpenSSL_add_all_algorithms();
		OPENSSL_config(NULL);

		int tmp = 0;
		recv(socket, &tmp, sizeof(tmp), 0);
		int n1 = ntohl(tmp);

		char dst_user[ALLOWED_CHAR_LENGTH];
		recv(socket, dst_user, ALLOWED_CHAR_LENGTH, 0);

		char join[ALLOWED_CHAR_LENGTH];
		strcpy(join, username);
		strcat(join, dst_user);

		unsigned char Kab[KEY_LEN];
		PKCS5_PBKDF2_HMAC_SHA1(join, strlen(join), NULL, 0, 1, KEY_LEN, Kab);

		unsigned char Kb[KEY_LEN];
		PKCS5_PBKDF2_HMAC_SHA1(dst_user, strlen(dst_user), NULL, 0, 1, KEY_LEN, Kb);

		unsigned char Ka[KEY_LEN];
		PKCS5_PBKDF2_HMAC_SHA1(username, strlen(username), NULL, 0, 1, KEY_LEN, Ka);


		// fflush(stdout);
		// printf("Ka %s len %d\n", Ka, strlen(Ka));
		unsigned char ticket[ALLOWED_CHAR_LENGTH];
		unsigned char encr_ticket[ALLOWED_CHAR_LENGTH];
		strcpy(ticket, Kab);
		strcat(ticket, "####");
		strcat(ticket, username);

		int ticket_clen = 0;
		int packet_clen = 0;
		unsigned char p_clen[ALLOWED_CHAR_LENGTH];
		unsigned char t_clen[ALLOWED_CHAR_LENGTH];
		// printf("Ticket len %d\n", strlen(ticket));

		ticket_clen = encrypt(ticket, strlen(ticket), Kb, encr_ticket);
		snprintf(t_clen, ALLOWED_CHAR_LENGTH, "%d", ticket_clen);

		printf("\nEncrypted ticket\n%s\n", encr_ticket);

		printf("\nKab\n%s\n", Kab);


		unsigned char p1[ALLOWED_CHAR_LENGTH];
		snprintf(p1, ALLOWED_CHAR_LENGTH, "%d", n1);

		unsigned char packet[ALLOWED_CHAR_LENGTH];
		strcpy(packet, "####");
		strcat(packet, p1);
		strcat(packet, "####");
		strcat(packet, Kab);
		strcat(packet, "####");
		strcat(packet, dst_user);
		strcat(packet, "####");
		strcat(packet, encr_ticket);
		strcat(packet, "####");
		// strcat(packet, "abcdabcdabcd");

		unsigned char encrypted_response[ALLOWED_CHAR_LENGTH];
		packet_clen = encrypt(packet, strlen(packet), Ka, encrypted_response);
		snprintf(p_clen, ALLOWED_CHAR_LENGTH, "%d", packet_clen);
		// printf("\nENCR Packet (kdc) CLEN %s %s\n", p_clen, encrypted_response);

		send(socket, t_clen, ALLOWED_CHAR_LENGTH, 0);
		send(socket, p_clen, ALLOWED_CHAR_LENGTH, 0);
		send(socket, encrypted_response, ALLOWED_CHAR_LENGTH, 0);

		printf("Act as relay now!\n");
		//act as relay now
		//recv auth packet from alice, send to bob
		relay(username, dst_user, socket);

		//type /auth_reply on dst_client

	} else if (strcmp(command, "/msg_reply") == 0) {
		send(socket, "11", ALLOWED_CHAR_LENGTH, 0);

	} else if (strcmp(command, "/auth_reply") == 0) {
		send(socket, "10", ALLOWED_CHAR_LENGTH, 0);

	} else if (strcmp(command, "/msg") == 0) {
		send(socket, "2", ALLOWED_CHAR_LENGTH, 0);

		char dst_user[ALLOWED_CHAR_LENGTH];
		recv(socket, dst_user, ALLOWED_CHAR_LENGTH, 0);

		char msg[ALLOWED_CHAR_LENGTH];
		recv(socket, msg, ALLOWED_CHAR_LENGTH, 0);

		// unsigned char enc_msg[ALLOWED_CHAR_LENGTH];
		// recv(socket, enc_msg, ALLOWED_CHAR_LENGTH, 0);

		// unsigned char enc_msg_clen[ALLOWED_CHAR_LENGTH];
		// recv(socket, enc_msg_clen, ALLOWED_CHAR_LENGTH, 0);

		// int x = send_auth(username, dst_user, enc_msg);
		// int x2 = send_auth(username, dst_user, enc_msg_clen);

		if (send_msg(username, dst_user, msg) != 1) {
			printf("failed for: %s\n", dst_user);
		} else {
			send(socket, "sent", ALLOWED_CHAR_LENGTH, 0);
		}


	} else if (strcmp(command, "/create_grp") == 0) {

		send(socket, "3", ALLOWED_CHAR_LENGTH, 0);

		char grp[ALLOWED_CHAR_LENGTH];
		recv(socket, grp, ALLOWED_CHAR_LENGTH, 0);

		int rc = create_group(grp, username);
		if (rc == 1) {
			printf("joined");
			send(socket, "group created!\n", ALLOWED_CHAR_LENGTH, 0);
		} else if (rc == 0) {
			printf("failed");
			send(socket, "group not created!\n", ALLOWED_CHAR_LENGTH, 0);
		} else if (rc == -1) {
			printf("already exists");
			send(socket, "group already exists!\n", ALLOWED_CHAR_LENGTH, 0);
		}

	} else if (strcmp(command, "/join_grp") == 0) {
		send(socket, "4", ALLOWED_CHAR_LENGTH, 0);

		char grp[ALLOWED_CHAR_LENGTH];
		recv(socket, grp, ALLOWED_CHAR_LENGTH, 0);

		int rc = join_group(grp, username);
		if (rc == 1) {
			printf("joined");
			send(socket, "group joined!\n", ALLOWED_CHAR_LENGTH, 0);
		} else if (rc == 0) {
			printf("group doesn't exist");
			send(socket, "group doesn't exist!\n", ALLOWED_CHAR_LENGTH, 0);
		} else if (rc == -1) {
			printf("already");
			send(socket, "already in group!\n",
			     ALLOWED_CHAR_LENGTH, 0);
		}

	} else if (strcmp(command, "/send") == 0) {
		send(socket, "5", ALLOWED_CHAR_LENGTH, 0);

		char dst_user[ALLOWED_CHAR_LENGTH];
		recv(socket, dst_user, ALLOWED_CHAR_LENGTH, 0);

		char filename[ALLOWED_CHAR_LENGTH];
		recv(socket, filename, ALLOWED_CHAR_LENGTH, 0);

		int size = 0;
		recv(socket, &size, sizeof(int), 0);
		printf("SIZE %d\n", size);

		int rc;

		if (V != 1) {
			rc = recv_file(socket, filename, size, dst_user);
		} else {
			rc = recv_f(socket, filename, size, dst_user);
		}

		if (rc == 1) {
			printf("recvd\n");
			send(socket, "recvd", ALLOWED_CHAR_LENGTH, 0);
		} else {
			printf("failed\n");
			send(socket, "failed", ALLOWED_CHAR_LENGTH, 0);
		}

	} else if (strcmp(command, "/msg_grp") == 0) {
		send(socket, "6", ALLOWED_CHAR_LENGTH, 0);

		char msg[ALLOWED_CHAR_LENGTH];
		recv(socket, msg, ALLOWED_CHAR_LENGTH, 0);
//		printf("Message is %s\n", msg);

		char grp[ALLOWED_CHAR_LENGTH];
		recv(socket, grp, ALLOWED_CHAR_LENGTH, 0);

		int rc = msg_group(grp, username, msg);
		if (rc == 1) {
			printf("sent");
			send(socket, "messages sent!\n", ALLOWED_CHAR_LENGTH, 0);
		} else if (rc == 0) {
			printf("failed");
			send(socket, "messages not sent! :(\n", ALLOWED_CHAR_LENGTH, 0);
		}
//		else if (rc == -1) {
//			printf("already exists");
//			send(socket, "group already exists!\n", ALLOWED_CHAR_LENGTH, 0);
//		}
	} else if (strcmp(command, "/recv") == 0) {
		send(socket, "7", ALLOWED_CHAR_LENGTH, 0);

		char filename[ALLOWED_CHAR_LENGTH];
		recv(socket, filename, ALLOWED_CHAR_LENGTH, 0);

		send_to_dst(filename, username, socket);

	} else if (strcmp(command, "/cert") == 0) {
		send(socket, "8", ALLOWED_CHAR_LENGTH, 0);

	} else if (strcmp(command, "/tls") == 0) {
		send(socket, "9", ALLOWED_CHAR_LENGTH, 0);

		//setup a SSL server context
		int rc = TLS_Server(socket, username);
	} else {
		send(socket, "-1", ALLOWED_CHAR_LENGTH, 0);
		perror("Command not supported!\n");
	}

}

void create_env(int socket, char* username) {

	while (1) {

		pid_t pid;
		pid = fork(); //clones, parent gets child-id, child gets 0

		if (pid < 0) {
			errno = EACCES;
			perror("Fork Failed");

		} else if (pid == 0) {

			// child - execute command here
			char command[ALLOWED_CHAR_LENGTH];
			recv(socket, command, ALLOWED_CHAR_LENGTH, 0);

			handle_command(command, username, socket);
			close(socket);

			fflush(stdout);
			exit(1);
		} else if (pid > 0) {
			// parent
			waitpid(pid, NULL, 0);
		}
	}
}

void sigproc() {
	signal(SIGINT, sigproc);
	printf(" Trapped. Try Ctrl + \\ to quit.\n");
}

void quitproc() {
	printf(" Quitting! \n");
	remove(".logged_in");
	remove(".groups");
	remove(".msg");
	exit(0);
}

int sanity_check(char* username) {

	FILE * file_pointer;
	file_pointer = fopen(".allowed_users", "r");

	if (file_pointer == NULL) {
		errno = EBADF;
		perror("Error while opening the file.\n");
		return -1;
	}

	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	int return_val = -1;
	while ((read = getline(&line, &len, file_pointer)) != -1) {
		strip_line_endings(line);
		if (strcmp(line, username) == 0) {
			return_val = 1;
			break;
		}
	}

	if (line) {
		free(line);
	}
	fclose(file_pointer);

	return return_val;
}

void register_user(char* username) {

	FILE * file_pointer;
	file_pointer = fopen(".allowed_users", "a+");

	if (file_pointer == NULL) {
		errno = ECANCELED;
		printf("Can't access path .allowed_users \n");
		perror("Cannot open file!");
		return;
	}

	char *usage = "Usage %s, [options] ... ";
	fprintf(file_pointer, username, usage);

	fclose(file_pointer);
}

void register_login(char* username) {
	char* path = ".logged_in";
	FILE * file_pointer;
	file_pointer = fopen(path, "r");

	if (file_pointer == NULL) {
		errno = ECANCELED;
		printf("Can't access path %s\n", path);
		perror("Cannot open file!");

	}

	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	char result[ALLOWED_CHAR_LENGTH];
	strcpy(result, "username_Logged in users are: \n");

	bool flag = true;
	while ((read = getline(&line, &len, file_pointer)) != -1) {
		strip_line_endings(line);
		if (strcmp(username, line) == 0) {
			flag = false;
			break;
		}
	}

	if (line) {
		free(line);
	}

	fclose(file_pointer);

	if (flag == true) {
		file_pointer = fopen(path, "a+");

		if (file_pointer == NULL) {
			errno = ECANCELED;
			printf("Can't access path %s\n", path);
			perror("Cannot open file!");
		}

		char username_[ALLOWED_CHAR_LENGTH];
		strcpy(username_, username);
		strcat(username_, "\n");
		char *usage = "Usage %s, [options] ... ";
		fprintf(file_pointer, username_, usage);

		fclose(file_pointer);
	}
}

bool already_login(char* username) {
	char* path = ".logged_in";
	FILE * file_pointer;
	file_pointer = fopen(path, "r");

	if (file_pointer == NULL) {
		errno = ECANCELED;
		printf("Can't access path %s\n", path);
		perror("Cannot open file!");
	}

	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	char result[ALLOWED_CHAR_LENGTH];
	strcpy(result, "Logged in users are: \n");

	bool flag = true;
	while ((read = getline(&line, &len, file_pointer)) != -1) {
		strip_line_endings(line);
		if (strcmp(username, line) == 0) {
			flag = false;
			break;
		}
	}

	if (line) {
		free(line);
	}

	fclose(file_pointer);

	return flag;
}

static void *connection_handler0(void *connection_socket) {

	printf("Handling new connection!\n");

	int* _socket = (int *) connection_socket;

	char username[ALLOWED_CHAR_LENGTH];
	if (recv(_socket, username, ALLOWED_CHAR_LENGTH, 0) < 0) {
		perror("RECV failed");
		exit(-1);
	}

	if (sanity_check(username) != 1) {
		printf("%s registered! \n", username);
		register_user(username);
		if (send(_socket, "registered", ALLOWED_CHAR_LENGTH, 0) < 0) {
			perror("Send failed");
			exit(-1);
		}
	} else {
		printf("Welcome back, you are already registered.\n");

		if (send(_socket, "connected", ALLOWED_CHAR_LENGTH, 0) < 0) {
			perror("Send failed");
			exit(-1);
		}
	}

	close(_socket);

//	fflush(stdout);
//	return NULL;
	return 0;
}

void *connection_handler(void *connection_socket) {

	printf("Handling new connection!\n");

	int* _socket = (int *) connection_socket;

	char username[ALLOWED_CHAR_LENGTH];
	if (recv(_socket, username, ALLOWED_CHAR_LENGTH, 0) < 0) {
		perror("RECV failed");
		exit(-1);
	}

	if (sanity_check(username) != 1) {
		printf("%s registered! \n", username);
		register_user(username);
		if (send(_socket, "registered", ALLOWED_CHAR_LENGTH, 0) < 0) {
			perror("Send failed");
			exit(-1);
		}
	} else {
		printf("Welcome back, you are already registered.\n");

		if (send(_socket, "connected", ALLOWED_CHAR_LENGTH, 0) < 0) {
			perror("Send failed");
			exit(-1);
		}
	}

	if (sanity_check(username) == 1 && already_login(username) == true) {
//	if (sanity_check(username) == 1 #### already_login(username) == true) {

		printf("%s connected.\n", username);
		if (send(_socket, "connected", ALLOWED_CHAR_LENGTH, 0) < 0) {
			perror("Send failed");
			exit(-1);
		}

		register_login(username);
		User new = new_user(_socket, username);
		users[user_id] = new;

		create_env(_socket, username);

		close(_socket);

	} else {
		//terminate connection here
		printf("Invalid username!\n");
		send(_socket, "disconnected", ALLOWED_CHAR_LENGTH, 0);
	}

	return 0;
}

int main(int argc, char const *argv[]) {

	signal(SIGINT, sigproc);
	signal(SIGQUIT, quitproc);

	if (V != 1) {

		int server_socket_descriptor0 = socket(PF_INET, SOCK_STREAM, 0);
		if (server_socket_descriptor0 < 0) {
			errno = EBADR;
			perror("Error creating socket!\n");
			exit(-1);
		}

		struct sockaddr_in server_address0;

		server_address0.sin_family = AF_INET;
		server_address0.sin_addr.s_addr = inet_addr("127.0.0.1");
		server_address0.sin_port = htons(PORT_X);

		memset(server_address0.sin_zero, '\0',
		       sizeof(server_address0.sin_zero));

		if (bind(server_socket_descriptor0,
		         (struct sockaddr *) &server_address0, sizeof(server_address0))
		        < 0) {
			errno = EBADRQC;
			perror("Bind Failed!");
			exit(-1);
		}

		if (listen(server_socket_descriptor0, MAX_CONN) < 0) {
			errno = ENETRESET;
			perror("Error!");
			exit(-1);
		}

		int s;

		for (int thread_number = 0; thread_number < MAX_CONN; thread_number++) {

			struct sockaddr_in client_address0;
			socklen_t address_size0 = sizeof(client_address0);

			int connection_descriptor0 = accept(server_socket_descriptor0,
			                                    (struct sockaddr *) &client_address0, &address_size0);

			if (connection_descriptor0 < 0) {
				errno = EACCES;
				perror("Unable to connect!");
				exit(-1);
			}

			printf("A new client has connected.\n");
			user_id++;

			s = pthread_create(&worker_threads0[thread_number], NULL,
			                   &connection_handler0, (void *) connection_descriptor0);
			if (s != 0) {
				printf("Unable to create!");
				return -1;
			}
			/*
			 sleep(2);
			 pthread_cancel(worker_threads0[thread_number]);
			 printf("asdsad!\n");
			 */

		}

		for (int thread_number = 0; thread_number < MAX_CONN; thread_number++)
			pthread_join(worker_threads0[thread_number], NULL);

	} else {

		sleep(1);

		////////////////////////////////////////////////////////////////
		int server_socket_descriptor1 = socket(PF_INET, SOCK_STREAM, 0);
		if (server_socket_descriptor1 < 0) {
			errno = EBADR;
			perror("Error creating socket!\n");
			exit(-1);
		}

		struct sockaddr_in server_address1;

		server_address1.sin_family = AF_INET;
		server_address1.sin_addr.s_addr = inet_addr("127.0.0.1");
		server_address1.sin_port = htons(PORT_Y);

		memset(server_address1.sin_zero, '\0',
		       sizeof(server_address1.sin_zero));

		if (bind(server_socket_descriptor1,
		         (struct sockaddr *) &server_address1, sizeof(server_address1))
		        < 0) {
			errno = EBADRQC;
			perror("Bind Failed!");
			exit(-1);
		}

		if (listen(server_socket_descriptor1, MAX_CONN) < 0) {
			errno = ENETRESET;
			perror("Error!");
			exit(-1);
		}

		for (int thread_number = 0; thread_number < MAX_CONN; thread_number++) {

			struct sockaddr_in client_address1;
			socklen_t address_size1 = sizeof(client_address1);

			int connection_descriptor1 = accept(server_socket_descriptor1,
			                                    (struct sockaddr *) &client_address1, &address_size1);

			if (connection_descriptor1 < 0) {
				errno = EACCES;
				perror("Unable to connect!");
				exit(-1);
			}

			printf("Listening...\n");
			printf("A new client has connected.\n");
			user_id++;
			pthread_create(&worker_threads[thread_number], NULL,
			               connection_handler, (void *) connection_descriptor1);
		}

		for (int thread_number = 0; thread_number < MAX_CONN; thread_number++)
			pthread_join(worker_threads[thread_number], NULL);
	}

	return 0;
}

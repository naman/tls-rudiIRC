all:
	touch .logged_in
	touch texts/user1
	touch texts/user2
	mkdir -p texts
	gcc client.c -o client -lm -lssl -lpthread -lcrypto -g -w
	gcc server.c -o server -lm -lssl -lpthread -lcrypto -g -w

clean:
	rm client server

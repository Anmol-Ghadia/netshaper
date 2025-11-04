#include "Client.h"
#include <cstring>
#include <sys/un.h>
#include <thread>
#include <fcntl.h>
#include <errno.h>

namespace TCP {

    Client::Client(const std::string &remoteHost, int remotePort,
            std::function<void(Client *, uint8_t *, size_t, connectionStatus)> onReceiveFunc,
            logLevels level)
        : remoteHost(remoteHost), remotePort(remotePort), logLevel(level), onReceive(onReceiveFunc) {

            remoteSocket = connectToRemote();
            if (remoteSocket < 0) {
                log(ERROR, "Failed to connect to remote Unix socket.");
                return;
            }

            log(DEBUG, "Connected to Unix domain socket: " + remoteHost);

            // Start receiving data in a separate thread
            std::thread([this]() { startReceiving(); }).detach();
        }

    Client::~Client() {
        if (remoteSocket != -1) {
            close(remoteSocket);
        }
    }

    ssize_t Client::sendData(uint8_t *buffer, size_t length) {
        ssize_t bytesSent = send(remoteSocket, buffer, length, 0);
        if (bytesSent < 0) {
            log(ERROR, "Send failed: " + std::string(strerror(errno)));
        }
        return bytesSent;
    }

    int Client::connectToRemote() {
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
            log(ERROR, "Socket creation failed: " + std::string(strerror(errno)));
            return CLIENT_SOCKET_ERROR;
        }

        sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;

        // Use the remoteHost as the Unix socket path
        strncpy(addr.sun_path, remoteHost.c_str(), sizeof(addr.sun_path) - 1);

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            log(ERROR, "Connect failed: " + std::string(strerror(errno)));
            close(sock);
            return CLIENT_CONNECT_ERROR;
        }

        return sock;
    }

    void Client::startReceiving() {
        uint8_t buffer[BUF_SIZE];

        while (true) {
            ssize_t bytesRead = recv(remoteSocket, buffer, sizeof(buffer), 0);
            if (bytesRead > 0) {
                onReceive(this, buffer, bytesRead, connectionStatus::ONGOING);
            } else if (bytesRead == 0) {
                log(DEBUG, "Connection closed by peer.");
                onReceive(this, buffer, 0, connectionStatus::FIN);
                break;
            } else {
                log(ERROR, "Receive failed: " + std::string(strerror(errno)));
                onReceive(this, buffer, 0, connectionStatus::FIN);
                break;
            }
        }

        close(remoteSocket);
        remoteSocket = -1;
    }

    void Client::log(logLevels level, const std::string &message) {
        if (level <= logLevel) {
            switch (level) {
                case ERROR:
                    std::cerr << "[ERROR] " << message << std::endl;
                    break;
                case WARNING:
                    std::cerr << "[WARNING] " << message << std::endl;
                    break;
                case DEBUG:
                    std::cout << "[DEBUG] " << message << std::endl;
                    break;
            }
        }
    }

} // namespace TCP


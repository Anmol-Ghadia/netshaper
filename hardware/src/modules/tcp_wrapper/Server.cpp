#include "Server.h"
#include <sys/un.h>
#include <cstring>
#include <csignal>
#include <fcntl.h>

namespace TCP {

    static const char *SOCKET_PATH = "/tmp/minesvpn.sock";

    Server::Server(std::string bindAddr, int localPort,
            std::function<bool(int, std::string &, uint8_t *, size_t, connectionStatus)> onReceiveFunc,
            logLevels level)
        : bindAddr(std::move(bindAddr)),
        localPort(localPort),
        localSocket(-1),
        logLevel(level),
        onReceive(std::move(onReceiveFunc)) {}

    Server::~Server() {
        if (localSocket != -1) {
            close(localSocket);
        }
        unlink(SOCKET_PATH);
    }

    void Server::log(logLevels level, const std::string &logMsg) {
        if (level <= logLevel) {
            std::cerr << "[Server] " << logMsg << std::endl;
        }
    }

    int Server::openSocket() {
        localSocket = socket(AF_UNIX, SOCK_STREAM, 0);
        if (localSocket < 0) {
            log(ERROR, "Failed to create UNIX socket");
            return SERVER_SOCKET_ERROR;
        }

        sockaddr_un addr{};
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
        unlink(SOCKET_PATH); // Ensure previous socket file is removed

        if (bind(localSocket, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
            log(ERROR, "Bind failed on UNIX socket");
            return SERVER_BIND_ERROR;
        }

        if (listen(localSocket, BACKLOG) < 0) {
            log(ERROR, "Listen failed on UNIX socket");
            return SERVER_LISTEN_ERROR;
        }

        log(DEBUG, "Socket successfully created and listening on UNIX domain socket");
        return localSocket;
    }

    void Server::startListening() {
        if (openSocket() < 0) {
            throw std::runtime_error("Failed to start UNIX domain socket server");
        }
        serverLoop();
    }

    [[noreturn]] void Server::serverLoop() {
        log(DEBUG, "Server loop started...");

        while (true) {
            sockaddr_un clientAddr{};
            socklen_t clientLen = sizeof(clientAddr);
            int clientSocket = accept(localSocket, reinterpret_cast<sockaddr *>(&clientAddr), &clientLen);
            if (clientSocket < 0) {
                log(ERROR, "Failed to accept client connection");
                continue;
            }

            std::string clientName = clientAddr.sun_path;  // Typically empty, but for consistency
            log(DEBUG, "Accepted connection");

            handleClient(clientSocket, clientName);
        }
    }

    void Server::handleClient(int clientSocket, std::string clientAddress) {
        receiveData(clientSocket, clientAddress);
        close(clientSocket);
        log(DEBUG, "Client disconnected");
    }

    void Server::receiveData(int socket, std::string &clientAddress) {
        uint8_t buffer[BUF_SIZE];
        ssize_t bytesRead;

        while ((bytesRead = recv(socket, buffer, BUF_SIZE, 0)) > 0) {
            bool keepConnection = onReceive(socket, clientAddress, buffer, bytesRead, ONGOING);
            if (!keepConnection) {
                log(DEBUG, "Client requested disconnect");
                break;
            }
        }

        onReceive(socket, clientAddress, buffer, 0, FIN);
    }

    ssize_t Server::sendData(int toSocket, uint8_t *buffer, size_t length) {
        return send(toSocket, buffer, length, 0);
    }

    int Server::checkIPVersion(const std::string &) {
        return AF_UNIX; // Not used in UNIX socket implementation
    }

    std::string Server::getAddress(struct sockaddr &sockAddr) {
        auto *addr = reinterpret_cast<sockaddr_un *>(&sockAddr);
        return std::string(addr->sun_path);
    }
}


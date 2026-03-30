//
// Created by Rut Vora
//

#include <stdexcept>
#include <iostream>
#include <sstream>
#include <utility>
#include <ctime>
#include <iomanip>
#include "Server.h"


#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>

//#define LOG_BUF_SIZE (1024 * 512)
#define MAX_LOG_COUNT 600
#define LOG_PATH "/tmp/quicserver-serverwrapper.log"
static struct timespec* log_buf = (struct timespec*)malloc(sizeof(struct timespec) * (MAX_LOG_COUNT + 10));
static size_t* len_buf = (size_t*)malloc(sizeof(size_t) * (MAX_LOG_COUNT + 10));
static size_t next_i = 0;
//static size_t log_off = 0;
//static size_t log_count = 0;

namespace QUIC {
  void Server::log(logLevels level, const std::string &log) {
    auto time = std::time(nullptr);
    auto localTime = std::localtime(&time);
    std::string levelStr;
    switch (level) {
      case DEBUG:
        levelStr = "QuicServer:DEBUG: ";
        break;
      case ERROR:
        levelStr = "QuicServer:ERROR: ";
        break;
      case WARNING:
        levelStr = "QuicServer:WARNING: ";
        break;

    }
    if (logLevel >= level) {
      std::cerr << std::put_time(localTime, "[%H:%M:%S] ") << levelStr
                << log << std::endl;
    }
  }

  QUIC_STATUS Server::streamCallbackHandler(MsQuicStream *stream,
                                            void *context,
                                            QUIC_STREAM_EVENT *event) {
    auto *server = reinterpret_cast<Server *>(context);

    const void *streamPtr = static_cast<const void *>(stream);
    std::stringstream ss;
    ss << "[Stream] " << streamPtr << " ";
    switch (event->Type) {
      case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        stream->Shutdown(0);
        ss << "shut down as peer aborted";
        server->log(WARNING, ss.str());
        break;

      case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //Send a FIN
        stream->Send(nullptr, 0, QUIC_SEND_FLAG_FIN, nullptr);
        ss << "shut down as peer sent a shutdown signal";
        server->log(WARNING, ss.str());
        break;

      case QUIC_STREAM_EVENT_RECEIVE: {
        auto bufferCount = event->RECEIVE.BufferCount;
#ifdef DEBUGGING
        ss << "Received data from peer: ";
#endif
        for (uint32_t i = 0; i < bufferCount; i++) {
          server->onReceive(stream, event->RECEIVE.Buffers[i].Buffer,
                            event->RECEIVE.Buffers[i].Length);
#ifdef DEBUGGING
          auto length = event->RECEIVE.Buffers[i].Length;
          ss << " \n\t Length: " << length;
        }
        server->log(DEBUG, ss.str());
#else
        }
#endif
      }
        break;

      case QUIC_STREAM_EVENT_SEND_COMPLETE: {
        ctx *contextPtr =
            reinterpret_cast<ctx *>(event->SEND_COMPLETE.ClientContext);
        free(contextPtr->buffer->Buffer); // The data that was sent
        free(contextPtr->buffer); // The QUIC_BUFFER struct
        free(contextPtr); // The ctx struct
      }
#ifdef DEBUGGING
        ss << "Finished a call to streamSend";
        server->log(DEBUG, ss.str());
#endif
        break;

      case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //Automatically handled as cleanUpAutoDelete is set when creating the
        // stream class instance in connectionHandler
        ss << "The stream was shutdown and cleaned up successfully";
        server->log(WARNING, ss.str());
      default:
        break;
    }
    return QUIC_STATUS_SUCCESS;

  }

  QUIC_STATUS Server::connectionHandler(MsQuicConnection *connection,
                                        void *context,
                                        QUIC_CONNECTION_EVENT *event) {
    auto *server = reinterpret_cast<Server *>(context);
    MsQuicStream *stream;
    std::stringstream ss;
    const void *connectionPtr = static_cast<const void *>(connection);
    ss << "[Connection] " << connectionPtr << " ";

    switch (event->Type) {
      case QUIC_CONNECTION_EVENT_CONNECTED:
        // The handshake has completed for the connection.
#ifdef DEBUGGING
        ss << "Connected";
        server->log(DEBUG, ss.str());
#endif
        connection->SendResumptionTicket();
        break;

      case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        stream = new MsQuicStream(event->PEER_STREAM_STARTED.Stream,
                                  CleanUpAutoDelete,
                                  streamCallbackHandler, context);
#ifdef DEBUGGING
        {
          const void *streamPtr = static_cast<const void *>(stream);
          ss << "Stream " << streamPtr << " started";
          server->log(DEBUG, ss.str());
        }
#endif
        break;

      case QUIC_CONNECTION_EVENT_RESUMED:
#ifdef DEBUGGING
        ss << "resumed";
        server->log(DEBUG, ss.str());
#endif
        break;

      case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        connection->Close();
        ss << "closed successfully";
        server->log(WARNING, ss.str());
        break;

      case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        ss << "shut down by peer";
        server->log(WARNING, ss.str());
        break;

      case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        if (event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status ==
            QUIC_STATUS_CONNECTION_IDLE) {
#ifdef DEBUGGING
          ss << "shutting down on idle";
          server->log(DEBUG, ss.str());
#endif
        } else {
          ss << "shut down by underlying transport layer";
          server->log(WARNING, ss.str());
        }
        break;

      default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
  }

  bool Server::loadConfiguration(const std::string &certFile,
                                 const std::string &keyFile) {
    // The settings for the QUIC Connection
    auto *settings = new MsQuicSettings;
    settings->SetSendBufferingEnabled(false);
    settings->SetPacingEnabled(false);
    settings->SetKeepAlive(idleTimeoutMs / 2);
    settings->SetIdleTimeoutMs(idleTimeoutMs);
    settings->SetServerResumptionLevel(QUIC_SERVER_RESUME_AND_ZERORTT);


    settings->SetPeerBidiStreamCount(maxPeerStreams);

    // Load the X509 certificate
    QUIC_CREDENTIAL_CONFIG config{};
    QUIC_CERTIFICATE_FILE certificateFileStruct;
    config.CertificateFile = &certificateFileStruct;
    config.CertificateFile->CertificateFile = certFile.c_str();
    config.CertificateFile->PrivateKeyFile = keyFile.c_str();
    config.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;


    MsQuicCredentialConfig credConfig(config);

    configuration = new MsQuicConfiguration(*reg, alpn, *settings,
                                            credConfig);
    delete settings;
    if (configuration->IsValid()) {
#ifdef DEBUGGING
      log(DEBUG, "Configuration loaded successfully!");
#endif
      return true;
    }
    log(ERROR, "Error loading configuration. Are you sure the correct server "
               "certificate and keyfile are provided?");
    return false;
  }

  Server::Server(const std::string &certFile, const std::string &keyFile,
                 int port, std::function<void(MsQuicStream *stream,
                                              uint8_t *buffer,
                                              size_t length)> onReceiveFunc,
                 logLevels level, int maxPeerStreams, uint64_t
                 idleTimeoutMs) : configuration(nullptr),
                                  listener(nullptr),
                                  addr(new QuicAddr(
                                      QUIC_ADDRESS_FAMILY_UNSPEC)),
                                  maxPeerStreams(maxPeerStreams) {
    reg = new MsQuicRegistration{appName.c_str(), profile, autoCleanup};
    this->idleTimeoutMs = idleTimeoutMs;
    this->logLevel = level;
    onReceive = std::move(onReceiveFunc);
#ifdef DEBUGGING
    log(DEBUG, "Loading Configuration...");
#endif
    bool success = loadConfiguration(certFile, keyFile);
    if (!success) {
      exit(1);
    }
    addr->SetPort(port);
#ifdef DEBUGGING
    {
      std::stringstream ss;
      ss << (alpn.operator const QUIC_BUFFER *())[0].Buffer;
      log(DEBUG, "ALPN: " + ss.str());
    }
    log(DEBUG, "Port: " + std::to_string(port));
#endif
  }

  void Server::startListening() {
    // Open the QUIC Listener (Server) for the given application and register
    // a listenerCallback function that is called for all events
    if (listener != nullptr) {
      log(WARNING, "startListening called on a server that's already "
                   "listening");
      return;
    }

    listener = new MsQuicAutoAcceptListener(*reg, *configuration,
                                            this->connectionHandler, this);
    listener->Start(alpn, &addr->SockAddr);
#ifdef DEBUGGING
    log(DEBUG, "Started listening");
#endif
  }

  void Server::stopListening() {
    delete listener;
    listener = nullptr;
#ifdef DEBUGGING
    log(DEBUG, "Stopped listening");
#endif
  }

  bool Server::send(MsQuicStream *stream, uint8_t *data, size_t length) {
    auto SendBuffer =
        reinterpret_cast<QUIC_BUFFER *>(malloc(sizeof(QUIC_BUFFER)));
    if (SendBuffer == nullptr) {
      return false;
    }

    SendBuffer->Buffer = data;
    SendBuffer->Length = length;

    ctx *context = reinterpret_cast<ctx *>(malloc(sizeof(ctx)));
    context->buffer = SendBuffer;

    // =======
    if (length >= 50) {
	    struct timespec *ts = &log_buf[next_i];
	    len_buf[next_i] = length;
	    clock_gettime(CLOCK_MONOTONIC_RAW, ts);
	    next_i += 1;
    }
    /*
    int len = snprintf
		    log_buf + log_off,
		    LOG_BUF_SIZE - log_off,
		    "%lld.%09ld %ld\n",
		    (long long)ts.tv_sec,
		    ts.tv_nsec,
		    length
		    );
		    */


    if (next_i >= MAX_LOG_COUNT) {
	    // add seperator
	    /*
	    len = snprintf(
			    log_buf + log_off,
			    LOG_BUF_SIZE - log_off,
			    "===\n=== Core Id: %d\n===\n",
			    sched_getcpu()
			  );

	    if (len > 0 && (size_t)len < LOG_BUF_SIZE - log_off) {
		    log_off += len;
		    log_count += 1;
	    }
			  */
	    // write to file
	    int fd = open(
			    LOG_PATH,
			    O_WRONLY | O_CREAT | O_APPEND,
			    0644
			 );
	    if (fd < 0) {
		    perror("open");
		    return QUIC_STATUS_SUCCESS;
	    }

	    char line[128];

	    for (int i = 0; i < MAX_LOG_COUNT; i++) {
		    struct timespec *ts = &log_buf[i];
		    size_t pkt_len = len_buf[i];
		    int len = snprintf(
				    line,
				    sizeof(line),
				    "%lld.%09ld,%ld\n",
				    (long long)ts->tv_sec,
				    ts->tv_nsec,
				    pkt_len
				    );

		    if (write(fd, line, len) != len) {
			    perror("write");
			    break;
		    }
	    }

	    int len = snprintf(
			    line,
			    sizeof(line),
			    "===\n=== Core Id: %d\n===\n",
			    sched_getcpu()
			    );

	    if (write(fd, line, len) != len) {
		    perror("write");
	    }

	    close(fd);

	    next_i = 0;
	    //    if (fd < 0) {
	    //          Status = QUIC_STATUS_SUCCESS;
	    //          return Status;
	    //    }
	    //
	    //
	    //
	    //    close(fd);
	    /*
	    size_t total = 0;

	    while (total < log_off) {
		    ssize_t n = write(fd, log_buf + total, log_off - total);
		    if (n <= 0) {
			    break;
		    }
		    total += (size_t)n;
	    }

	    close(fd);
	    log_off = 0;
	    log_count = 0;
	    */
    }


    // =====
    if (QUIC_FAILED(
        stream->Send(SendBuffer, 1, QUIC_SEND_FLAG_NONE, context))) {
      std::stringstream ss;
      ss << "[Stream " << stream->ID() << "] ";
      ss << " could not send data";
      log(ERROR, ss.str());
      free(SendBuffer);
      return false;
    }
    return true;
  }
}

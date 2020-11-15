/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4; fill-column: 100 -*- */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#pragma once

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "Common.hpp"
#include "Socket.hpp"
#include "Log.hpp"
#include "Util.hpp"

namespace Poco
{
    class MemoryInputStream;
    namespace Net
    {
        class HTTPRequest;
        class HTTPResponse;
    }
    class URI;
}

/// A client socket to make asynchronous HTTP requests.
class HttpRequest final : ProtocolHandlerInterface
{
public:
    HttpRequest(const std::string& host, const std::string& port, bool secure)
        : _host(host)
        , _port(port)
        , _secure(secure)
    {
    }

    HttpRequest(const std::string& host, const int port, bool secure)
        : HttpRequest(host, std::to_string(port), secure)
    {
    }

    const std::string& host() const { return _host; }
    const std::string& port() const { return _port; }
    bool secure() const { return _secure; }

    void asyncGet(const std::string&, SocketPoll& poll)
    {
        poll.insertNewSocket(_socket);
    }

    void onConnect(const std::shared_ptr<StreamSocket>& socket) override
    {
        // _socket = socket;
        LOG_TRC('#' << socket->getFD() << " Connected.");
    }

    void shutdown(bool /*goingAway*/, const std::string &/*statusMessage*/) override
    {
        // shutdown(goingAway ? WebSocketHandler::StatusCodes::ENDPOINT_GOING_AWAY :
        //          WebSocketHandler::StatusCodes::NORMAL_CLOSE, statusMessage);
    }

    void getIOStats(uint64_t &sent, uint64_t &recv) override
    {
        // std::shared_ptr<StreamSocket> socket = getSocket().lock();
        // if (socket)
        //     socket->getIOStats(sent, recv);
        // else
        {
            sent = 0;
            recv = 0;
        }
    }

    virtual void handleIncomingMessage(SocketDisposition&) override
    {
//         std::shared_ptr<StreamSocket> socket = _socket.lock();

// #if MOBILEAPP
//         // No separate "upgrade" is going on
//         if (socket && !socket->isWebSocket())
//             socket->setWebSocket();
// #endif

//         if (!socket)
//         {
//             LOG_ERR("No socket associated with WebSocketHandler " << this);
//         }
// #if !MOBILEAPP
//         else if (_isClient && !socket->isWebSocket())
//             handleClientUpgrade(socket);
// #endif
//         else
//         {
//             while (socket->processInputEnabled() && handleTCPStream(socket))
//                 ; // might have multiple messages in the accumulated buffer.
//         }
    }

    int getPollEvents(std::chrono::steady_clock::time_point /*now*/,
                      int64_t & /*timeoutMaxMicroS*/) override
    {
        int events = POLLIN;
        // if (_msgHandler && _msgHandler->hasQueuedMessages())
        //     events |= POLLOUT;
        return events;
    }

    /// Do we need to handle a timeout ?
    void checkTimeout(std::chrono::steady_clock::time_point) override {}

public:
    void performWrites() override
    {
        // if (_msgHandler)
        //     _msgHandler->writeQueuedMessages();
    }

    void onDisconnect() override
    {
        // if (_msgHandler)
        //     _msgHandler->onDisconnect();
    }

    // const std::shared_ptr<ProtocolHandlerInterface>& websocketHandler)
    // static std::shared_ptr<StreamSocket> connect(const std::string& host, const std::string& port,
    //                                              bool isSSL);

private:
    int sendTextMessage(const char*, const size_t, bool) const override { return 0; }

    int sendBinaryMessage(const char*, const size_t, bool) const override { return 0; }

private:
    const std::string _host;
    const std::string _port;
    const bool _secure;
    std::shared_ptr<StreamSocket> _socket;
};

#if 0
inline bool HttpRequest::connect()
{
    LOG_DBG("Connecting to " << _host << " : " << _port << " (" << (_secure ? "SSL" : "plain")
                             << ")");

    // FIXME: store the address?
    struct addrinfo* ainfo = nullptr;
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    const int rc = getaddrinfo(_host.c_str(), _port.c_str(), &hints, &ainfo);

#if !ENABLE_SSL
    if (_secure)
    {
        LOG_ERR("Error: wss for client websocket requested but SSL not compiled in.");
        return false;
    }
#endif

    std::string canonicalName;
    if (!rc && ainfo)
    {
        for (struct addrinfo* ai = ainfo; ai; ai = ai->ai_next)
        {
            if (ai->ai_canonname)
                canonicalName = ai->ai_canonname;

            if (ai->ai_addrlen && ai->ai_addr)
            {
                int fd = ::socket(ai->ai_addr->sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
                int res = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
                if (fd < 0 || (res < 0 && errno != EINPROGRESS))
                {
                    LOG_ERR("Failed to connect to " << _host);
                    ::close(fd);
                }
                else
                {
#if ENABLE_SSL
                    if (_secure)
                        _socket = StreamSocket::create<SslStreamSocket>(fd, true, websocketHandler);
#endif
                    // if (!_socket && !_secure)
                    //     _socket = StreamSocket::create<StreamSocket>(fd, true, websocketHandler);

                    if (_socket)
                        break;

                    LOG_ERR("Failed to allocate socket for client websocket " << _host);
                    ::close(fd);
                    break;
                }
            }
        }

        freeaddrinfo(ainfo);
    }
    else
        LOG_ERR("Failed to lookup client websocket host [" << _host << "] skipping");

    return _socket != nullptr;
}
#endif

/* vim:set shiftwidth=4 softtabstop=4 expandtab: */

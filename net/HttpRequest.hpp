/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4; fill-column: 100 -*- */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#pragma once

#include <sstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "Common.hpp"
#include <net/Socket.hpp>
#if ENABLE_SSL
#  include <net/SslSocket.hpp>
#endif
#include "Log.hpp"
#include "Util.hpp"

namespace Poco
{
class MemoryInputStream;
namespace Net
{
class HTTPRequest;
class HTTPResponse;
} // namespace Net
class URI;
} // namespace Poco

/// An HTTP Header.
class HttpHeader
{
public:
    /// Set an HTTP header entry.
    void set(const std::string& key, const std::string& value)
    {
        _headers.emplace_back(key, value);
    }

    /// Serialize the header to an output stream.
    template <typename T> T& serialize(T& os) const
    {
        for (const auto& pair : _headers)
        {
            os << pair.first << ": " << pair.second << "\r\n";
        }

        return os;
    }

    std::string toString() const
    {
        std::ostringstream oss;
        return serialize(oss).str();
    }

private:
    /// The headers are ordered key/value pairs.
    /// This isn't designed for lookup performance, but to preserve order.
    std::vector<std::pair<std::string, std::string>> _headers;
};

/// An HTTP Request made over HttpSession.
class HttpRequest final
{
public:
    static constexpr const char* VERB_GET = "GET";
    static constexpr const char* VERB_POST = "POST";
    static constexpr const char* VERS_1_1 = "HTTP/1.1";

    HttpRequest(const std::string& url, const std::string& verb = VERB_GET,
                const std::string& version = VERS_1_1)
        : _url(url)
        , _verb(verb)
        , _version(version)
    {
    }

    /// Create a request to GET the root resource "/".
    HttpRequest()
        : HttpRequest("/")
    {
    }

    /// Set the request URL.
    void setUrl(const std::string& url) { _url = url; }
    /// Get the request URL.
    const std::string& getUrl() const { return _url; }

    /// Set the request verb (typically GET or POST).
    void setVerb(const std::string& verb) { _verb = verb; }
    /// Get the request verb.
    const std::string& getVerb() const { return _verb; }

    /// Set the protocol version (typically HTTP/1.1).
    void setVersion(const std::string& version) { _version = version; }
    /// Get the protocol version.
    const std::string& getVersion() const { return _version; }

    /// The header object to populate.
    HttpHeader& header() { return _header; }

private:
    std::string _startLine;
    HttpHeader _header;
    std::string _url; //< The URL to request.
    std::string _verb; //< The verb of the request.
    std::string _version; //< The protocol version of the request.
};

class HttpResponse final
{
public:
    HttpResponse()
        : _statusCategory(StatusCategory::Informational)
    {
    }

    enum class StatusCategory
    {
        Informational, //< Request being processed, not final response.
        Successful, //< Successfully processed request, response on the way.
        Redirection, //< Redirected to a different resource.
        Client_Error, //< Bad request, cannot respond.
        Server_Error //< Bad server, cannot respond.
    };

    StatusCategory statusCategory() const { return _statusCategory; }

    const HttpHeader& header() const { return _header; }
    HttpHeader& header() { return _header; }

private:
    HttpHeader _header;
    StatusCategory _statusCategory;
};

/// A client socket to make asynchronous HTTP requests.
/// Designed to be reused for multiple requests.
class HttpSession final : public ProtocolHandlerInterface
{
    HttpSession(const std::string& host, const std::string& port, bool secure)
        : _host(host)
        , _port(port)
        , _secure(secure)
        , _state(State::New)
    {
    }

public:
    enum class State
    {
        New,
        SendRequest, //< Request sending needed or in progress.
        RecvHeader, //< Response header reading in progress.
        RecvBody, //< Response body reading in progress.
        Finished //< A request has been satisfied.
    };

    static std::shared_ptr<HttpSession> create(const std::string& host, const std::string& port,
                                               bool secure)
    {
        return std::shared_ptr<HttpSession>(new HttpSession(host, port, secure));
    }

    static std::shared_ptr<HttpSession> create(const std::string& host, const int port, bool secure)
    {
        return create(host, std::to_string(port), secure);
    }

    const std::string& host() const { return _host; }
    const std::string& port() const { return _port; }
    bool secure() const { return _secure; }

    State state() const { return _state; }

    const HttpResponse& response() const { return _response; }

    void asyncGet(const HttpRequest& req, SocketPoll& poll)
    {
        std::cerr << "Connecting\n";
        if (connect())
        {
            std::cerr << "Connected\n";
            _state = State::SendRequest;
            // Now prepare the request.
            _request = req;

            poll.insertNewSocket(_socket);
        }
    }

    void onConnect(const std::shared_ptr<StreamSocket>& socket) override
    {
        std::cout << "onConnect\n";
        // _socket = socket;
        LOG_TRC('#' << socket->getFD() << " Connected.");
    }

    void shutdown(bool /*goingAway*/, const std::string& /*statusMessage*/) override
    {
        std::cout << "shutdown\n";
    }

    void getIOStats(uint64_t& sent, uint64_t& recv) override
    {
        std::cout << "getIOStats\n";
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
        std::cout << "handleIncomingMessage\n";
        std::string res(_socket->getInBuffer().data(), _socket->getInBuffer().size());
        std::cout << res;

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
                      int64_t& /*timeoutMaxMicroS*/) override
    {
        std::cout << "getPollEvents\n";
        int events = POLLIN;
        if (_state == State::SendRequest)
            events |= POLLOUT;
        return events;
    }

    /// Do we need to handle a timeout ?
    void checkTimeout(std::chrono::steady_clock::time_point) override {}

public:
    void performWrites() override
    {
        std::cout << "performWrites\n";
        if (_state == State::SendRequest)
        {
            // std::string header = "GET http://www.example.org/pub/WWW/TheProject.html HTTP/1.1\n\n";
            std::ostringstream oss;
            oss << _request.getVerb() << ' ' << _request.getUrl() << ' ' << _request.getVersion()
                << "\r\n";
            _request.header().serialize(oss);
            oss << "\r\n";
            const std::string header = oss.str();

            Buffer& out = _socket->getOutBuffer();
            out.append(header.data(), header.size());
            std::cout << "performWrites: " << out.size() << "\n";
            // TODO: Write body in post requests.
            _state = State::RecvHeader;
            _socket->writeOutgoingData();
        }
    }

    void onDisconnect() override { std::cout << "onDisconnect\n"; }

    bool connect();

private:
    int sendTextMessage(const char*, const size_t, bool) const override { return 0; }

    int sendBinaryMessage(const char*, const size_t, bool) const override { return 0; }

private:
    const std::string _host;
    const std::string _port;
    const bool _secure;
    State _state;
    std::shared_ptr<StreamSocket> _socket;
    HttpRequest _request;
    HttpResponse _response;
};

inline bool HttpSession::connect()
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
                        _socket
                            = StreamSocket::create<SslStreamSocket>(fd, true, shared_from_this());
#endif
                    if (!_socket && !_secure)
                        _socket = StreamSocket::create<StreamSocket>(fd, true, shared_from_this());

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

/* vim:set shiftwidth=4 softtabstop=4 expandtab: */

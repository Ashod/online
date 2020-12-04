/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4; fill-column: 100 -*- */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#pragma once

#include <Poco/MemoryStream.h>
#include <Poco/Net/HTTPResponse.h>

#include <chrono>
#include <cstdint>
#include <fstream>
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

namespace http
{
/// The parse-state of a field.
enum class FieldParseState
{
    Unknown, //< Not yet parsed.
    Incomplete, //< Not enough data to parse this field. Need more data.
    Invalid, //< The field is invalid/unexpected/long.
    Complete, //< The field is complete. Doesn't imply it's valid.
    Valid //< The field is both complete and valid.
};

/// The callback signature for handling IO writes.
/// Returns the number of bytes read from the buffer,
/// -1 for error (terminates the transfer).
/// The second argument is the data size in the buffer.
using IoWriteFunc = std::function<int64_t(const char*, int64_t)>;

/// The callback signature for handling IO reads.
/// Returns the number of bytes written to the buffer,
/// 0 when no more data is left to read,
/// -1 for error (terminates the transfer).
/// The second argument is the buffer size.
using IoReadFunc = std::function<int64_t(char*, int64_t)>;

/// An HTTP Header.
class Header
{
public:
    static constexpr const char* CONTENT_TYPE = "Content-Type";
    static constexpr const char* CONTENT_LENGTH = "Content-Length";

    static constexpr int64_t MaxNumberFields = 128; // Arbitrary large number.
    static constexpr int64_t MaxNameLen = 512;
    static constexpr int64_t MaxValueLen = 9 * 1024; // 8000 bytes recommended by rfc.
    static constexpr int64_t MaxFieldLen = MaxNameLen + MaxValueLen;
    static constexpr int64_t MaxHeaderLen = MaxNumberFields * MaxFieldLen; // ~1.18 MB.

    /// Describes the header state during parsing.
    enum class State
    {
        New,
        Incomplete, //< Haven't reached the end yet.
        InvalidField, //< Too long, no colon, etc.
        TooManyFields, //< Too many fields to accept.
        Complete //< Header is complete and valid.
    };

    using Container = std::vector<std::pair<std::string, std::string>>;
    using ConstIterator = std::vector<std::pair<std::string, std::string>>::const_iterator;

    ConstIterator begin() const { return _headers.begin(); }
    ConstIterator end() const { return _headers.end(); }

    int64_t parse(const char* p, int64_t len)
    {
        try
        {
            Poco::MemoryInputStream data(p, len);

            Poco::Net::HTTPResponse response;
            response.read(data);
            if (response.hasContentLength())
                setContentLength(response.getContentLength());
            setContentType(response.getContentType());
            std::cerr << "Read " << data.tellg() << " bytes of header:" << std::endl;
            std::cerr << std::string(p, data.tellg()) << std::endl;
            return data.tellg();
        }
        catch (const Poco::Exception& exc)
        {
            std::cerr << "ERROR: " << exc.displayText() << std::endl;
        }

        return 0;
    }

    /// Add an HTTP header field.
    void add(const std::string& key, const std::string& value)
    {
        _headers.emplace_back(key, value);
    }

    /// Set an HTTP header field, replacing an earlier value, if exists.
    void set(const std::string& key, const std::string& value)
    {
        for (auto& pair : _headers)
        {
            if (pair.first == key)
            {
                pair.second = value;
                return;
            }
        }

        _headers.emplace_back(key, value);
    }

    bool has(const std::string& key) const
    {
        for (const auto& pair : _headers)
        {
            if (pair.first == key)
                return true;
        }

        return false;
    }

    std::string get(const std::string& key) const
    {
        for (const auto& pair : _headers)
        {
            if (pair.first == key)
                return pair.second;
        }

        return std::string();
    }

    /// Set the Content-Type header.
    void setContentType(const std::string& type) { set(CONTENT_TYPE, type); }
    /// Get the Content-Type header.
    std::string getContentType() const { return get(CONTENT_TYPE); }
    /// Returns true iff a Content-Type header exists.
    bool hasContentType() const { return has(CONTENT_TYPE); }

    /// Set the Content-Length header.
    void setContentLength(int64_t length) { set(CONTENT_LENGTH, std::to_string(length)); }
    /// Get the Content-Length header.
    int64_t getContentLength() const { return std::stoll(get(CONTENT_LENGTH)); }
    /// Returns true iff a Content-Length header exists.
    bool hasContentLength() const { return has(CONTENT_LENGTH); }

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
    //TODO: We might not need this and get away with a map.
    Container _headers;
};

/// An HTTP Request made over Session.
class Request final
{
public:
    static constexpr const char* VERB_GET = "GET";
    static constexpr const char* VERB_POST = "POST";
    static constexpr const char* VERS_1_1 = "HTTP/1.1";

    /// The stages of processing the request.
    enum class Stage
    {
        Header, //< Communicate the header.
        Body, //< Communicate the body (if any).
        Finished //< Done.
    };

    Request(const std::string& url = "/", const std::string& verb = VERB_GET,
            const std::string& version = VERS_1_1)
        : _url(url)
        , _verb(verb)
        , _version(version)
        , _bodyReaderCb([](const char*, int64_t) { return 0; })
        , _stage(Stage::Header)
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
    Header& header() { return _header; }
    const Header& header() const { return _header; }

    /// Set the request body source to upload some data. Meaningful for POST.
    /// Size is needed to set the Content-Length.
    void setBodySource(IoReadFunc bodyReaderCb, int64_t size)
    {
        header().setContentLength(size);
        _bodyReaderCb = std::move(bodyReaderCb);
    }

    /// Set the file to send as the body of the request.
    void setBodyFile(const std::string& path)
    {
        //FIXME: use generalized lambda campture to move the ifstream, available in C++14.
        auto ifs = std::make_shared<std::ifstream>(path, std::ios::binary);

        ifs->seekg(0, std::ios_base::end);
        const int64_t size = ifs->tellg();
        ifs->seekg(0, std::ios_base::beg);

        setBodySource(
            [=](char* buf, int64_t len) -> int64_t {
                ifs->read(buf, len);
                return ifs->gcount();
            },
            size);
    }

    Stage stage() const { return _stage; }

    bool writeData(Buffer& out)
    {
        if (_stage == Stage::Header)
        {
            std::ostringstream oss;
            oss << getVerb() << ' ' << getUrl() << ' ' << getVersion() << "\r\n";
            header().serialize(oss);
            oss << "\r\n";
            const std::string header = oss.str();

            out.append(header.data(), header.size());
            std::cerr << "performWrites (header): " << header.size() << "\n";
            _stage = Stage::Body;
        }

        if (_stage == Stage::Body)
        {
            char buffer[16 * 1024];
            const int64_t read = _bodyReaderCb(buffer, sizeof(buffer));
            if (read < 0)
                return false;

            if (read == 0)
            {
                _stage = Stage::Finished;
            }
            else if (read > 0)
            {
                out.append(buffer, read);
                std::cerr << "performWrites (body): " << read << "\n";
            }
        }

        return true;
    }

private:
    Header _header;
    std::string _url; //< The URL to request.
    std::string _verb; //< The verb of the request.
    std::string _version; //< The protocol version of the request.
    IoReadFunc _bodyReaderCb;
    Stage _stage;
};

/// HTTP Status Line is the first line of a response sent by a server.
class StatusLine
{
public:
    static constexpr int64_t VersionLen = 8;
    static constexpr int64_t StatusCodeLen = 3;
    static constexpr int64_t MaxReasonPhraseLen = 512; // Arbitrary large number.
    static constexpr int64_t MinStatusLineLen = sizeof("HTTP/0.0 000 X\r\n");
    static constexpr int64_t MaxStatusLineLen = VersionLen + StatusCodeLen + MaxReasonPhraseLen;
    static constexpr int64_t MinValidStatusCode = 100;
    static constexpr int64_t MaxValidStatusCode = 599;

    static constexpr const char* HTTP_1_1 = "HTTP/1.1";
    static constexpr const char* OK = "OK";

    StatusLine(const std::string& version = HTTP_1_1, int code = 200,
               const std::string& reason = OK)
        : _httpVersion(version)
        , _statusCode(code)
        , _reasonPhrase(reason)
    {
    }

    /// The Status Code class of the response.
    /// None of these implies complete receipt of the response.
    enum class StatusCodeClass
    {
        Invalid,
        Informational, //< Request being processed, not final response.
        Successful, //< Successfully processed request, response on the way.
        Redirection, //< Redirected to a different resource.
        Client_Error, //< Bad request, cannot respond.
        Server_Error //< Bad server, cannot respond.
    };

    StatusCodeClass statusCategory() const
    {
        if (_statusCode >= 500 && _statusCode < 600)
            return StatusCodeClass::Server_Error;
        if (_statusCode >= 400)
            return StatusCodeClass::Client_Error;
        if (_statusCode >= 300)
            return StatusCodeClass::Redirection;
        if (_statusCode >= 200)
            return StatusCodeClass::Successful;
        if (_statusCode >= 100)
            return StatusCodeClass::Informational;
        return StatusCodeClass::Invalid;
    }

    /// Skips over space and tab characters starting at off.
    /// Returns the offset of the first match, otherwise, len.
    /// Technically, we should skip: SP, HTAB, VT (%x0B), FF (%x0C), or bare CR.
    int64_t skipSpaceAndTab(const char* p, int64_t off, int64_t len)
    {
        for (; off < len; ++off)
        {
            if (p[off] != ' ' && p[off] != '\t')
                return off;
        }

        return len;
    }

    /// Parses a Status Line.
    /// Returns the state and clobbers the len on succcess to the number of bytes read.
    FieldParseState parse(const char* p, int64_t& len)
    {
        // First line is the status line.
        if (p == nullptr || len < MinStatusLineLen)
            return FieldParseState::Incomplete;

        int64_t off = skipSpaceAndTab(p, 0, len);
        if (off >= MaxStatusLineLen)
            return FieldParseState::Invalid;

        // We still expect the minimum amount of data.
        if ((len - off) < MinStatusLineLen)
            return FieldParseState::Incomplete;

        // We should have the version now.
        assert(off + VersionLen < len && "Expected to have more data.");
        const char* version = &p[off];
        constexpr int VersionMajPos = sizeof("HTTP/") - 1;
        constexpr int VersionDotPos = VersionMajPos + 1;
        constexpr int VersionMinPos = VersionDotPos + 1;
        const int versionMajor = version[VersionMajPos] - '0';
        const int versionMinor = version[VersionMinPos] - '0';
        if (!Util::startsWith(version, "HTTP/") || (versionMajor < 0 || versionMajor > 9)
            || version[VersionDotPos] != '.' || (versionMinor < 0 || versionMinor > 9))
        {
            return FieldParseState::Invalid;
        }

        _httpVersion = std::string(version, VersionLen);
        _versionMajor = versionMajor;
        _versionMinor = versionMinor;

        // Find the Status Code.
        off = skipSpaceAndTab(p, off + VersionLen, len);
        if (off >= MaxStatusLineLen)
            return FieldParseState::Invalid;

        // We still expect the Status Code and CRLF.
        if ((len - off) < (MinStatusLineLen - VersionLen))
            return FieldParseState::Incomplete;

        // Read the Status Code now.
        assert(off + StatusCodeLen < len && "Expected to have more data.");
        _statusCode = std::atoi(&p[off]);
        if (_statusCode < MinValidStatusCode || _statusCode > MaxValidStatusCode)
            return FieldParseState::Invalid;

        // Find the Reason Phrase.
        off = skipSpaceAndTab(p, off + StatusCodeLen, len);
        if (off >= MaxStatusLineLen)
            return FieldParseState::Invalid;

        const int64_t reasonOff = off;

        // Find the line break, which ends the status line.
        for (; off < len; ++off)
        {
            if (p[off] == '\r' || p[off] == '\n')
                break;

            if (off >= MaxStatusLineLen)
                return FieldParseState::Invalid;
        }

        if (off >= len)
            return FieldParseState::Incomplete;

        _reasonPhrase = std::string(&p[reasonOff], off - reasonOff);

        // Consume the line breaks.
        for (; off < len; ++off)
        {
            if (p[off] != '\r' && p[off] != '\n')
                break;
        }

        len = off;
        return FieldParseState::Valid;
    }

    const std::string& httpVersion() const { return _httpVersion; }
    int versionMajor() const { return _versionMajor; }
    int versionMinor() const { return _versionMinor; }
    int statusCode() const { return _statusCode; }
    const std::string& reasonPhrase() const { return _reasonPhrase; }

private:
    std::string _httpVersion; //< Typically "HTTP/1.1"
    int _versionMajor; //< The first version digit (typically 1).
    int _versionMinor; //< The second version digit (typically 1).
    int _statusCode;
    std::string _reasonPhrase; //< A client SHOULD ignore the reason-phrase content.
};

/// The response for an HTTP request.
class Response final
{
public:
    Response()
        : _state(State::New)
        , _parserStage(ParserStage::StatusLine)
        , _recvBodySize(0)
    {
        // By default we store the body in memory.
        saveBodyToMemory();
    }

    /// The state of the response.
    enum class State
    {
        New, //< Valid but meaningless.
        Incomplete, //< In progress, no errors.
        Error, //< This is for protocol errors, not 400 and 500 reponses.
        Complete //< Successfully completed.
    };

    /// Signifies that the response is
    State state() const { return _state; }

    /// Returns true iff there is no more data to expect.
    bool done() const { return (_state == State::Error || _state == State::Complete); }

    const StatusLine& statusLine() const { return _statusLine; }

    const Header& header() const { return _header; }

    void saveBodyToFile(const std::string& path)
    {
        _bodyFile.open(path, std::ios_base::out | std::ios_base::binary);
        _onBodyWriteCb = [this](const char* p, int64_t len) {
            if (_bodyFile.good())
                _bodyFile.write(p, len);
            return _bodyFile.good() ? len : -1;
        };
    }

    void saveBodyToHandler(IoWriteFunc onBodyWriteCb) { _onBodyWriteCb = std::move(onBodyWriteCb); }

    void saveBodyToMemory()
    {
        _onBodyWriteCb = [this](const char* p, int64_t len) {
            _body.insert(_body.end(), p, p + len);
            // std::cerr << "Body: " << len << "\n" << _body << std::endl;
            return len;
        };
    }

    /// Returns the body, assuming it wasn't redirected to file or callback.
    std::string getBody() const { return _body; }

    /// Handles incoming data.
    /// Returns the number of bytes consumed, or -1 for error
    /// and/or to interrupt transmission.
    int64_t readData(const char* p, int64_t len)
    {
        // We got some data.
        _state = State::Incomplete;

        int64_t available = len;
        if (_parserStage == ParserStage::StatusLine)
        {
            int64_t read = available;
            switch (_statusLine.parse(p, read))
            {
                case FieldParseState::Unknown:
                case FieldParseState::Complete:
                case FieldParseState::Incomplete:
                    return 0;
                case FieldParseState::Invalid:
                    _state = State::Error;
                    return -1;
                case FieldParseState::Valid:
                    if (read <= 0)
                        return read; // Unexpected, really.
                    if (read > 0)
                    {
                        //FIXME: Don't consume what we read until we have our header parser.
                        // available -= read;
                        // p += read;
                        _parserStage = ParserStage::Header;
                    }
                    break;
            }
        }

        if (_parserStage == ParserStage::Header)
        {
            const int64_t read = _header.parse(p, available);
            if (read < 0)
            {
                _state = State::Error;
                return read;
            }

            if (read > 0)
            {
                available -= read;
                p += read;

                if (_header.hasContentLength())
                {
                    if (_header.getContentLength() > 0)
                        _parserStage = ParserStage::Body;
                    else if (_header.getContentLength() == 0)
                        _parserStage = ParserStage::Finished; // No body, we are done.
                    else if (_header.getContentLength() < 0)
                    {
                        _state = State::Error;
                        _parserStage = ParserStage::Finished;
                    }
                }

                if (_statusLine.statusCategory() == StatusLine::StatusCodeClass::Informational
                    || _statusLine.statusCode() == 204 /*No Content*/
                    || _statusLine.statusCode() == 304 /*Not Modified*/) // || HEAD request
                // || 2xx on CONNECT request
                {
                    _parserStage = ParserStage::Finished; // No body, we are done.
                }
            }
        }

        if (_parserStage == ParserStage::Body)
        {
            // std::cerr << "ParserStage::Body: " << available << "\n"
            //           << std::string(p, available) << std::endl;
            const int64_t read = _onBodyWriteCb(p, available);
            if (read < 0)
            {
                _state = State::Error;
                return read;
            }

            if (read > 0)
            {
                available -= read;
                _recvBodySize += read;
                if (_header.hasContentLength() && _recvBodySize >= _header.getContentLength())
                {
                    _parserStage = ParserStage::Finished;
                }
            }
        }

        if (_parserStage == ParserStage::Finished)
        {
            finish();
        }

        return len - available;
    }

    /// Signifies that we got all the data we expected
    /// and cleans up and updates the states.
    void finish()
    {
        _bodyFile.close();
        std::cerr << "State::Complete\n";
        _state = State::Complete;
    }

private:
    /// The stage we're at in consuming the received data.
    enum class ParserStage
    {
        StatusLine,
        Header,
        Body,
        Finished
    };

    StatusLine _statusLine;
    Header _header;
    State _state; //< The state of the Response.
    ParserStage _parserStage; //< The parser's state.
    int64_t _recvBodySize; //< The amount of data we received (compared to the Content-Length).
    std::string _body; //< Used when _bodyHandling is InMemory.
    std::ofstream _bodyFile; //< Used when _bodyHandling is OnDisk.
    IoWriteFunc _onBodyWriteCb; //< Used to handling body receipt in all cases.
};

/// A client socket to make asynchronous HTTP requests.
/// Designed to be reused for multiple requests.
class Session final : public ProtocolHandlerInterface
{
    Session(const std::string& host, const std::string& port, bool secure)
        : _host(host)
        , _port(port)
        , _secure(secure)
        , _connected(false)
    {
    }

public:
    static std::shared_ptr<Session> create(const std::string& host, const std::string& port,
                                           bool secure)
    {
        return std::shared_ptr<Session>(new Session(host, port, secure));
    }

    static std::shared_ptr<Session> create(const std::string& host, const int port, bool secure)
    {
        return create(host, std::to_string(port), secure);
    }

    const std::string& host() const { return _host; }
    const std::string& port() const { return _port; }
    bool secure() const { return _secure; }

    std::shared_ptr<const Response> response() const { return _response; }

    bool syncRequest(const Request& req, const std::chrono::microseconds timeoutUs)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeoutUs;

        std::cerr << "syncRequest\n";
        _response.reset(new Response);
        _request = req;
        _request.header().set("Host", host()); // Make sure the host is set.

        if (!_connected && !connect())
            return false;

        SocketPoll poller("HttpSessionPoll");

        poller.insertNewSocket(_socket);
        poller.poll(timeoutUs);
        while (!_response->done())
        {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline)
                return false;

            const auto remaining
                = std::chrono::duration_cast<std::chrono::microseconds>(deadline - now);
            poller.poll(remaining);
        }

        return _response->state() == Response::State::Complete;
    }

    void asyncRequest(const Request& req, SocketPoll& poll)
    {
        std::cerr << "asyncRequest\n";
        _response.reset(new Response);
        _request = req;
        _request.header().set("Host", host()); // Make sure the host is set.

        if (!_connected && connect())
        {
            std::cerr << "Connected\n";
            poll.insertNewSocket(_socket);
        }
        else
            poll.wakeupWorld();
    }

private:
    void onConnect(const std::shared_ptr<StreamSocket>& socket) override
    {
        std::cerr << "onConnect\n";
        LOG_TRC('#' << socket->getFD() << " Connected.");
        _connected = true;
    }

    void shutdown(bool /*goingAway*/, const std::string& /*statusMessage*/) override
    {
        std::cerr << "shutdown\n";
    }

    void getIOStats(uint64_t& sent, uint64_t& recv) override
    {
        std::cerr << "getIOStats\n";
        _socket->getIOStats(sent, recv);
    }

    int getPollEvents(std::chrono::steady_clock::time_point /*now*/,
                      int64_t& /*timeoutMaxMicroS*/) override
    {
        std::cerr << "getPollEvents\n";
        int events = POLLIN;
        if (_request.stage() != Request::Stage::Finished)
            events |= POLLOUT;
        return events;
    }

    virtual void handleIncomingMessage(SocketDisposition& disposition) override
    {
        std::cerr << "handleIncomingMessage\n";

        std::vector<char>& data = _socket->getInBuffer();
        const int64_t read = _response->readData(data.data(), data.size());
        if (read > 0)
        {
            // Remove consumed data.
            data.erase(data.begin(), data.begin() + read);
        }
        else if (read < 0 || _response->done())
        {
            // Interrupt the transfer.
            disposition.setClosed();
        }
    }

    void performWrites() override
    {
        std::cerr << "performWrites\n";

        Buffer& out = _socket->getOutBuffer();
        if (!_request.writeData(out))
        {
            _socket->shutdown();
        }
        else if (!out.empty())
        {
            std::cerr << "Sending\n"
                      << std::string(out.getBlock(), out.getBlockSize()) << std::endl;
            _socket->writeOutgoingData();
        }
    }

    void onDisconnect() override
    {
        std::cerr << "onDisconnect\n";
        _connected = false;
    }

    bool connect();

    /// Do we need to handle a timeout ?
    void checkTimeout(std::chrono::steady_clock::time_point) override {}
    int sendTextMessage(const char*, const size_t, bool) const override { return 0; }
    int sendBinaryMessage(const char*, const size_t, bool) const override { return 0; }

private:
    const std::string _host;
    const std::string _port;
    const bool _secure;
    std::shared_ptr<StreamSocket> _socket;
    Request _request;
    std::shared_ptr<Response> _response;
    bool _connected;
};

inline bool Session::connect()
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

} // namespace http

/* vim:set shiftwidth=4 softtabstop=4 expandtab: */

/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4; fill-column: 100 -*- */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <config.h>

#include <Poco/Net/HTTPClientSession.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/StreamCopier.h>

#include <string>
#include <test/lokassert.hpp>

#include <net/HttpRequest.hpp>
#include <FileUtil.hpp>
#include <Util.hpp>

/// http::Request unit-tests.
class HttpRequestTests : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(HttpRequestTests);

    // CPPUNIT_TEST(testSimpleGet);
    // CPPUNIT_TEST(test500GetStatuses);
    CPPUNIT_TEST(testSimplePost);

    CPPUNIT_TEST_SUITE_END();

    void testSimpleGet();
    void test500GetStatuses();
    void testSimplePost();
};

static std::pair<Poco::Net::HTTPResponse, std::string> pocoGet(const std::string& host,
                                                               const std::string& url)
{
    Poco::Net::HTTPClientSession session(host, 80);
    Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_GET, url,
                                   Poco::Net::HTTPMessage::HTTP_1_1);
    session.sendRequest(request);
    Poco::Net::HTTPResponse response;
    std::istream& rs = session.receiveResponse(response);
    // std::cout << response.getStatus() << ' ' << response.getReason() << std::endl;

    std::string responseString;
    if (response.hasContentLength() && response.getContentLength() > 0)
    {
        std::ostringstream outputStringStream;
        Poco::StreamCopier::copyStream(rs, outputStringStream);
        responseString = outputStringStream.str();
        // std::cout << responseString << std::endl;
        // std::cout << "-----" << std::endl;
    }

    return std::make_pair(response, responseString);
}

void HttpRequestTests::testSimpleGet()
{
    const char* Host = "www.example.com";
    const char* URL = "/";

    const auto pocoResponse = pocoGet(Host, URL);

    // Start the polling thread.
    SocketPoll pollThread("HttpSessionPoll");
    pollThread.startThread();

    http::Request httpRequest;
    httpRequest.setUrl(URL);
    httpRequest.header().set("Host", Host);

    auto httpSession = http::Session::create(Host, 80, false);
    httpSession->asyncGet(httpRequest, pollThread);

    const http::Response& httpResponse = httpSession->response();

    for (int i = 0; i < 10000 && !httpResponse.done(); ++i)
        usleep(100); // Wait some more.

    LOK_ASSERT(httpResponse.state() == http::Response::State::Complete);
    LOK_ASSERT(!httpResponse.statusLine().httpVersion().empty());
    LOK_ASSERT(!httpResponse.statusLine().reasonPhrase().empty());
    LOK_ASSERT(httpResponse.statusLine().statusCode() == 200);
    LOK_ASSERT(httpResponse.statusLine().statusCategory()
               == http::StatusLine::StatusCodeClass::Successful);

    const std::string body = httpResponse.getBody();
    LOK_ASSERT(!body.empty());
    LOK_ASSERT_EQUAL(pocoResponse.second, body);

    pollThread.joinThread();
}

static void compare(const Poco::Net::HTTPResponse& pocoResponse, const std::string& pocoBody,
                    const http::Response& httpResponse)
{
    LOK_ASSERT(httpResponse.state() == http::Response::State::Complete);
    LOK_ASSERT(!httpResponse.statusLine().httpVersion().empty());
    LOK_ASSERT(!httpResponse.statusLine().reasonPhrase().empty());

    LOK_ASSERT_EQUAL(pocoBody, httpResponse.getBody());

    LOK_ASSERT_EQUAL(static_cast<int>(pocoResponse.getStatus()),
                     httpResponse.statusLine().statusCode());
    LOK_ASSERT_EQUAL(pocoResponse.getReason(), httpResponse.statusLine().reasonPhrase());

    LOK_ASSERT_EQUAL(pocoResponse.hasContentLength(), httpResponse.header().hasContentLength());
    if (pocoResponse.hasContentLength())
        LOK_ASSERT_EQUAL(pocoResponse.getContentLength(), httpResponse.header().getContentLength());
}

void HttpRequestTests::test500GetStatuses()
{
    // Start the polling thread.
    SocketPoll pollThread("HttpSessionPoll");
    pollThread.startThread();

    const std::string host = "httpbin.org";

    http::Request httpRequest;
    httpRequest.header().set("Host", host);

    auto httpSession = http::Session::create(host, 80, false);
    const http::Response& httpResponse = httpSession->response();

    http::StatusLine::StatusCodeClass statusCodeClasses[]
        = { http::StatusLine::StatusCodeClass::Informational,
            http::StatusLine::StatusCodeClass::Successful,
            http::StatusLine::StatusCodeClass::Redirection,
            http::StatusLine::StatusCodeClass::Client_Error,
            http::StatusLine::StatusCodeClass::Server_Error };
    int curStatusCodeClass = -1;
    for (int statusCode = 100; statusCode < 600; ++statusCode)
    {
        const std::string url = "/status/" + std::to_string(statusCode);
        httpRequest.setUrl(url);
        httpSession->asyncGet(httpRequest, pollThread);

        for (int i = 0; i < 10000 && !httpResponse.done(); ++i)
            usleep(100); // Wait some more.

        LOK_ASSERT(httpResponse.state() == http::Response::State::Complete);
        LOK_ASSERT(!httpResponse.statusLine().httpVersion().empty());
        LOK_ASSERT(!httpResponse.statusLine().reasonPhrase().empty());

        if (statusCode % 100 == 0)
            ++curStatusCodeClass;
        LOK_ASSERT(httpResponse.statusLine().statusCategory()
                   == statusCodeClasses[curStatusCodeClass]);

        LOK_ASSERT(httpResponse.statusLine().statusCode() == statusCode);

        if (httpResponse.statusLine().statusCategory()
            != http::StatusLine::StatusCodeClass::Informational)
        {
            const auto pocoResponse = pocoGet(host, url); // Get via Poco in parallel.
            compare(pocoResponse.first, pocoResponse.second, httpResponse);
        }
    }

    pollThread.joinThread();
}

void HttpRequestTests::testSimplePost()
{
    const std::string Host = "httpbin.org";
    const char* URL = "/post";

    // Start the polling thread.
    SocketPoll pollThread("HttpSessionPoll");
    pollThread.startThread();

    http::Request httpRequest(URL, http::Request::VERB_POST);

    // Write the test data to file.
    const char data[] = "abcd-qwerty!!!";
    const std::string path = FileUtil::getSysTempDirectoryPath() + "/test_http_post";
    std::ofstream ofs(path, std::ios::binary);
    ofs.write(data, sizeof(data) - 1); // Don't write the terminating null.
    ofs.close();

    httpRequest.setBodyFile(path);

    auto httpSession = http::Session::create(Host, 80, false);
    httpSession->asyncGet(httpRequest, pollThread);

    const http::Response& httpResponse = httpSession->response();

    for (int i = 0; i < 10000 && !httpResponse.done(); ++i)
        usleep(100); // Wait some more.

    LOK_ASSERT(httpResponse.state() == http::Response::State::Complete);
    LOK_ASSERT(!httpResponse.statusLine().httpVersion().empty());
    LOK_ASSERT(!httpResponse.statusLine().reasonPhrase().empty());
    LOK_ASSERT(httpResponse.statusLine().statusCode() == 200);
    LOK_ASSERT(httpResponse.statusLine().statusCategory()
               == http::StatusLine::StatusCodeClass::Successful);

    const std::string body = httpResponse.getBody();
    LOK_ASSERT(!body.empty());
    std::cerr << "[" << body << "]\n";
    LOK_ASSERT(body.find(data) != std::string::npos);

    pollThread.joinThread();
}

CPPUNIT_TEST_SUITE_REGISTRATION(HttpRequestTests);

/* vim:set shiftwidth=4 softtabstop=4 expandtab: */

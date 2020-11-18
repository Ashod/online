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
#include <Util.hpp>

/// HttpRequest unit-tests.
class HttpRequestTests : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(HttpRequestTests);

    CPPUNIT_TEST(testSimpleGet);
    CPPUNIT_TEST(testGetStatus);

    CPPUNIT_TEST_SUITE_END();

    void testSimpleGet();
    void testGetStatus();
};

void HttpRequestTests::testSimpleGet()
{
    const char* Host = "www.example.com";
    const char* URL = "/";

    Poco::Net::HTTPClientSession session(Host, 80);
    Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_GET, URL,
                                   Poco::Net::HTTPMessage::HTTP_1_1);
    session.sendRequest(request);
    Poco::Net::HTTPResponse response;
    std::istream& rs = session.receiveResponse(response);
    std::cout << response.getStatus() << ' ' << response.getReason() << std::endl;

    std::ostringstream outputStringStream;
    Poco::StreamCopier::copyStream(rs, outputStringStream);
    std::string responseString = outputStringStream.str();
    std::cout << responseString << std::endl;
    std::cout << "-----" << std::endl;

    // Start the polling thread.
    SocketPoll pollThread("HttpRequestPoll");
    pollThread.startThread();

    HttpRequest httpRequest;
    httpRequest.setUrl(URL);
    httpRequest.header().set("Host", Host);

    auto httpSession = HttpSession::create(Host, 80, false);
    httpSession->asyncGet(httpRequest, pollThread);

    const HttpResponse& httpResponse = httpSession->response();

    for (int i = 0; i < 10000 && !httpResponse.done(); ++i)
        usleep(100); // Wait some more.

    LOK_ASSERT(httpResponse.state() == HttpResponse::State::Complete);
    LOK_ASSERT(!httpResponse.statusLine().httpVersion().empty());
    LOK_ASSERT(!httpResponse.statusLine().reasonPhrase().empty());
    LOK_ASSERT(httpResponse.statusLine().statusCode() == 200);
    LOK_ASSERT(httpResponse.statusLine().statusCategory()
               == StatusLine::StatusCodeClass::Successful);

    const std::string body = httpResponse.getBody();
    LOK_ASSERT(!httpResponse.getBody().empty());

    LOK_ASSERT_EQUAL(responseString, body);

    pollThread.joinThread();
}

void HttpRequestTests::testGetStatus()
{
    // Start the polling thread.
    SocketPoll pollThread("HttpRequestPoll");
    pollThread.startThread();

    HttpRequest httpRequest;
    httpRequest.header().set("Host", "httpbin.org");

    auto httpSession = HttpSession::create("httpbin.org", 80, false);
    const HttpResponse& httpResponse = httpSession->response();

    StatusLine::StatusCodeClass statusCodeClasses[]
        = { StatusLine::StatusCodeClass::Informational, StatusLine::StatusCodeClass::Successful,
            StatusLine::StatusCodeClass::Redirection, StatusLine::StatusCodeClass::Client_Error,
            StatusLine::StatusCodeClass::Server_Error };
    int curStatusCodeClass = -1;
    for (int statusCode = 100; statusCode < 600; ++statusCode)
    {
        httpRequest.setUrl("/status/" + std::to_string(statusCode));
        httpSession->asyncGet(httpRequest, pollThread);

        for (int i = 0; i < 10000 && !httpResponse.done(); ++i)
            usleep(100); // Wait some more.

        LOK_ASSERT(httpResponse.state() == HttpResponse::State::Complete);
        LOK_ASSERT(!httpResponse.statusLine().httpVersion().empty());
        LOK_ASSERT(!httpResponse.statusLine().reasonPhrase().empty());
        LOK_ASSERT(httpResponse.statusLine().statusCode() == statusCode);

        if (statusCode % 100 == 0)
            ++curStatusCodeClass;
        LOK_ASSERT(httpResponse.statusLine().statusCategory()
                   == statusCodeClasses[curStatusCodeClass]);

        LOK_ASSERT(httpResponse.getBody().empty());
    }
    pollThread.joinThread();
}

CPPUNIT_TEST_SUITE_REGISTRATION(HttpRequestTests);

/* vim:set shiftwidth=4 softtabstop=4 expandtab: */

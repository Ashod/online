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

#include <test/lokassert.hpp>

#include <net/HttpRequest.hpp>
#include <Util.hpp>

/// HttpRequest unit-tests.
class HttpRequestTests : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(HttpRequestTests);

    CPPUNIT_TEST(testSimpleGet);

    CPPUNIT_TEST_SUITE_END();

    void testSimpleGet();
};

void HttpRequestTests::testSimpleGet()
{
    Poco::Net::HTTPClientSession session("example.com", 80);
    Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_GET, "/",
                                   Poco::Net::HTTPMessage::HTTP_1_1);
    session.sendRequest(request);

    Poco::Net::HTTPResponse response;
    std::istream& rs = session.receiveResponse(response);
    std::cout << response.getStatus() << ' ' << response.getReason() << std::endl;

    std::ostringstream outputStringStream;
    Poco::StreamCopier::copyStream(rs, outputStringStream);
    std::string responseString = outputStringStream.str();
    // std::cout << responseString << std::endl;

    // Start the polling thread.
    SocketPoll pollThread("HttpRequestPoll");
    pollThread.startThread();

    HttpRequest httpRequest;
    httpRequest.setUrl("/");
    httpRequest.header().set("Host", "www.example.com");
    // httpRequest.set("Connection", "upgrade");
    // httpRequest.set("Upgrade", "upgrade");

    auto httpSession = HttpSession::create("example.com", 80, false);
    httpSession->asyncGet(httpRequest, pollThread);

    const HttpResponse& httpResponse = httpSession->response();

    while (!httpResponse.done())
    {
        // Wait some more.
        usleep(100);
    }

    const std::string body = httpResponse.getBody();

    LOK_ASSERT_EQUAL(responseString, body);

    pollThread.joinThread();
}

CPPUNIT_TEST_SUITE_REGISTRATION(HttpRequestTests);

/* vim:set shiftwidth=4 softtabstop=4 expandtab: */

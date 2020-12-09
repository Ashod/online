/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4; fill-column: 100 -*- */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <config.h>

#include <WopiTestServer.hpp>
#include <Log.hpp>
#include <Unit.hpp>
#include <UnitHTTP.hpp>
#include <helpers.hpp>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Util/LayeredConfiguration.h>

class UnitWOPI : public WopiTestServer
{
    enum class Phase
    {
        LoadAndSave,
        Modify,
        SaveModified,
        Polling
    } _phase;

    enum class SavingPhase
    {
        Unmodified,
        Modified
    } _savingPhase;

    bool _finishedSaveUnmodified;
    bool _finishedSaveModified;

public:
    UnitWOPI()
        : WopiTestServer("UnitWOPI")
        , _phase(Phase::LoadAndSave)
        , _finishedSaveUnmodified(false)
        , _finishedSaveModified(false)
    {
    }

    bool isAutosave() override
    {
        // we fake autosave when saving the modified document
        return _savingPhase == SavingPhase::Modified;
    }

    void assertPutFileRequest(const Poco::Net::HTTPRequest& request) override
    {
        LOG_INF("assertPutFileRequest: ... ");
        if (_savingPhase == SavingPhase::Unmodified)
        {
            // the document is not modified
            LOK_ASSERT_EQUAL(std::string("false"), request.get("X-LOOL-WOPI-IsModifiedByUser"));

            // but the save action is an explicit user's request
            LOK_ASSERT_EQUAL(std::string("false"), request.get("X-LOOL-WOPI-IsAutosave"));

            _finishedSaveUnmodified = true;
        }
        else if (_savingPhase == SavingPhase::Modified)
        {
            // the document is modified
            LOK_ASSERT_EQUAL(std::string("true"), request.get("X-LOOL-WOPI-IsModifiedByUser"));

            // and this test fakes that it's an autosave
            LOK_ASSERT_EQUAL(std::string("true"), request.get("X-LOOL-WOPI-IsAutosave"));

            // Check that we get the extended data.
            LOK_ASSERT_EQUAL(std::string("CustomFlag=Custom Value;AnotherFlag=AnotherValue"),
                                 request.get("X-LOOL-WOPI-ExtendedData"));

            _finishedSaveModified = true;
        }

        if (_finishedSaveUnmodified && _finishedSaveModified)
            exitTest(TestResult::Ok);
    }

    void invokeWSDTest() override
    {
        constexpr char testName[] = "UnitWOPI";

        switch (_phase)
        {
            case Phase::LoadAndSave:
            {
                LOG_INF(testName << ": LoadAndSave: initWebsocket.");
                initWebsocket("/wopi/files/0?access_token=anything");

                LOG_INF(testName << ": LoadAndSave: load url=" << getWopiSrc());
                helpers::sendTextFrame(*getWs()->getLOOLWebSocket(), "load url=" + getWopiSrc(), testName);
                LOG_INF(testName << ": LoadAndSave: save dontTerminateEdit=1 dontSaveIfUnmodified=0");
                helpers::sendTextFrame(*getWs()->getLOOLWebSocket(), "save dontTerminateEdit=1 dontSaveIfUnmodified=0", testName);

                LOG_INF(testName << ": LoadAndSave => Modify");
                _phase = Phase::Modify;
                _savingPhase = SavingPhase::Unmodified;
                SocketPoll::wakeupWorld();
                break;
            }
            case Phase::Modify:
            {
                LOG_INF(testName << ": Modify: key type=input char=97 key=0");
                helpers::sendTextFrame(*getWs()->getLOOLWebSocket(), "key type=input char=97 key=0", testName);
                LOG_INF(testName << ": Modify: key type=up char=0 key=512");
                helpers::sendTextFrame(*getWs()->getLOOLWebSocket(), "key type=up char=0 key=512", testName);

                LOG_INF(testName << ": Modify => SaveModified");
                _phase = Phase::SaveModified;
                break;
            }
            case Phase::SaveModified:
            {
                LOG_INF(testName << ": SaveModify: save dontTerminateEdit=0 dontSaveIfUnmodified=0 ...");
                helpers::sendTextFrame(*getWs()->getLOOLWebSocket(),
                                       "save dontTerminateEdit=0 dontSaveIfUnmodified=0 "
                                       "extendedData=CustomFlag%3DCustom%20Value%3BAnotherFlag%"
                                       "3DAnotherValue",
                                       testName);

                LOG_INF(testName << ": SaveModified => Polling");
                _phase = Phase::Polling;
                _savingPhase = SavingPhase::Modified;
                break;
            }
            case Phase::Polling:
            {
                // just wait for the results
                break;
            }
        }
    }
};

UnitBase *unit_create_wsd(void)
{
    return new UnitWOPI();
}

/* vim:set shiftwidth=4 softtabstop=4 expandtab: */

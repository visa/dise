#pragma once

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <dEnc/Defines.h>
#include <vector>

namespace dEnc
{

    struct GroupChannel
    {
        std::vector<oc::Session> mSessions;
        std::vector<Channel> mRequestChls, mListenChls;

        void connect(u64 partyIdx, u64 numParties, oc::IOService& ios, std::string ip = "localhost")
        {
            if (mSessions.size())
                throw std::runtime_error("connect can be called once " LOCATION);
            mSessions.resize(numParties - 1);

            u64 eIter = 0;
            for (u64 i = 0; i < numParties; ++i)
            {
                if (i != partyIdx)
                {
                    oc::EpMode mode = i > partyIdx ? oc::EpMode::Client : oc::EpMode::Server;
                    std::string name = "ep" + (i > partyIdx ?
                        std::to_string(i) + "-" + std::to_string(partyIdx) :
                        std::to_string(partyIdx) + "-" + std::to_string(i));

                    mSessions[eIter].start(ios, ip, mode, name);
                    mRequestChls.push_back(mSessions[eIter].addChannel("request", "listen"));
                    mListenChls.push_back(mSessions[eIter].addChannel("listen", "request"));

                    ++eIter;
                }
            }
        }

    };


}
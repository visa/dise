#pragma once
#include <dEnc/Defines.h>
#include <cryptoTools/Crypto/RCurve.h>
#include "Dprf.h"

namespace dEnc {

    


	class Npr03AsymDprf : public Dprf
	{
	public:
        using Num = oc::REccNumber;
        using Point = oc::REccPoint;


        struct MasterKey
        {
            std::function<Num(u64 i)> mKeyPoly;

            Num mMasterKey;

            std::vector<Num> mKeyShares;
            std::vector<Point> mCommits;

            void KeyGen(u64 n, u64 m, PRNG& prng, Type type);
        };


		virtual ~Npr03AsymDprf();

        // The index of this party
		i64 mPartyIdx;

        // The total number of parties
		u64 mN;

        // The threshold of parties alloed to produce an DPRF output
        u64 mM;

        // A flag to specify what type of security is desired (semihonest, malicious, ...)
        Type mType;

        // Local source of randomness
		PRNG mPrng;

        // Internal flag that determines if the OPRF is currently closed.
        bool mIsClosed = true;

        oc::REllipticCurve mCurve;

        // The local secret key
		Num mSk;

		std::vector<Num> mTempNums;
		std::vector<Point> mGSks, mTempPoints;
        Point mGen;
		std::vector<Num> mDefaultLag;



		static std::function<Num(u64 i)> interpolate(span<Num> fx, span<Num> x);
		static std::function<Num(u64 i)> interpolate(span<Num> fx);

		void init(
			u64 partyIdx,
			u64 m,
			span<Channel> requestChls,
			span<Channel> listChls,
			block seed,
            Type  type,
            Num sk,
            span<Point> gSks);

		virtual void serveOne(span<u8>request, u64 outputPartyIdx)override;
		void serveOne(block in, span<u8> dest, u64 outputPartyIdx);

		virtual block eval(block input)override;
		virtual AsyncEval asyncEval(block input)override;
		virtual AsyncEval asyncEval(span<block> input)override;

		virtual void close()override;


		void startListening();
		std::vector<std::vector<u8>> mRecvBuff;
		std::promise<void> mServerDoneProm;
		std::future<void> mServerDone;
		std::atomic<u64> mListens;
		std::vector < std::function<void()>> mServerListenCallbacks;
		std::vector<u64> mWorkQueue;


		std::vector<Channel> mRequestChls, mListenChls;
	};

}
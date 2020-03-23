#include "AmmrClient.h"


#include "dEnc/tools/MultiKeyAES.h"
#include <cryptoTools/Crypto/RandomOracle.h>
#include "dEnc/dprf/Npr03AsymDprf.h"
#include "dEnc/dprf/Npr03SymDprf.h"

namespace dEnc
{

    template<typename DPRF>
	void AmmrClient<DPRF>::init(u64 partyIdx, block seed, DPRF* dprf)
	{
		mDprf = dprf;
		mPartyIdx = partyIdx;
		mPrng.SetSeed(seed);
	}


    template<typename DPRF>
    void AmmrClient<DPRF>::encrypt(span<block> ptxt, std::vector<block>& ctxt)
	{
		// Sample randomness rho for the commitment
		block p = mPrng.get<block>();
		block alpha;

		// hash the {message, rho} to get the DPRF input
		oc::RandomOracle H(sizeof(block));
		H.Update((u8*)ptxt.data(), ptxt.size() * sizeof(block));
		H.Update(p);
		H.Final(alpha);

		// eval DPRF(x)
		auto fx = mDprf->eval(alpha);

		// expend the DPRF to get a key and tag. This is a PRG (AES counter mode).
        oc::AES enc(fx);

		// append the preable to the ciphertext
		ctxt.resize(ptxt.size() + 3);
		ctxt[0] = oc::toBlock(mPartyIdx);
		ctxt[1] = alpha;
		ctxt[2] = enc.ecbEncBlock(oc::ZeroBlock) ^ p;

		auto dest = ctxt.begin() + 3;
		auto src = ptxt.data();
        enc.ecbEncCounterMode(1, { dest, ctxt.end() } );

		for (u64 i = 0; i < ptxt.size(); ++i)
		{
			*dest = *dest  ^ *src;
			++dest;
			++src;
		}
	}

    template<typename DPRF>
    AsyncEncrypt AmmrClient<DPRF>::asyncEncrypt(span<block> ptxt, std::vector<block>& ctxt)
	{
        struct State
        {
            State(span<block>d, std::vector<block>& c) :ptxt(d), ctxt(c) {}

            span<block> ptxt;
            std::vector<block>& ctxt;
            AsyncEval async;
        };
        auto state = std::make_shared<State>(ptxt, ctxt);

        // Sample randomness rho for the commitment
        block p = mPrng.get<block>();
        block alpha;

		// hash the {message, rho} to get the DPRF input
		oc::RandomOracle H(sizeof(block));
		H.Update((u8*)ptxt.data(), ptxt.size() * sizeof(block));
		H.Update(p);
		H.Final(alpha);


        // append the preable to the ctxt
        state->ctxt.resize(state->ptxt.size() + 3);
        state->ctxt[0] = oc::toBlock(mPartyIdx);
        state->ctxt[1] = alpha;
        state->ctxt[2] = p;

		// eval DPRF(x)
        state->async = mDprf->asyncEval(alpha);

        // complete the rest of the encryption proceedure when the 
        // user calls the completion handle, ae.get().
		AsyncEncrypt ae;

		ae.get = [state]()
		{
            // block until the DPRF has been fully evaluated
			auto fx = state->async.get();

            // set the key
			oc::AES enc(fx[0]);

            state->ctxt[2] = state->ctxt[2] ^ enc.ecbEncBlock(oc::ZeroBlock);
			auto dest = state->ctxt.begin() + 3;
			auto src = state->ptxt.begin();
            auto size = state->ptxt.size();
            enc.ecbEncCounterMode(1, { dest, state->ctxt.end() });

			for (u64 i = 0; i < size; ++i)
			{
				*dest = *dest  ^ *src;
				++dest;
				++src;
			}
		};
		return ae;
	}

    template<typename DPRF>
    AsyncEncrypt AmmrClient<DPRF>::asyncEncrypt(
        span<std::vector<block>> d, 
        std::vector<std::vector<block>>& c)
	{
        struct State
        {
            State(span<std::vector<block>> d, span<std::vector<block>> c) :
                ptxts(d),
                ctxts(c) {}

            span<std::vector<block>> ptxts, ctxts;
            AsyncEval async;
        };


        std::vector<block> alphas(d.size());
        c.resize(d.size());
        auto state = std::make_shared<State>(d, c);

        for (u64 i = 0; i < d.size(); ++i)
		{
            auto& ctxt = state->ctxts[i];

            ctxt.resize(3 + state->ptxts[i].size());

            ctxt[0] = oc::toBlock(mPartyIdx);
			auto& alpha = ctxt[1];
			auto& p = ctxt[2];

			p = mPrng.get<block>();

			// hash the {message, rho} to get the DPRF input
            oc::RandomOracle H(sizeof(block));
			H.Update((u8*)d[i].data(), d[i].size() * sizeof(block));
			H.Update(p);
			H.Final(alpha);

            alphas[i] = alpha;
		}

		// eval DPRF(x)
        state->async = mDprf->asyncEval(alphas);

		AsyncEncrypt ae;

		ae.get = [state]()
		{
			auto fxx = state->async.get();
			for (u64 i = 0; i < state->ptxts.size(); ++i)
			{
				auto& ptxt = state->ptxts[i];
				auto& ctxt = state->ctxts[i];
				auto& fx = fxx[i];

				// expend the DPRF to get a key and tag
				oc::AES enc(fx);

				// append the preable to the ctxt
				ctxt[2] = ctxt[2] ^ enc.ecbEncBlock(oc::ZeroBlock);

				auto dest = ctxt.begin() + 3;
				auto src = ptxt.begin();
                enc.ecbEncCounterMode(1, { dest, ctxt.end() });

				for (u64 j = 0; j < ptxt.size(); ++j)
				{
					*dest = *dest  ^ *src;
					++dest;
					++src;
				}
			}

		};
		return ae;

	}


    template<typename DPRF>
    void AmmrClient<DPRF>::decrypt(span<block> ctxt, std::vector<block>& ptxt)
	{
        if(ctxt.size() < 4)            
            throw std::runtime_error("ciphertext is too small. " LOCATION);

		//auto& partyID = *(u64*)ctxt.ptxt();
		auto& alpha = ctxt[1];

		// DPRF eval
		auto fx = mDprf->eval(alpha);

		// append the preable to the ctxt
		ptxt.resize(ctxt.size() - 3);

        // expend the DPRF to get a key and 
		// encrypt the message using counter mode.
        oc::AES enc(fx);
        enc.ecbEncCounterMode(1, ptxt);

		auto p = enc.ecbEncBlock(oc::ZeroBlock) ^ ctxt[2];

		auto src = ctxt.begin() + 3;
		auto dest = ptxt.begin();
		for (u64 i = 0; i < ptxt.size(); ++i)
		{
			*dest = *dest  ^ *src;
			++dest;
			++src;
		}

        oc::RandomOracle H(sizeof(block));
		H.Update((u8*)ptxt.data(), ptxt.size() * sizeof(block));
		H.Update(p);
		block alpha2;
		H.Final(alpha2);

		if (neq(alpha, alpha2))
			throw std::runtime_error("alpha mismatch" LOCATION);
	}

    template<typename DPRF>
    AsyncDecrypt AmmrClient<DPRF>::asyncDecrypt(span<block> ctxt, std::vector<block>& ptxt)
	{

        if (ctxt.size() < 4)
            throw std::runtime_error("ciphertext is too small. " LOCATION);

        // allocate space for the ptxt.
        ptxt.resize(ctxt.size() - 3);

        struct State {
            span<block> ctxt, ptxt;
            AsyncEval async;
        };

		// DPRF eval
        auto state = std::make_shared<State>();
        state->ctxt = ctxt;
        state->ptxt = ptxt;
        state->async = mDprf->asyncEval(ctxt[1]);

		AsyncDecrypt ae;

		ae.get = [state]()
		{

			auto fx = state->async.get();
            auto& ptxt = state->ptxt;
            auto& ctxt = state->ctxt;

			// expend the DPRF to get a key and 
			// encrypt the message using counter mode.
			oc::AES enc(fx[0]);
			enc.ecbEncCounterMode(1, ptxt);

			auto p = enc.ecbEncBlock(oc::ZeroBlock) ^ ctxt[2];

			auto src = ctxt.begin() + 3;
			auto dest = ptxt.begin();
			for (u64 i = 0; i < ptxt.size(); ++i)
			{
				*dest = *dest  ^ *src;
				++dest;
				++src;
			}

            oc::RandomOracle H(sizeof(block));
            H.Update((u8*)ptxt.data(), ptxt.size() * sizeof(block));
			H.Update(p);
			block alpha2;
			H.Final(alpha2);

            auto& alpha = state->ctxt[1];
            if (neq(alpha, alpha2))
				throw std::runtime_error("alpha mismatch" LOCATION);
		};

		return ae;
	}



    template<typename DPRF>
    AsyncDecrypt AmmrClient<DPRF>::asyncDecrypt(
        span<std::vector<block>> ctxts,
        std::vector<std::vector<block>>& ptxts)
	{
        struct State
        {
            span<std::vector<block>> ctxts, ptxts;
            AsyncEval async;
        };

        std::vector<block> alphas(ctxts.size());

        ptxts.resize(ctxts.size());

		for (u64 i = 0; i < ctxts.size(); ++i)
		{
            if (ctxts[i].size() < 4)
                throw std::runtime_error("ciphertext is too small. " LOCATION);

            alphas[i] = ctxts[i][1];
            ptxts[i].resize(ctxts[i].size() - 3);
		}

		AsyncDecrypt ae;
        auto state = std::make_shared<State>();
        state->ctxts = ctxts;
        state->ptxts = ptxts;
        state->async = mDprf->asyncEval(alphas);

		ae.get = [state]()
		{
			auto fxx = state->async.get();
            auto& ctxts = state->ctxts;
            auto& ptxts = state->ptxts;

			for (u64 i = 0; i < ctxts.size(); ++i)
			{
				auto& ctxt = ctxts[i];
				auto& ptxt = ptxts[i];
				auto& fx = fxx[i];
				auto& alpha = ctxt[1];

				// expend the DPRF to get a key and 
				// encrypt the message using counter mode.
				oc::AES enc(fx);
				enc.ecbEncCounterMode(1, ptxt);

				auto p = enc.ecbEncBlock(oc::ZeroBlock) ^ ctxt[2];

				auto src = ctxt.begin() + 3;
				auto dest = ptxt.begin();
				for (u64 i = 0; i < ptxt.size(); ++i)
				{
					*dest = *dest  ^ *src;
					++dest;
					++src;
				}

                oc::RandomOracle H(sizeof(block));
                H.Update((u8*)ptxt.data(), ptxt.size() * sizeof(block));
				H.Update(p);
				block alpha2;
				H.Final(alpha2);

				if (neq(alpha, alpha2))
					throw std::runtime_error("alpha mismatch" LOCATION);
			}

		};

		return ae;
	}



    template<typename DPRF>
    void AmmrClient<DPRF>::close()
	{
		mDprf->close();
	}

    
    template class AmmrClient<Npr03AsymDprf>;

    template class AmmrClient<Npr03SymDprf>;
}

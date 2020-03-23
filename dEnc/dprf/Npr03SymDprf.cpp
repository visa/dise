#include "Npr03SymDprf.h"
#include <boost/math/special_functions/binomial.hpp>

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/MatrixView.h>
namespace dEnc {


	Npr03SymDprf::~Npr03SymDprf()
	{
        close();

        // if we have started listening to the network, then 
        // wait for the server callbacks to complete.
		if (mServerListenCallbacks.size())
			mServerDone.get();
	}



    void Npr03SymDprf::MasterKey::KeyGen(u64 n, u64 m, PRNG & prng)
    {

        // each subkey i will be distributed to subsetSize-out-of-n of the parties.
        auto subsetSize = n - m + 1;

        // the number of sub keys
        i64 d = boost::math::binomial_coefficient<double>(n, subsetSize);

        // the number of keys each party will hold.
        i64 cc = boost::math::binomial_coefficient<double>(n - 1, subsetSize - 1);

        // A matrix where row i contains a list of the key that party i will hold.
        subKeys.resize(n, cc);
        keyStructure.resize(n, cc);

        // currentPartyKeyCount[i] is the number of keys that have been given to party i.
        std::vector<u64> currentPartyKeyCount(n, 0);

        // a vector that will hold the current subset of the parties what will
        // receive the current key, keys[curKeyIdx]
        std::vector<u64> cur; cur.reserve(subsetSize);
        u64 curKeyIdx = 0;

        // Gnerate the keys using the PRNG.
        keys.resize(d);
        prng.get(keys.data(), keys.size());


        // This is a recursive function which iterates through every
        // subset of {0, 1, ..., n-1} with size subsetSize. When
        // such a subset is found then it holds that remainingRoom == 0. To this
        // subset we give the key, keys[curKeyIdx]. Then the next 
        // such subset is found and given the next key.
        std::function<void(u64, u64)> go = [&](u64 curSize, u64 remainingRoom)
        {
            if (remainingRoom)
            {
                // the idea here is that we will consider the following sets
                // cur' = cur U { i }
                // cur' = cur U { i+1 }
                //    ...
                // cur' = cur U { n-1 }
                // For each of these we will recurse until we get a large enough set.
                // Note that cur is a subset of  {0,1,...,i-1} and therefore we wont
                // repeat any index.
                for (u64 i = curSize; i < n; ++i)
                {
                    cur.push_back(i);
                    go(i + 1, remainingRoom - 1);
                    cur.pop_back();
                }
            }
            else
            {
                // ok, cur now holds the next subset of parties. Lets give 
                // them all the next key.
                for (u64 i = 0; i < cur.size(); ++i)
                {
                    // the party Idx
                    auto p = cur[i];
                    // the next free key position for this party
                    auto jj = currentPartyKeyCount[p]++;

                    keyStructure(p, jj) = curKeyIdx;
                    subKeys(p, jj) = keys[curKeyIdx];
                }
                ++curKeyIdx;
            }
        };


        go(0, subsetSize);
    }



	void Npr03SymDprf::init(
		u64 partyIdx,
		u64 m,
		span<Channel> requestChls,
		span<Channel> listenChls,
		block seed,
        oc::Matrix<u64>& keyStructure,
        span<block> keys)
	{

		mPartyIdx = partyIdx;
		mRequestChls = { requestChls.begin(), requestChls.end() };
		mListenChls = { listenChls.begin(), listenChls.end() };
		mPrng.SetSeed(seed);
        mIsClosed = false;

		mM = m;
		mN = mRequestChls.size() + 1;

        // Each subKey k_i will be distributed to subsetSize-out-of-n of the parties.
        auto subsetSize = mN - mM + 1;
        
        // the totak number of k_i
        mD = boost::math::binomial_coefficient<double>(mN, subsetSize);

		mDefaultKeys.resize(mN);
		for (u64 i = mPartyIdx, j = 0; j < mM; ++j)
		{
			constructDefaultKeys(i, keyStructure, keys);

            // i = i - 1 mod mN
            // mathematical mod where i can not be negative
			i = i ? (i - 1) : mN - 1;
		}


		startListening();
	}

	void Npr03SymDprf::serveOne(span<u8> rr, u64 chlIdx)
	{
        TODO("Add support for allowing the request to specify which parties are involved in this evaluation. "
            "This can be done by sending a bit vector of the parties that contribute keys and then have this "
            "party figure out which keys to use in a similar way that constructDefaultKeys(...) does it.");

        // Right now we only support allowing 16 bytes to be the OPRF input.
        // When a multiple is sent, this its interpreted as requesting 
        // several OPRF evaluations.
		if(rr.size() % sizeof(block))
			throw std::runtime_error(LOCATION);

        // Get a view of the data as blocks.
		span<block> request( (block*)rr.data(), rr.size() / sizeof(block) );

        // a vector to hold the OPRF output shares.
		std::vector<oc::block> fx(request.size());

        // compute the partyIdx based on the channel idx.
		auto pIdx = chlIdx + (chlIdx >= mPartyIdx ? 1 : 0);

		if (request.size() == 1)
		{
            // If only one OPRF input is used, we vectorize the AES evaluation
            // so that several keys are evaluated in parallel.

			fx.resize(mDefaultKeys[pIdx].mAESs.size());
			mDefaultKeys[pIdx].ecbEncBlock(request[0], fx.data());

			for (u64 j = 1; j < fx.size(); ++j)
				fx[0] = fx[0] ^ fx[j];

			fx.resize(1);
		}
		else
		{
            // If several OPRF values are evaluated in parallel, then we apply a single key to several
            // OPRF inputs at a time. 

			auto numKeys = mDefaultKeys[pIdx].mAESs.size();
			std::vector<block> buff2(request.size());
			for (u64 i = 0; i < numKeys; ++i)
			{
				mDefaultKeys[pIdx].mAESs[i].ecbEncBlocks(request.data(), request.size(), buff2.data());
				for (u64 j = 0; j < request.size(); ++j)
				{
					fx[j] = fx[j] ^ buff2[j];
				}
			}
		}

        // send back the OPRF output share.
		mListenChls[chlIdx].asyncSend(std::move(fx));
	}

	block Npr03SymDprf::eval(block input)
	{
        // simply call the async version and then block for it to complete.
		return asyncEval(input).get()[0];
	}

	AsyncEval Npr03SymDprf::asyncEval(block input)
	{
        TODO("Add support for sending the party identity for allowing encryption to be distinguished from decryption. ");

        // Send the OPRF input to the next m-1 parties
		auto end = mPartyIdx + mM;
		for (u64 i = mPartyIdx + 1; i < end; ++i)
		{
			auto c = i % mN;
			if (c > mPartyIdx) --c;

			mRequestChls[c].asyncSendCopy(&input, 1);
		}


        // Set up the completion callback "AsyncEval".
        // This object holds a function that is called when 
        // the user wants to async eval to complete. This involves
        // receiving the OPRF output shares from the other parties
        // and combining them with the local share.
		AsyncEval ae;

        struct State
        {
            State(u64 m)
            :fx(m)
            ,async(m-1)
            {}
		    std::vector<block> fx;
            std::vector<std::future<void>> async;

        };
        // allocate space to store the OPRF output shares
        auto w = std::make_shared<State>(mM);

        // Futures which allow us to block until the repsonces have 
        // been received


        // Evaluate the local OPRF output share.
        std::vector<block> buff(mDefaultKeys[mPartyIdx].mAESs.size());
        mDefaultKeys[mPartyIdx].ecbEncBlock(input, buff.data());

        // store this share at the end of fx
		auto& b = w->fx.back();
        b = oc::ZeroBlock;
		for (u64 i = 0; i < buff.size(); ++i)
			b = b ^ buff[i];

        // queue up the receive operations to receive the OPRF output shares
		for (u64 i = mPartyIdx + 1, j = 0; j < w->async.size(); ++i, ++j)
		{
			auto c = i % mN;
			if (c > mPartyIdx) --c;

			w->async[j] = mRequestChls[c].asyncRecv(&w->fx[j], 1);
		}

        // This function is called when the user wants the actual 
        // OPRF output. It must combine the OPRF output shares
        ae.get = [this, w = std::move(w)]() mutable ->std::vector<block> 
        {
            // block until all of the OPRF output shares have arrived.
            for (u64 i = 0; i < mM - 1; ++i)
                w->async[i].get();

            // XOR all of the output shares
            std::vector<block> ret{ w->fx[0] };
            for (u64 i = 1; i < mM; ++i)
                ret[0] = ret[0] ^ w->fx[i];

            return (ret);
        };
		return ae;
	}

	AsyncEval Npr03SymDprf::asyncEval(span<block> in)
	{
        struct State
        {
            std::vector<block> out, in, fxx;
            std::unique_ptr<std::future<void>[]> async;
        };
        auto state = std::make_shared<State>();

        // allocate space to store the OPRF outputs.
        state->out.resize(in.size());


        // Copy the inputs into a shared vector so that it 
        // can be sent to all parties using one allocation.
        state->in.insert(state->in.end(), in.begin(), in.end());

        // send this input to all parties
		auto end = mPartyIdx + mM;
		for (u64 i = mPartyIdx + 1; i < end; ++i)
		{
			auto c = i % mN;
			if (c > mPartyIdx) --c;

            // This send is smart and will increment the ref count of
            // the shared pointer
			mRequestChls[c].asyncSend(state->in);
		}

		auto numKeys = mDefaultKeys[mPartyIdx].mAESs.size();

        // evaluate the local OPRF output shares
		std::vector<block> buff2(in.size());
		for (u64 i = 0; i < numKeys; ++i)
		{
			mDefaultKeys[mPartyIdx].mAESs[i].ecbEncBlocks(in.data(), in.size(), buff2.data());
            auto& out = state->out;
			for (u64 j = 0; j < out.size(); ++j)
			{
				out[j] = out[j] ^ buff2[j];
			}
		}

        // allocate space to store the other OPRF output shares
		auto numRecv = (mM - 1);
        state->fxx.resize(numRecv* in.size());
		//auto fxx(new block[numRecv * in.size()]);

        // Each row of fx will hold a the OPRF output shares from one party
		oc::MatrixView<block> fx(state->fxx.begin(), state->fxx.end(), in.size());

        // allocate space to store the futures which allow us to block until the
        // other OPRF output shares have arrived.
        state->async.reset(new std::future<void>[numRecv]);

        // schedule the receive operations for the other OPRF output shares.
		for (u64 i = mPartyIdx + 1, j = 0; j < numRecv; ++i, ++j)
		{
			auto c = i % mN;
			if (c > mPartyIdx) --c;

			state->async[j] = mRequestChls[c].asyncRecv(fx[j]);
		}

        // construct the completion handler that is called when the user wants to 
        // actual OPRF output. This requires blocking to receive the OPRF output
        // and then combining it.
		AsyncEval ae;
		ae.get = [state, numRecv, fx]() mutable -> std::vector<block>
		{
            auto& o = state->out;
			for (u64 i = 0; i < numRecv; ++i)
			{
                state->async[i].get();

				auto buff2 = fx[i];
				for (u64 j = 0; j < o.size(); ++j)
				{
					o[j] = o[j] ^ buff2[j];
				}
			}
			return std::move(o);
		};

		return ae;
	}

	void Npr03SymDprf::startListening()
	{

		mRecvBuff.resize(mRequestChls.size());
		mListens = mListenChls.size();
		mServerListenCallbacks.resize(mListenChls.size());


		for (u64 i = 0; i < mListenChls.size(); ++i)
		{
			mServerListenCallbacks[i] = [&, i]()
			{
                // If the client sends more than one byte, interpret this
                // as a request to evaluate the DPRF.
				if (mRecvBuff[i].size() > 1)
				{
                    // Evaluate the DPRF and send the result back.
					serveOne(mRecvBuff[i], i);

                    // Eueue up another receive operation which will call 
                    // this callback when the request arrives.
					mListenChls[i].asyncRecv(mRecvBuff[i], mServerListenCallbacks[i]);
				}
				else
				{
                    // One byte means that the cleint is done requiresting 
                    // DPRf evaluations. We can close down.
					if (--mListens == 0)
					{
                        // If this is the last callback to close, set
                        // the promise that denotes that the server
                        // callback loops have all completed.
						mServerDoneProm.set_value();
					}
				}
			};

			mListenChls[i].asyncRecv(mRecvBuff[i], mServerListenCallbacks[i]);
		}
	}

	void Npr03SymDprf::constructDefaultKeys(u64 pIdx, oc::Matrix<u64>& mKeyIdxs, span<block> myKeys)
    {
        // Default keys are computed taking all the keys that party pIdx has
        // followed by all the missing keys party pIdx+1 has and so on.

        // A list indicating which keys have already been accounted for.
		std::vector<u8> keyList(mD, 0);
		auto p = pIdx;

        // First lets figure out what keys are been provided 
        // by parties {pIdx, pIdx+1, ..., mPartyIdx-1} 
		while (p != mPartyIdx)
		{
			for (u64 i = 0; i < myKeys.size(); ++i)
				keyList[mKeyIdxs(p, i)] = 1;

			p = (p + 1) % mN;
		}

        // Now lets see if any remaining keys that this party can contribute.
		std::vector<block> keys; keys.reserve(myKeys.size());
		for (u64 j = 0; j < myKeys.size(); ++j)
		{
			if (keyList[mKeyIdxs(mPartyIdx, j)] == 0)
				keys.push_back(myKeys[j]);
		}

        // initialize the "multi-key" AES instance with these keys.
		mDefaultKeys[pIdx].setKeys(keys);
	}

	void Npr03SymDprf::close()
	{
        if (mIsClosed == false)
        {
            mIsClosed = true;

		    u8 close[1];
		    close[0] = 0;

            // closing the channel is done by sending a single byte.
		    for (auto& c : mRequestChls)
			    c.asyncSendCopy(close, 1);

        }
	}

}

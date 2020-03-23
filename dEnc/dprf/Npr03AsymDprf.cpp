#include "Npr03AsymDprf.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Log.h"

namespace dEnc
{
    Npr03AsymDprf::~Npr03AsymDprf()
    {
        close();

        if (mServerListenCallbacks.size())
            mServerDone.get();
    }


    std::function<Npr03AsymDprf::Num(u64 i)> Npr03AsymDprf::interpolate(span<Num> fx, span<Num> xi)
    {
        std::vector<Num> fxx(fx.begin(), fx.end());
        std::vector<Num> xxi(xi.begin(), xi.end());


        auto L = [fxx, xxi](u64 xx)
        {
            auto m = fxx.size();
            Num ret(0);
            Num x(xx);

            // Now compute the degree m-1 lagrange polynomial L(x) such that
            //       L(i) = fx[i]   for i \in {0,...,m}

            // The formula is
            //    L(x) = \sum_{i=0,...,m}   fx[i] * l_i(x)
            // where
            //    l_i(x) = \prod_{m=0,...,m;  m!=i}   (x - x_i) / (x_i - x_j)
            //           = \prod_{m=0,...,m;  m!=i}   (x - i) / (i - j)     since x_i = i
            std::vector<std::function<Num(const Num&)>> l(m);

            Num one(1);
            for (u64 i = 0; i < m; ++i)
            {
                //l[i] = [&,i](const Num& x)
                //{
                Num l_i(1);

                for (u64 j = 0; j < m; ++j)
                    if (j != i)
                        l_i *= (x - xxi[j]) / (xxi[i] - xxi[j]);

                //return l_i;
                //};

                ret += fxx[i] * l_i;// l[i](x);
            }
            return ret;
        };

        return L;
    }

    std::function<Npr03AsymDprf::Num(u64 i)> Npr03AsymDprf::interpolate(span<Num> fx)
    {
        std::vector<Num> xi; xi.reserve(fx.size());
        for (u64 i = 0; i < fx.size(); ++i)
            xi.emplace_back(i32(i));

        return interpolate(fx, xi);
    }



    void Npr03AsymDprf::MasterKey::KeyGen(u64 n, u64 m, PRNG & prng, Type type)
    {
        oc::REllipticCurve curve;

        // gnerate m random points wich will define our m-1 degree polynomial
        std::vector<Num> fx(m);
        for (u64 i = 0; i < m; ++i)
            fx[i].randomize(prng);

        // interpolate these points. The 
        mKeyPoly = interpolate(fx);

        // The master key is the polynomial at zero.
        mMasterKey = fx[0] /* == mKeyPoly(0) */;

        // The key shars are the polynomial at 1, 2, ..., n
        mKeyShares.resize(n);
        for (u64 i = 0; i < n; ++i)
        {
            mKeyShares[i] = mKeyPoly(i + 1);
            //std::cout << "sk[" << i << "] " << mKeyShares[i] << std::endl;
        }

        // For malicious security, we need to compute
        if (type == Type::Malicious)
        {
            auto gen = curve.getGenerator();
            mCommits.resize(n);
            for (u64 i = 0; i < n; ++i)
                mCommits[i] = gen * mKeyShares[i];

        }
        else if (type == Type::PublicVarifiable)
        {
            throw std::runtime_error("PublicVarifiable is not implemented. " LOCATION);
        }
    }

    void Npr03AsymDprf::init(
        u64 partyIdx,
        u64 m,
        span<Channel> requestChls,
        span<Channel> listChls,
        block seed,
        Type  type,
        Num sk,
        span<Point> gSks)
    {
        mPartyIdx = partyIdx;
        mM = m;
        mN = requestChls.size() + 1;
        mType = type;
        mPrng.SetSeed(seed);
        mIsClosed = false;

        // Make sure gSks is the right size 
        if (gSks.size() != mN * (type == Type::Malicious))
            throw std::runtime_error("Commitments to the secret keys is required for malicious security. " LOCATION);

        mRequestChls = { requestChls.begin(), requestChls.end() };
        mListenChls = { listChls.begin(), listChls.end() };

        // Copy this parties secret key
        mSk = sk;

        // Copy the commitments to the other secret keys
        mGSks = { gSks.begin(), gSks.end() };

        // Take a copy of the generator
        oc::REllipticCurve curve;
        mGen = curve.getGenerator();

        // Precompute the lagrange interpolation coefficients
        mDefaultLag.resize(mM);

        // pre compute a vector containing { mPartyIdx + 1, mPartyIdx + 2, ..., mPartyIdx + m}
        std::vector<Num> xi(mM);
        for (u64 i = 0, j = mPartyIdx; i < mM; ++i, ++j)
            xi[i] = j % mN + 1;


        // mDefaultLag[i] will hold the lagrange coefficient to use
        // with party i.
        for (i64 i = 0; i < mM; ++i)
        {
            auto& l_i = mDefaultLag[i];

            l_i = 1;
            for (u64 j = 0; j < m; ++j)
                if (j != i) l_i *= xi[j] / (xi[j] - xi[i]);
        }

        // cache some values that will be used as temporary storage
        mTempPoints.resize(6);
        mTempNums.resize(6);

        // Start the service that listens to OPRF evaluations requests 
        // from the other parties.
        startListening();
    }

    void Npr03AsymDprf::serveOne(span<u8> request, u64 outputPartyIdx)
    {
        oc::REllipticCurve curve;
        int pointSize = mGen.sizeBytes();
        int numSize = mSk.sizeBytes();


        // Make sure that the requests are a 
        if (request.size() % sizeof(block))
            throw std::runtime_error(LOCATION);

        auto numRequests = request.size() / sizeof(block);

        auto sizePer = (mType != Type::SemiHonest) ?
            pointSize * 3 + numSize :
            pointSize;

        std::vector<u8> response(numRequests * sizePer);

        auto sIter = (block*)request.data();
        auto dIter = response.data();

        for (u64 i = 0; i < numRequests; ++i)
        {
            serveOne(sIter[i], span<u8>(dIter, sizePer), outputPartyIdx);

            dIter += sizePer;
        }

        mListenChls[outputPartyIdx].asyncSend(std::move(response));
    }

    void Npr03AsymDprf::serveOne(block in, span<u8> dest, u64 outputPartyIdx)
    {
        oc::REllipticCurve curve;

        // hash the input to a random point
        oc::REccPoint v;
        v.randomize(in);

        if (mType != Type::SemiHonest)
        {
            // compute the challenge by hashing the input.
            Num c;
            oc::RandomOracle ro(sizeof(block));
            ro.Update(in ^ oc::AllOneBlock);
            block challenge;
            ro.Final(challenge);
            c.randomize(challenge);


            // compute the zero knowledge proof with respect to c

            Num r(mPrng);
            auto a1 = mGen * r;
            auto a2 = v * r;
            auto z = r + mSk * c;

            // Compute the output share
            v *= mSk;

            // serialize the output and proof
            auto iter = dest.data();
            v.toBytes(iter); iter += v.sizeBytes();
            a1.toBytes(iter);  iter += a1.sizeBytes();
            a2.toBytes(iter);  iter += a2.sizeBytes();
            z.toBytes(iter);   iter += z.sizeBytes();

        }
        else
        {
            // Compute and serialize the output share
            v *= mSk;
            v.toBytes(dest.data());
        }
    }

    block Npr03AsymDprf::eval(block input)
    {
        return asyncEval(input).get()[0];
    }

    AsyncEval Npr03AsymDprf::asyncEval(block input)
    {
        return asyncEval({ &input, 1 });
    }

    // A struct that holds some intermidiate values using the async operation
    struct Workspace
    {
        // An instance of a single evaluation
        struct W {
            // The input point
            oc::REccPoint v;

            // The output share
            oc::REccPoint y;

            // The challenge 
            oc::REccNumber c;
        };

        // a vector to hold the temps for many (concurrent)
        // evluations
        std::vector<W> w;

        /**
         * Initialize another set of temporaries for a set of
         * n parallel evaluations of the DPRF
         * @param[in] n  - The number of parallel evluations to allocate
         */
        Workspace(u64 n)
        {
            w.resize(n);
        }

        // a buffer to receive the DPRF output shares into.
        oc::Matrix<u8> buff2;

        // a set of futures that will be fulfilled when the 
        // DPRF output shares have arrived.
        std::vector<std::future<void>> asyncs;
    };

    AsyncEval Npr03AsymDprf::asyncEval(span<block> in)
    {
        // create a shared copy of the input and send it to the other
        // parties as the OPRF input.
        auto sendBuff = std::make_shared<std::vector<block>>(in.begin(), in.end());
        for (u64 i = 1, j = mPartyIdx; i < mM; ++i, ++j)
        {
            mRequestChls[j % mRequestChls.size()].asyncSend(sendBuff);
        }

        oc::REllipticCurve curve;

        // This "Workspace" will hold all of the temporaries
        // until the operation has completed
        auto w = std::make_shared<Workspace>(in.size());

        auto pointSize = w->w[0].v.sizeBytes();
        auto numSize = w->w[0].c.sizeBytes();


        for (u64 i = 0; i < in.size(); ++i)
        {
            auto& v = w->w[i].v;
            auto& y = w->w[i].y;
            auto& c = w->w[i].c;


            // Hash each of the inputs to a random point on the ceruve
            w->w[i].v.randomize(in[i]);

            // Perform the interpolcation in the exponent
            y = v * (mDefaultLag[0] * mSk);

            if (mType != Type::SemiHonest)
            {
                // compute the challenge value which we use later
                oc::RandomOracle ro(sizeof(block));
                ro.Update(in[i] ^ oc::AllOneBlock);
                block challenge;
                ro.Final(challenge);
                c.randomize(challenge);
            }
        }

        // The size in bytes that we expect to be returned
        auto isMal = mType != Type::SemiHonest;
        auto size = (1 + isMal * 2) * pointSize + isMal * numSize;

        // allocate enough space to receive the OPRF output and proofs
        w->buff2.resize((mM - 1), size * in.size());
        w->asyncs.resize(mM - 1);
        for (u64 i = 1, j = mPartyIdx; i < mM; ++i, ++j)
        {
            auto& chl = mRequestChls[j % mRequestChls.size()];


            using Container = decltype(w->buff2[i - 1]);

            static_assert(oc::is_container<Container>::value &&
                !oc::has_resize<Container, void(typename Container::size_type)>::value, "");

            // Schedule the OPRF output to be recieved and store it
            // in row i-1 of w->buff2
            w->asyncs[i - 1] = chl.asyncRecv(w->buff2[i - 1]);
        }

        // Construct the completion event that is executed when the
        // user wants to complete the async eval.
        AsyncEval ae;
        ae.get = [this, w, pointSize]()->std::vector<block>
        {
            auto inSize = w->w.size();
            oc::REllipticCurve curve;

            Point vk, vz, gz, a1, a2;
            Num s;
            std::vector<block> ret(inSize);

            // Process the OPRF output shares one at a time
            for (u64 i = 1, j = mPartyIdx; i < mM; ++i, ++j)
            {
                // block for the data to arrive.
                w->asyncs[i - 1].get();

                // pointer into the output share
                auto iter = w->buff2[i - 1].data();

                for (u64 inIdx = 0; inIdx < inSize; ++inIdx)
                {
                    Point& v = w->w[inIdx].v;
                    Point& y = w->w[inIdx].y;
                    Num& c = w->w[inIdx].c;

                    // read in the output share = H(x)^k_i
                    vk.fromBytes(iter);
                    iter += vk.sizeBytes();

                    // y = SUM_i  H(x)^{\lambda_i * k_i}
                    y += vk * mDefaultLag[i];

                    if (mType == Type::Malicious)
                    {
                        // if malicious, then parse the ZK proof

                        a1.fromBytes(iter);  iter += a1.sizeBytes();
                        a2.fromBytes(iter);  iter += a2.sizeBytes();
                        s.fromBytes(iter);   iter += s.sizeBytes();

                        auto pIdx = (mPartyIdx + i) % mN;

                        // Compute the check values
                        gz = mGen * s;
                        vz = v * s;

                        a1 += mGSks[pIdx] * c;
                        a2 += vk * c;

                        // make sure the proof matches
                        if (gz != a1 || vz != a2)
                            throw std::runtime_error(LOCATION);

                    }
                    else if (mType == Type::PublicVarifiable)
                    {
                        throw std::runtime_error("PublicVarifiable is not implemented. " LOCATION);

                        //TODO("update this to use real proof. Currently just do dummy work too approximate the efficienty");
                        //vz = v * s;
                        //a2 += vk * c;
                    }
                }
            }

            // Hash the output value to get a random string
            std::vector<u8> buff(pointSize);
            for (u64 inIdx = 0; inIdx < inSize; ++inIdx)
            {
                oc::REccPoint& y = w->w[inIdx].y;
                y.toBytes(buff.data());

                oc::RandomOracle H(sizeof(block));

                H.Update(buff.data(), buff.size());
                H.Final(ret[inIdx]);
            }

            return ret;
        };

        return ae;
    }


    void Npr03AsymDprf::startListening()
    {
        mServerDone = (mServerDoneProm.get_future());
        mRecvBuff.resize(mRequestChls.size());
        mListens = mListenChls.size();
        mServerListenCallbacks.resize(mListenChls.size());

        for (u64 i = 0; i < mListenChls.size(); ++i)
        {
            // If the client sends more than one byte, interpret this
            // as a request to evaluate the DPRF.
            mServerListenCallbacks[i] = [&, i]()
            {
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

    void Npr03AsymDprf::close()
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

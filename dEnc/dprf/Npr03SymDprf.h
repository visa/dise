#pragma once

#include <dEnc/Defines.h>
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Crypto/AES.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <condition_variable>

#include "Dprf.h"
#include "dEnc/tools/MultiKeyAES.h"

namespace dEnc {

    // DPRF class implementing the Naor,Pinkas,Reingold based on 
    // replicated secret sharing and any PRF. 
    // See http://www.wisdom.weizmann.ac.il/~naor/PAPERS/npr.pdf
    // See https://eprint.iacr.org/2018/727.pdf section 8.2
    class Npr03SymDprf : public Dprf
    {
    public:

        // A struct for holding and generating the master key.
        // This struct can be used to inititialize the parties.
        struct MasterKey
        {
            // A list of the individual KeyShare Shares
            std::vector<block> keys;

            // A matrixs encoding which party has which key.
            // The i'th row contains the list of the keys that party i holds.
            oc::Matrix<u64> keyStructure;

            // The i'th row of subKeys contains the keys for party i;
            oc::Matrix<block> subKeys;

            /**
             * Generates the keys shares for an m-out-of-n OPRF using the 
             * randomness provided by the prng
             * @param[in] n         - The number of parties in the OPRF protocol
             * @param[in] m         - The threshold of the OPRF protocol
             * @param[in] prng      - The randomness source used to generate the keys
             */
            void KeyGen(u64 n, u64 m, PRNG& prng);

            /**
             * Returns the keys that party partyIdx should use. The index of these keys
             * can be obtained by looking at subKeys.
             * @param[in] partyIdx  - The index of the party 
             */
            oc::span<block> getSubkey(u64 partyIdx) { return subKeys[partyIdx]; }
        };



        Npr03SymDprf()
            : mServerDone(mServerDoneProm.get_future())
        {}

        Npr03SymDprf(Npr03SymDprf&&) = default;

        virtual ~Npr03SymDprf();


        // Callbacks that are used when a new DPRF evaluation
        // arrived over the network, i.e. mServerListenCallbacks[i]
        // is called when party i sends a request.
        std::vector<std::function<void()>> mServerListenCallbacks;

        // The index of this party
        i64 mPartyIdx;
        // The total number of parties in the DPRF protocol
        u64 mN;
        // The DPRF threshold. This many parties must be contacted.
        u64 mM;
        // The total number of key shares
        u64 mD;

        // Random number generator
        oc::PRNG mPrng;

        // Internal flag that determines if the OPRF is currently closed.
        bool mIsClosed = true;

        // Pre-computer subsets of the keys that to this party should
        // use then party i requrests an evaluation, i.e. mDefaultKeys[i].
        std::vector<MultiKeyAES> mDefaultKeys;

        /**
         * Initializes the DPRF with an existing key. 
         * @param[in] partyIdx     - The index of this party
         * @param[in] m            - The threshold of the scheme
         * @param[in] requestChls  - N Channels that eval requests should be sent over
         * @param[in] listenChls   - N Channels that should be listened to for eval requests
         * @param[in] seed         - A random seed
         * @param[in] keyStructure - A 2D array where row i lists they keys party i has.
         * @param[in] keys         - The keys that this party has
         */
        void init(
            u64 partyIdx,
            u64 m,
            span<Channel> requestChls,
            span<Channel> listenChls,
            block seed,
            oc::Matrix<u64>& keyStructure,
            span<block> keys);

        /**
         * The server routine which takes a request string (OPRF input)
         * and sends back the corresponding OPRF output share to the
         * specified party.
         * @param[in] request        - A 16 byte array containing the OPRF input
         * @param[in] outputPartyIdx - The index of the party that the response should be sent to 
         */
        virtual void serveOne(span<u8>request, u64 outputPartyIdx)override;

        /**
         * A blocking call to evaluate the OPRF on the provided input.
         * @param[in] input        - The OPRF input.
         */
        virtual block eval(block input)override;

        /**
         * A non blocking call to evaluate the OPRF. To complete the 
         * OPRF evaluation call AsyncEval::get();
         * @param[in] input        - The OPRF input.
         */
        virtual AsyncEval asyncEval(block input) override;

        /**
         * A non blocking call to evaluate several independent OPRF values. 
         * To complete the OPRF evaluation call AsyncEval::get();
         * @param[in] input        - The list of OPRF inputs.
         */
        virtual AsyncEval asyncEval(span<block> input) override;

        /**
         * Shuts down the servers that are listening for more OPRF requrests
         */
        virtual void close()override;


    private:
        /**
         * Starts the callback loop for listening for OPRF eval requests on the 
         * mListenChls Channels.
         */
        void startListening();

        /**
         * Precomputes the default keys that should be used when party pIdx contacts this party 
         * with an OPRF evaluation request. In the case that some of these parties are not
         * available a different set of keys may be requires. Implementing such a fucntionality
         * is future work.
         */
        void constructDefaultKeys(u64 pIdx, oc::Matrix<u64>& keyStructure, span<block> myKeys);

        // Buffers that are used to receive the client DPRF evaluation requests
        std::vector<std::vector<u8>> mRecvBuff;

        // A promise that is fulfilled when all of the server DPRF callbacks
        // have completed all of their work. This happens when all clients 
        // shut down the connections.
        std::promise<void> mServerDoneProm;

        // The future for mServerDoneProm.
        std::future<void> mServerDone;

        // The number of active callback loops. 
        std::atomic<u64> mListens;

        // Channels that the client should send their DPRF requests over.
        std::vector<Channel> mRequestChls;

        // Channels that the servers should listen to for DPRF requests.
        std::vector<Channel> mListenChls;
    };

}
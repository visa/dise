#pragma once

#include <dEnc/Defines.h>
#include <dEnc/dprf/Dprf.h>
#include <cryptoTools/Network/Endpoint.h>
namespace dEnc{

	struct AsyncEncrypt
	{
		std::function<void()> get;
	};

	typedef AsyncEncrypt AsyncDecrypt;


    template<typename DPRF>
	class AmmrClient
	{
	public:
        DPRF* mDprf;
		u64 mPartyIdx;
		PRNG mPrng;


        /**
         * Initializes the increction scheme using a pre-initialized
         * DPRF. 
         * @param[in] partyIdx - The index of the local party.
         * @param[in] seed     - A random seen used to generate encryptions.
         * @param[in] dprf     - A pre-initialized DPRF.
         */
		void init(u64 partyIdx, block seed, DPRF* dprf);

        /**
         * Synchonously encrypt the provided data.
         * @param[in] data     - The data to be encrypted.
         * @param[out] ctxt    - The resulting ciphertext.
         */ 
		void encrypt(span<block> data, std::vector<block>& ctxt);

        /**
         * Asynchonously encrypt the provided data. Returns a completion handle
         * AsyncEncrypt which must have AsyncEncrypt::get() called before the 
         * ciphertext is written to the output parameter ctxt.
         * @param[in] data     - The data to be encrypted.
         * @param[out] ctxt    - The resulting ciphertext.
         */
		AsyncEncrypt asyncEncrypt(span<block> data, std::vector<block>& ctxt);

        /**
         * Asynchonously encrypts a series of independent plaintexts. Returns 
         * a completion handle AsyncEncrypt which must have AsyncEncrypt::get() 
         * called before the ciphertext is written to the output parameter ctxt.
         * @param[in] data     - The list of plaintexts that should be encrypted.
         * @param[out] ctxt    - The location that each of the ciphertexts should be written to.
         */
		AsyncEncrypt asyncEncrypt(span<std::vector<block>> data, std::vector<std::vector<block>>& ctxt);


        /**
         * Synchonously decrypts ciphtertext. 
         * @param[in] ctxt     - The ciphertext that will be decrypted
         * @param[out] data    - The location that the plaintext will be written to.
         */
		void decrypt(span<block> ctxt, std::vector<block>& data);

        /**
         * Asynchonously decrypts a ciphertext. Returnsa completion handle 
         * AsyncDecrypt which must have AsyncDecrypt::get() called before 
         * the plaintext is written to the output parameter data.
         * @param[in] ctxt     - The list of ciphertexts that should be decrypted.
         * @param[out] data    - The location that each of the plaintexts should be written to.
         */
		AsyncDecrypt asyncDecrypt(span<block> ctxt, std::vector<block>& data);

        /**
         * Asynchonously decrypts a series of independent ciphertexts. Returns
         * a completion handle AsyncDecrypt which must have AsyncDecrypt::get()
         * called before the plaintext is written to the output parameter data.
         * @param[in] ctxt     - The list of ciphertexts that should be decrypted.
         * @param[out] data    - The location that each of the plaintexts should be written to.
         */
		AsyncDecrypt asyncDecrypt(span<std::vector<block>> ctxt, std::vector<std::vector<block>>& data);

		void close();
	};

}

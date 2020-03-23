#pragma once
#include <vector>
#include <cryptoTools/Crypto/AES.h>
#include "dEnc/Defines.h"

namespace dEnc
{


	class MultiKeyAES
	{
	public:
		std::vector<oc::AES> mAESs;

		MultiKeyAES() {};
		MultiKeyAES(span<block> keys)
		{
			setKeys(keys);
		}

		void setKeys(span<block> keys)
		{
			mAESs.resize(keys.size());
			for (u64 i = 0; i < mAESs.size(); ++i)
			{
				mAESs[i].setKey(keys[i]);
			}
		}

		void ecbEncBlock(const block& plaintext, block* cyphertexts) const
		{

			auto mainLoop = mAESs.size() / 8;
			auto finalLoop = mAESs.size() % 8;

			auto dest = cyphertexts;
			auto key = mAESs.data();
			for (int i = 0; i < mainLoop; ++i)
			{
				dest[0] = _mm_xor_si128(plaintext, key[0].mRoundKey[0]);
				dest[1] = _mm_xor_si128(plaintext, key[1].mRoundKey[0]);
				dest[2] = _mm_xor_si128(plaintext, key[2].mRoundKey[0]);
				dest[3] = _mm_xor_si128(plaintext, key[3].mRoundKey[0]);
				dest[4] = _mm_xor_si128(plaintext, key[4].mRoundKey[0]);
				dest[5] = _mm_xor_si128(plaintext, key[5].mRoundKey[0]);
				dest[6] = _mm_xor_si128(plaintext, key[6].mRoundKey[0]);
				dest[7] = _mm_xor_si128(plaintext, key[7].mRoundKey[0]);

				for (u64 j = 1; j < 10; ++j)
				{
					dest[0] = _mm_aesenc_si128(dest[0], key[0].mRoundKey[j]);
					dest[1] = _mm_aesenc_si128(dest[1], key[1].mRoundKey[j]);
					dest[2] = _mm_aesenc_si128(dest[2], key[2].mRoundKey[j]);
					dest[3] = _mm_aesenc_si128(dest[3], key[3].mRoundKey[j]);
					dest[4] = _mm_aesenc_si128(dest[4], key[4].mRoundKey[j]);
					dest[5] = _mm_aesenc_si128(dest[5], key[5].mRoundKey[j]);
					dest[6] = _mm_aesenc_si128(dest[6], key[6].mRoundKey[j]);
					dest[7] = _mm_aesenc_si128(dest[7], key[7].mRoundKey[j]);
				}
				dest[0] = _mm_aesenclast_si128(dest[0], key[0].mRoundKey[10]);
				dest[1] = _mm_aesenclast_si128(dest[1], key[1].mRoundKey[10]);
				dest[2] = _mm_aesenclast_si128(dest[2], key[2].mRoundKey[10]);
				dest[3] = _mm_aesenclast_si128(dest[3], key[3].mRoundKey[10]);
				dest[4] = _mm_aesenclast_si128(dest[4], key[4].mRoundKey[10]);
				dest[5] = _mm_aesenclast_si128(dest[5], key[5].mRoundKey[10]);
				dest[6] = _mm_aesenclast_si128(dest[6], key[6].mRoundKey[10]);
				dest[7] = _mm_aesenclast_si128(dest[7], key[7].mRoundKey[10]);

				dest += 8;
				key += 8;
			}

			for (int i = 0; i < finalLoop; ++i)
			{
				dest[0] = _mm_xor_si128(plaintext, key[0].mRoundKey[0]);

				for (u64 j = 1; j < 10; ++j)
				{
					dest[0] = _mm_aesenc_si128(dest[0], key[0].mRoundKey[j]);
				}
				dest[0] = _mm_aesenclast_si128(dest[0], key[0].mRoundKey[10]);

				++dest;
				++key;
			}
		}


		const MultiKeyAES& operator=(const MultiKeyAES& rhs)
		{
			for (u64 i = 0; i < mAESs.size(); ++i)
			{
				for(u64 j =0; j < sizeof(mAESs[i].mRoundKey) / sizeof(block); ++j)
					mAESs[i].mRoundKey[j] = rhs.mAESs[i].mRoundKey[j];
			}

			return rhs;
		}
	};

}
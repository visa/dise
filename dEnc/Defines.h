#pragma once
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Crypto/PRNG.h>
namespace dEnc {

	using i64 = oc::i64;
	using u64 = oc::u64;
	using i32 = oc::i32;
	using u32 = oc::u32;
	using i16 = oc::i16;
	using u16 = oc::u16;
	using i8 = oc::i8;
	using u8 = oc::u8;
	using Channel = oc::Channel;
	using block = oc::block;
	using PRNG = oc::PRNG;
	template<typename T> using span = oc::span<T>;


}
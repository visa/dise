#include "AmmrClient_tests.h"

#include <dEnc/distEnc/AmmrClient.h>
#include <dEnc/dprf/Npr03SymDprf.h>
#include <dEnc/dprf/Npr03AsymDprf.h>
#include <cryptoTools/Common/Finally.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/Channel.h>
#include <dEnc/tools/GroupChannel.h>

using namespace dEnc;


bool eq(span<block> a, span<block>b)
{
    return (a.size() == b.size() &&
        memcmp(a.data(), b.data(), a.size() * sizeof(block)) == 0);
};


template <typename DPRF>
void test_ammr(const u64 &trials,
    PRNG &prng, 
    const u64 &n, 
    std::vector<AmmrClient<DPRF>> &encs)
{

    std::vector<std::vector<block>> d(trials), c(trials), p(trials);
    for (u64 i = 0; i < trials; ++i)
    {
        d[i].resize(prng.get<u64>() % 99 + 1);
        prng.get(d[i].data(), d[i].size());
    }

    auto d0 = d[0];
    auto c0 = c[0];
    auto p0 = p[0];


    for (u64 i = 0; i < n; ++i)
    {

        encs[i].asyncEncrypt(d, c).get();
        encs[i].asyncEncrypt(d0, c0).get();

        encs[i].asyncDecrypt(c, p).get();
        encs[i].asyncDecrypt(c0, p0).get();


        if (!eq(p0, p[0]))
            throw std::runtime_error(LOCATION);


        for (u64 t = 0; t < trials; ++t)
        {
            if (!eq(p[t], d[t]))
                throw std::runtime_error(LOCATION);


            std::vector<block> data(prng.get<u64>() % 99 + 1), ciphertext, data2;
            prng.get(data.data(), data.size());

            encs[i].encrypt(data, ciphertext);
            encs[i].decrypt(ciphertext, data2);

            if (!eq(data, data2))
                throw std::runtime_error(LOCATION);

            encs[i].decrypt(c[t], data2);


            if (!eq(d[t], data2))
                throw std::runtime_error(LOCATION);
        }
    }
}


void AmmrSymClient_encDec_test()
{

	oc::setThreadName("__myThread__");
	u64 n = 4;
	u64 m = 2;
	u64 trials = 4;

	oc::IOService ios;
	std::vector<GroupChannel> eps(n);
	std::vector<AmmrClient<Npr03SymDprf>> encs(n);
	std::vector<Npr03SymDprf> dprfs(n);

	oc::Finally f([&]() {
		for (u64 i = 0; i < n; ++i)
			encs[i].close();
	});

	for (u64 i = 0; i < n; ++i)
		eps[i].connect(i, n, ios);

    PRNG prng(oc::ZeroBlock);
    Npr03SymDprf::MasterKey mk;
    mk.KeyGen(n, m, prng);

	for (u64 i = 0; i < n; ++i)
	{
		auto& e = eps[i];

        dprfs[i].init(i, m, e.mRequestChls, e.mListenChls, prng.get<block>(), mk.keyStructure, mk.getSubkey(i));
		encs[i].init(i, prng.get<block>(), &dprfs[i]);
	}

    test_ammr(trials, prng, n, encs);
}



void AmmrAsymShClient_encDec_test()
{
	oc::setThreadName("__myThread__");


	u64 n = 4;
	u64 m = 2;
	u64 trials = 4;

	oc::IOService ios;
	std::vector<GroupChannel> eps(n);
	std::vector<AmmrClient<Npr03AsymDprf>> encs(n);
	std::vector<Npr03AsymDprf> dprfs(n);

	oc::Finally f([&]() {
		for (u64 i = 0; i < n; ++i)
			encs[i].close();
	});
	for (u64 i = 0; i < n; ++i)
		eps[i].connect(i, n, ios);

    auto type = Dprf::Type::SemiHonest;
    PRNG prng(oc::ZeroBlock);

    Npr03AsymDprf::MasterKey mk;
    mk.KeyGen(n, m, prng, type);

    for (u64 i = 0; i < n; ++i)
	{
        auto& e = eps[i];

        dprfs[i].init(i, m, e.mRequestChls, e.mListenChls, prng.get<block>(), type, mk.mKeyShares[i], {});
		encs[i].init(i, prng.get<block>(), &dprfs[i]);
	}
    test_ammr(trials, prng, n, encs);
}



void AmmrAsymMalClient_encDec_test()
{
	oc::setThreadName("__myThread__");


	u64 n = 4;
	u64 m = 2;
	u64 trials = 4;

	oc::IOService ios;
	std::vector<GroupChannel> eps(n);
	std::vector<AmmrClient<Npr03AsymDprf>> encs(n);
	std::vector<Npr03AsymDprf> dprfs(n);

	oc::Finally f([&]() {
		for (u64 i = 0; i < n; ++i)
			encs[i].close();
	});

	for (u64 i = 0; i < n; ++i)
		eps[i].connect(i, n, ios);


    auto type = Dprf::Type::Malicious;
    PRNG prng(oc::ZeroBlock);

    Npr03AsymDprf::MasterKey mk;
    mk.KeyGen(n, m, prng, type);

    for (u64 i = 0; i < n; ++i)
    {
        auto& e = eps[i];

        dprfs[i].init(i, m, e.mRequestChls, e.mListenChls, prng.get<block>(), type, mk.mKeyShares[i], mk.mCommits);
        encs[i].init(i, prng.get<block>(), &dprfs[i]);
    }

    test_ammr(trials, prng, n, encs);
}



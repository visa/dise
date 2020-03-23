#include "Npr03DPRF_tests.h"
#include <dEnc/dprf/Npr03SymDprf.h>
#include <dEnc/dprf/Npr03AsymDprf.h>
#include <cryptoTools/Common/Finally.h>
#include <cryptoTools/Common/Log.h>

#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/Channel.h>

#include <dEnc/tools/GroupChannel.h>

using namespace dEnc;




void Npr03SymShDPRF_eval_test()
{
	oc::setThreadName("__myThread__");

	u64 n = 4;
	u64 m = 2;

	u64 trials = 4;

	oc::IOService ios;
	std::vector<GroupChannel> comms(n);
	std::vector<Npr03SymDprf> dprfs(n);

	oc::Finally f([&]() {
		for (auto& d : dprfs) d.close();
		dprfs.clear();
		comms.clear(); });

	for (u64 i = 0; i < n; ++i)
		comms[i].connect(i, n, ios);

    PRNG prng(oc::ZeroBlock);
    Npr03SymDprf::MasterKey mk;
    mk.KeyGen(n, m, prng);

	for (u64 i = 0; i < n; ++i)
	{
		dprfs[i].init(i, m, comms[i].mRequestChls, comms[i].mListenChls, oc::toBlock(i), mk.keyStructure, mk.getSubkey(i));
	}

	std::vector<oc::AES> keys(dprfs[0].mD);
	for (auto i =0; i < keys.size(); ++i)
		keys[i].setKey(mk.keys[i]);

	std::vector<block> x(trials), exp(trials);
	for (u64 t = 0; t < trials; ++t)
	{
		x[t] = prng.get<block>();
		exp[t] = oc::ZeroBlock;

		for (u64 i = 0; i < keys.size(); ++i)
		{
			exp[t] = exp[t] ^ keys[i].ecbEncBlock(x[t]);
		}
	}


	for (u64 i = 0; i < n; ++i)
	{
		auto out = dprfs[i].asyncEval(x).get();

		for (u64 t = 0; t < trials; ++t)
		{
			auto fi = dprfs[i].eval(x[t]);

			if (neq(fi, exp[t]) || neq(out[t], exp[t]))
			{
				std::cout << "failed " << std::endl;

				throw std::runtime_error(LOCATION);
			}
		}
	}


}

void Npr03AsymShDPRF_eval_test()
{


	oc::setThreadName("__myThread__");

	u64 n = 4;
	u64 m = 2;

	u64 trials = 4;

	oc::IOService ios;
	std::vector<GroupChannel> comms(n);
	std::vector<Npr03AsymDprf> dprfs(n);
	oc::Finally f([&]() {
		for (auto& d : dprfs) d.close();
		dprfs.clear();
		comms.clear(); });
	for (u64 i = 0; i < n; ++i)
		comms[i].connect(i, n, ios);

    
    auto type = Dprf::Type::SemiHonest;
    PRNG prng(oc::ZeroBlock);

    Npr03AsymDprf::MasterKey mk;
    mk.KeyGen(n, m, prng, type);

	for (u64 i = 0; i < n; ++i)
	{
		dprfs[i].init(i, m, comms[i].mRequestChls, comms[i].mListenChls, oc::toBlock(i), type, mk.mKeyShares[i], mk.mCommits);
	}


	std::vector<block> x(trials);
	for (u64 t = 0; t < trials; ++t)
	{
		x[t] = prng.get<block>();
	}

	auto exp = dprfs[0].asyncEval(x).get();
	for (u64 i = 0; i < n; ++i)
	{
		auto d = dprfs[i].asyncEval(x).get();

		for (u64 t = 0; t < trials; ++t)
		{
			auto fi = dprfs[i].eval(x[t]);
			auto fi2 = dprfs[i].asyncEval(x[t]).get()[0];

			if (neq(fi, exp[t]) ||
				neq(fi2, exp[t]) ||
				neq(d[t], exp[t]))
			{
				std::cout << "failed " << std::endl;
				throw std::runtime_error(LOCATION);
			}
		}
	}
}

void Npr03AsymMalDPRF_eval_test()
{


	oc::setThreadName("__myThread__");

	u64 n = 4;
	u64 m = 2;

	u64 trials = 4;

	oc::IOService ios;
	std::vector<GroupChannel> comms(n);
	std::vector<Npr03AsymDprf> dprfs(n);
	oc::Finally f([&]() {
		for (auto& d : dprfs) d.close();
		dprfs.clear();
		comms.clear(); });
	for (u64 i = 0; i < n; ++i)
		comms[i].connect(i, n, ios);


    auto type = Dprf::Type::SemiHonest;
    PRNG prng(oc::ZeroBlock);

    Npr03AsymDprf::MasterKey mk;
    mk.KeyGen(n, m, prng, type);

	for (u64 i = 0; i < n; ++i)
	{
		dprfs[i].init(i, m, comms[i].mRequestChls, comms[i].mListenChls, oc::toBlock(i), type, mk.mKeyShares[i], mk.mCommits);
	}
     

	std::vector<block> x(trials);
	for (u64 t = 0; t < trials; ++t)
	{
		x[t] = prng.get<block>();
	}

	auto exp = dprfs[0].asyncEval(x).get();
	for (u64 i = 0; i < n; ++i)
	{
		auto d = dprfs[i].asyncEval(x).get();

		for (u64 t = 0; t < trials; ++t)
		{
			auto fi = dprfs[i].eval(x[t]);
			auto fi2 = dprfs[i].asyncEval(x[t]).get()[0];

			if (neq(fi, exp[t]) ||
				neq(fi2, exp[t]) ||
				neq(d[t], exp[t]))
			{
				std::cout << "failed " << std::endl;
				throw std::runtime_error(LOCATION);
			}
		}
	}


}

#include <dEnc_tests/all.h>
#include <dEnc/distEnc/AmmrClient.h>
#include <dEnc/dprf/Npr03SymDprf.h>
#include <dEnc/dprf/Npr03AsymDprf.h>

#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include "util.h"

#include <dEnc/tools/GroupChannel.h>

using namespace dEnc;


template<typename DPRF>
void eval(std::vector<AmmrClient<DPRF>>& encs,u64 n, u64 m, u64 blockCount, u64 batch, u64 trials, u64 numAsync, bool lat, std::string tag)
{
    oc::Timer t;
    auto s = t.setTimePoint("start");

    // The party that will initiate the encryption.
    // The other parties will respond to requests on the background.
    // This happens using the threads created by oc::IoService
    auto& initiator = encs[0];

    // the buffers to hold the data.
    std::vector<std::vector<block>> data(batch), ciphertext(batch), data2(batch);
    for (auto& d : data) d.resize(blockCount);

    if (lat)
    {
        // we are interested in latency and therefore we 
        // will only have one encryption in flight at a time.
        for (u64 t = 0; t < trials; ++t)
            initiator.encrypt(data[0], ciphertext[0]);

    }
    else
    {
        // We are going to initiate "batch" encryptions at once.
        // In addition, we will send out "numAsync" batches before we 
        // complete the first batch. This allows higher throughput.

        // A place to store "inflight" encryption operations
        std::deque<AsyncEncrypt> asyncs;

        
        auto loops = (trials + batch - 1) / batch;
        trials = loops * batch;
        for (u64 t = 0; t < loops; ++t)
        {

            // check if we have reached the maximum number of 
            // async encryptions. If so, then complete the oldest 
            // one by calling AsyncEncrypt::get();
            if (asyncs.size() == numAsync)
            {
                asyncs.front().get();
                asyncs.pop_front();
            }

            // initiate another encryption. This will not complete immidiately.
            asyncs.emplace_back(initiator.asyncEncrypt(data, ciphertext));
        }

        // Complete all pending encryptions
        while (asyncs.size())
        {
            asyncs.front().get();
            asyncs.pop_front();
        }
    }

    auto e = t.setTimePoint("end");

    // close all of the instances.
    for (u64 i = 0; i < n; ++i)
        encs[i].close();

    auto online = (double)std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();

    // print the statistics.
    std::cout << tag <<"      n:" << n << "  m:" << m << "   t:" << trials << "     enc/s:" << 1000 * trials / online << "   ms/enc:" << online / trials << " \t "
        << " Mbps:" << (trials * sizeof(block) * 2 * (m - 1) * 8 / (1 << 20)) / (online / 1000)
        << std::endl;

}


void AmmrSymClient_tp_Perf_test(u64 n, u64 m, u64 blockCount, u64 trials, u64 numAsync, u64 batch, bool lat)
{

    // set up the networking
    oc::IOService ios;
    std::vector<GroupChannel> eps(n);
    for (u64 i = 0; i < n; ++i)
        eps[i].connect(i, n, ios);

    // allocate the DPRFs and the encryptors
    std::vector<AmmrClient<Npr03SymDprf>> encs(n);
    std::vector<Npr03SymDprf> dprfs(n);

    // Initialize the parties using a random seed from the OS.
    oc::PRNG prng(oc::sysRandomSeed());

    // Generate the master key for this DPRF.
    Npr03SymDprf::MasterKey mk;
    mk.KeyGen(n, m, prng);


    // initialize the DPRF and the encrypters
    for (u64 i = 0; i < n; ++i)
    {
        auto& e = eps[i];

        dprfs[i].init(i, m, e.mRequestChls, e.mListenChls, prng.get<block>(),mk.keyStructure, mk.getSubkey(i));
        encs[i].init(i, prng.get<block>(), &dprfs[i]);
    }

    // Perform the benchmark.                                          
    eval(encs, n, m, blockCount, batch, trials, numAsync, lat, "Sym      ");
}






void AmmrAsymSHClient_Perf_test(u64 n, u64 m, u64 blockCount, u64 trials, u64 numAsync, u64 batch, bool lat)
{

    // set up the networking
    oc::IOService ios;
    std::vector<GroupChannel> eps(n);
    for (u64 i = 0; i < n; ++i)
        eps[i].connect(i, n, ios);

    // allocate the DPRFs and the encryptors
    std::vector<AmmrClient<Npr03AsymDprf>> encs(n);
    std::vector<Npr03AsymDprf> dprfs(n);

    // Initialize the parties using a random seed from the OS.
    oc::PRNG prng(oc::sysRandomSeed());

    // Generate the master key for this DPRF.
    auto type = Dprf::Type::SemiHonest;
    Npr03AsymDprf::MasterKey mk;
    mk.KeyGen(n, m, prng, type);


    // initialize the DPRF and the encrypters
    for (u64 i = 0; i < n; ++i)
    {
        auto& e = eps[i];

        dprfs[i].init(i, m, e.mRequestChls, e.mListenChls, prng.get<block>(), type, mk.mKeyShares[i], mk.mCommits);
        encs[i].init(i, prng.get<block>(), &dprfs[i]);
    }

    // Perform the benchmark.                                          
    eval(encs, n, m, blockCount, batch, trials, numAsync, lat, "Asym-SH  ");
}




void AmmrAsymMalClient_Perf_test(u64 n, u64 m, u64 blockCount, u64 trials, u64 numAsync, u64 batch, bool lat, bool pv)
{

    // set up the networking
    oc::IOService ios;
    std::vector<GroupChannel> eps(n);
    for (u64 i = 0; i < n; ++i)
        eps[i].connect(i, n, ios);

    // allocate the DPRFs and the encryptors
    std::vector<AmmrClient<Npr03AsymDprf>> encs(n);
    std::vector<Npr03AsymDprf> dprfs(n);

    // Initialize the parties using a random seed from the OS.
    oc::PRNG prng(oc::sysRandomSeed());

    // Generate the master key for this DPRF.
    auto type = pv ? Dprf::Type::PublicVarifiable : Dprf::Type::Malicious;
    Npr03AsymDprf::MasterKey mk;
    mk.KeyGen(n, m, prng, type);

    // initialize the DPRF and the encrypters
    for (u64 i = 0; i < n; ++i)
    {
        auto& e = eps[i];
        dprfs[i].init(i, m, e.mRequestChls, e.mListenChls, prng.get<block>(), type, mk.mKeyShares[i], mk.mCommits);
        encs[i].init(i, prng.get<block>(), &dprfs[i]);
    }

    // Perform the benchmark.                                          
    eval(encs, n, m, blockCount, batch, trials, numAsync, lat, "Asym-Mal ");
}


int main(int argc, char** argv)
{

    oc::CLP cmd;
    cmd.parse(argc, argv);

    if (cmd.isSet("u")) {
        auto& tests = dEnc_tests::tests; 

        if (cmd.isSet("list"))
        {
            tests.list();
            return 0;
        }
        else
        {
            cmd.setDefault("loop", 1);
            auto loop = cmd.get<u64>("loop");

            oc::TestCollection::Result result;
            if (cmd.hasValue("u"))
                result = tests.run(cmd.getMany<u64>("u"), loop);
            else
                result = tests.runAll(loop);

            if (result == oc::TestCollection::Result::passed)
                return 0;
            else
                return 1;
        }
    }

    if (cmd.isSet("lat"))
        getLatency();

    u64 t = 4096;
    u64 b = 128;
    u64 a = 1024 / b;
    cmd.setDefault("t", t);
    cmd.setDefault("b", b);
    cmd.setDefault("a", a);
    cmd.setDefault("size", 20);
    t = cmd.get<u64>("t");
    b = cmd.get<u64>("b");
    a = cmd.get<u64>("a");
    auto size = cmd.get<u64>("size");
    bool l = cmd.isSet("l");


    cmd.setDefault("nStart", 4);
    cmd.setDefault("nStep", 2);
    auto nStart = cmd.get<u64>("nStart");
    auto nEnd = (cmd.isSet("nEnd") ? cmd.get<u64>("nEnd") : nStart + 1);
    auto nStep = cmd.get<i64>("nStep");

    cmd.setDefault("mf", "0.5");
    auto mFrac = cmd.get < double>("mf");
    if (mFrac <= 0 || mFrac > 1)
    {
        std::cout << ("bad mf") << std::endl;
        return 0;
    }

    cmd.setDefault("mc", -1);
    auto mc = cmd.get<i64>("mc");


    std::string shSym("ss"), shAsym("sa"), malAsym("ma"), pvAsym("pv");
    bool noneSet = !cmd.isSet(shSym) && !cmd.isSet(shAsym) && !cmd.isSet(malAsym) && !cmd.isSet(pvAsym);
    if (noneSet)
    {
        std::cout
            << "============================================\n"
            << "||   Threshold Authenticated Encryption   ||\n"
            << "============================================\n"
            << "\n"
            << "This program reports the encryption performance of the distributed threshold encryptions scheme.\n"
            << "\n"
            << "Protocol flags:\n"
            << " -" << shSym << "  to run `weakly malicious` protocol with an AES based DPRF.\n"
            << " -" << shAsym << "  to run `weakly malicious` protocol with an DDH based DPRF.\n"
            << " -" << malAsym << "  to run `strongly malicious` protocol with an DDH based DPRF.\n"
            << " -" << pvAsym << "  to run `strongly malicious` protocol with an DHH based DPRF and has public varifiability.\n"
            << "\n"
            << "Parameters:\n"
            << " -nStart    the number of parties to have on the first iteration (default = 4).\n"
            << " -nEnd      the number of parties to terminate on (default = nStart + 1).\n"
            << " -nStep     the number of parties to add after each iteration, up to a total of nEnd (default = 2).\n"
            << " -mf        the threshold will be set to be an mf fraction of the parties (default = 0.5).\n"
            << " -mc        alternatively, a constant theshold of parties can be specified. -mf will be ignored.\n"
            << " -t         the number of encryptions to be performed for each configuration (default = 4096).\n"
            << " -b         the number of encryptions that should be send in a single requires (default = 128).\n"
            << " -a         the number of asynchronous encryption batches that should be allowed (default = 10).\n"
            << " -l         a flag to indicates that encryptions should be performed synchonously and one at a time. -b,-a will be ignored.\n"
            << " -size      the number of 16 byte blocks that should be encrypted (default = 20)\n"
            << "\n"
            << "Unit tests can be use with\n"
            << " -u \n"
            ;
    }
    else
    {

        for (auto n = nStart; n < nEnd; n += nStep)
        {
            auto m = std::max<u64>(2, (mc == -1) ? n * mFrac : mc);

            if (m > n)
            {
                std::cout << "can not have a threshold larger than the number of parties. theshold=" << m << ", #parties=" << n << std::endl;
                return -1;
            }

            if (cmd.isSet(shSym))  AmmrSymClient_tp_Perf_test(n, m, size, t, a, b, l);
            if (cmd.isSet(shAsym)) AmmrAsymSHClient_Perf_test(n, m, size, t, a, b, l);
            if (cmd.isSet(malAsym))AmmrAsymMalClient_Perf_test(n, m, size, t, a, b, l, false);
            if (cmd.isSet(pvAsym)) AmmrAsymMalClient_Perf_test(n, m, size, t, a, b, l, true);
        }
    }
}
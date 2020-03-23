#include "util.h"

using namespace osuCrypto;
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/Channel.h>
#define tryCount 2
void getLatency()
{
	IOService ios;
	Endpoint p0(ios,"localhost", EpMode::Server, "s"), p1(ios, "localhost", EpMode::Client, "s");

	auto c0 = p0.addChannel("ss");
	auto c1 = p1.addChannel("ss");

	c0.waitForConnection();
	c1.waitForConnection();

	auto thrd = std::thread([&]()
	{
		senderGetLatency(c0);
	});
	recverGetLatency(c1);

	thrd.join();
}

void senderGetLatency(Channel& chl)
{

    u8 dummy[1];

    chl.asyncSend(dummy, 1);



    chl.recv(dummy, 1);
    chl.asyncSend(dummy, 1);


    std::vector<u8> oneMbit((1 << 20) / 8);
    for (u64 i = 0; i < tryCount; ++i)
    {
        chl.recv(dummy, 1);

        for(u64 j =0; j < (1<<10); ++j)
            chl.asyncSend(oneMbit.data(), oneMbit.size());
    }
    chl.recv(dummy, 1);


	for (u64 j = 0; j < (1 << 10); ++j)
	{
		chl.asyncRecv(oneMbit.data(), oneMbit.size());
		chl.asyncSend(oneMbit.data(), oneMbit.size());
	}

	chl.recv(dummy, 1);
}

void recverGetLatency(Channel& chl)
{

    u8 dummy[1];
    chl.recv(dummy, 1);
    Timer timer;
    auto start = timer.setTimePoint("");
    chl.asyncSend(dummy, 1);


    chl.recv(dummy, 1);

    auto mid = timer.setTimePoint("");
    auto recvStart = mid;
    auto recvEnd = mid;

    auto rrt = mid - start;
    std::cout << "latency:   " << std::chrono::duration_cast<std::chrono::milliseconds>(rrt).count() << " ms" << std::endl;

    std::vector<u8> oneMbit((1 << 20) / 8);
    for (u64 i = 0; i < tryCount; ++i)
    {
        recvStart = timer.setTimePoint("");
        chl.asyncSend(dummy, 1);

        for (u64 j = 0; j < (1 << 10); ++j)
            chl.recv(oneMbit);

        recvEnd = timer.setTimePoint("");

        // nanoseconds per GegaBit
        auto uspGb = std::chrono::duration_cast<std::chrono::nanoseconds>(recvEnd - recvStart - rrt / 2).count();

        // nanoseconds per second
        double usps = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::seconds(1)).count();

        // MegaBits per second
        auto Mbps = usps / uspGb *  (1 << 10);

        std::cout << "bandwidth ->: " << Mbps << " Mbps" << std::endl;
    }

    chl.asyncSend(dummy, 1);
	std::future<void> f;
	recvStart = timer.setTimePoint("");
	for (u64 j = 0; j < (1 << 10); ++j)
	{
		f = chl.asyncRecv(oneMbit.data(), oneMbit.size());
		chl.asyncSend(oneMbit.data(), oneMbit.size());
	}
	f.get();
	recvEnd = timer.setTimePoint("");
	chl.send(dummy, 1);

	// nanoseconds per GegaBit
	auto uspGb = std::chrono::duration_cast<std::chrono::nanoseconds>(recvEnd - recvStart - rrt / 2).count();

	// nanoseconds per second
	double usps = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::seconds(1)).count();

	// MegaBits per second
	auto Mbps = usps / uspGb *  (1 << 10);

	std::cout << "bandwidth <->: " << Mbps << " Mbps" << std::endl;
}

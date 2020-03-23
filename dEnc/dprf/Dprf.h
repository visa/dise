#pragma once

#include <dEnc/Defines.h>
namespace dEnc {

	struct AsyncEval {
        std::function<std::vector<block>()> get;
        //std::function<void()>destructor;

        AsyncEval() = default;
        AsyncEval(AsyncEval&&) = default;

        AsyncEval(const AsyncEval&)
        {
            throw std::runtime_error("std::fucntion sucks cause copy is required...");
        }

        AsyncEval& operator=(AsyncEval&&) = default;
    };

	class Dprf
	{
	public:
        enum class Type
        {
            SemiHonest,
            Malicious,
            PublicVarifiable
        };

        virtual ~Dprf() = default;
        
		virtual void serveOne(span<u8>request, u64 outputPartyIdx) = 0;

		virtual block eval(block input) = 0;
		virtual AsyncEval asyncEval(block input) = 0;
		virtual AsyncEval asyncEval(span<block> input) = 0;

		virtual void close() = 0;
	};

}
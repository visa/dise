#include "all.h"
#include <iostream>
#include <string>
#include <functional>
#include <cryptoTools/Common/Log.h>
namespace dEnc_tests
{

    oc::TestCollection tests([](oc::TestCollection& tests)
	{
        tests.add("Npr03SymShDPRF_eval_test           ", Npr03SymShDPRF_eval_test);
		tests.add("Npr03AsymShDPRF_eval_test          ", Npr03AsymShDPRF_eval_test);
		tests.add("Npr03AsymMalDPRF_eval_test         ", Npr03AsymMalDPRF_eval_test);
		tests.add("AmmrSymClient_encDec_test          ", AmmrSymClient_encDec_test);
		tests.add("AmmrAsymShClient_encDec_test       ", AmmrAsymShClient_encDec_test);
		tests.add("AmmrAsymMalClient_encDec_test      ", AmmrAsymMalClient_encDec_test);
    });
}

#include <stdint.h>
#include <stdio.h>
#include <climits>
#include "hsv.hpp"

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    double SV = provider.ConsumeFloatingPoint<double>();
    double V = provider.ConsumeFloatingPoint<double>();

    shasta::hsvToHsl(SV, V);
    return 0;
}
#pragma once

#include <cstddef>
#include <cstdint>

extern "C"
{
    void matMulVecPacked(uint32_t *out, const uint32_t *a, const uint32_t *b, size_t aRows, size_t aCols);
}

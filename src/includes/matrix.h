#pragma once
// #include "seal/seal.h"
#include "utils.h"
#include <stdint.h>
#include <stddef.h>

#if defined(__AVX512F__)
    #include <immintrin.h>
#elif defined(__AVX2__)
    #include <immintrin.h>
#endif

// define a structure for a matrix
typedef struct {
    uint64_t *data;
    size_t rows;
    size_t cols;
    size_t levels;
} matrix_t; 

typedef struct {
    uint128_t *data;
    size_t rows;
    size_t cols;
    size_t levels;
} matrix128_t; 


// ! mat_vec functions means matrix-vector multiplication. 
// It is used for testing the performance of each method. Otherwise,
// we are doing out = A * B, where A = m * n, B = n * 2, n = DatabaseConstants::MaxFstDimSz

// ======================== NAIVE STUFF ========================
void naive_mat_vec(matrix_t *A, matrix_t *B, matrix_t *out);
void naive_mat_vec_128(matrix_t *A, matrix_t *B, matrix128_t *out);
void naive_level_mat_mat(matrix_t *A, matrix_t *B, matrix_t *out);
void naive_level_mat_mat_128(matrix_t *A, matrix_t *B, matrix128_t *out);

// ======================== LEVEL MAT MAT ========================
// performing coeff_val_cnt many matrix matrix multiplications. Assumes that the B matrix has only two columns.
void level_mat_mat(matrix_t *A, matrix_t *B, matrix_t *out);

// suitable for the first dimension. The output is in uint128_t.
void level_mat_mat_128(matrix_t *A, matrix_t *B, matrix128_t *out);

// A single matrix * matrix multiplication, assuming second matrix has only two
// columns. This is a helper for level_mat_mult_128.
void mat_mat_128(const uint64_t *__restrict A, const uint64_t *__restrict B,
                 uint128_t *__restrict out, const size_t rows,
                 const size_t cols);

// Indirect first-dimension multiply: gathers entries from a shared level-major
// NTT store via an index table, then performs the same mat-mat-128 computation.
// shared_store layout: shared_store[level * shared_num_entries + entry_id]
void indirect_level_mat_mat_128(
    const uint64_t *shared_store,
    size_t shared_num_entries,
    const uint32_t *index_table,
    size_t rows,            // other_dim_sz
    size_t cols,            // fst_dim_sz
    size_t levels,          // coeff_val_cnt
    const uint64_t *B_data, // query matrix (fst_dim_sz × 2 × levels)
    uint128_t *out_data     // output (other_dim_sz × 2 × levels)
);

// calculate mod after each multiplication. Hence, output will be in uint64_t.
void level_mat_mat_direct_mod(matrix_t *A, matrix_t *B, matrix_t *out, const seal::Modulus mod);


// ======================== COMPONENT WISE MULTIPLICATION ========================

// These are examples of component wise multiplication. This demonstrates the
// first dimension multiplication of OnionPIRv1.
// In v1, we think of the database as a matrix of polynomials, where each NTT
// polynomial is stored in a vector. Then, the first dimension is doing a
// matrix-matrix multiplication where each element is a vector, and the
// multiplication is defined by component wise multiplication of the vectors.
// Hence, multiplying one "row" of database and one "column" of query is
// equivalent as doing 2*N*degree many component wise multiplications, where N
// is the first dimension size, say 256.
// ? The question is: will the entire query vector of vectors stay in the cache
// when we scan the second "row" of the database?
// Short answer: No. Bad locality.

// Perform the Matrix Multiplication over a direct product over component wise vector multiplication.
void component_wise_mult(matrix_t *A, matrix_t *B, matrix_t *out);
void component_wise_mult_128(matrix_t *A, matrix_t *B, matrix128_t *out);
#if defined(__AVX512F__)
// This is using intel::hexl::EltwiseMultMod for each component wise multiplication.
void component_wise_mult_direct_mod(matrix_t *A, matrix_t *B, uint64_t *out, const uint64_t mod);
#endif

// ======================== THIRD PARTIES ========================
// Currently, I don't know any libraries that can do 64x64->128 multiplication.
// Here we use 64*64->64 multiplications as the easier alternative.
// If you want a cleaner code, maybe you can write a genearal level_mat_mult
// wrapper, then pass the function pointer to the actual implementation.
// I am being lazy here...


// ======================== HELPER FUNCTIONS ========================
// calculates c = c + a * b mod m using Barrett reduction
inline void mult_add_mod(uint64_t &a, uint64_t &b, uint64_t &c, const seal::Modulus &m) {
    uint128_t tmp = (uint128_t)a * b + c;
    uint64_t raw[2] = {static_cast<uint64_t>(tmp), static_cast<uint64_t>(tmp >> 64)};
    c = util::barrett_reduce_128(raw, m);
}


// NOTE: avx_mat_mat_mult_128 (and the AVX-512 helpers mul_64x64_128 /
// horizontal_reduce_128) were removed. The function was AVX-512-only with
// no AVX2 fallback, was never wired into server.cpp's dispatch (which uses
// naive_level_mat_mat_128), and was only invoked from a benchmark in
// tests.cpp. HEXL's runtime-dispatched eltwise routines now provide the
// SIMD acceleration on x86_64 via component_wise_mult_direct_mod.
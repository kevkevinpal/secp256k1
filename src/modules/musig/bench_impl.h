/***********************************************************************
 * Copyright (c) 2025 Pieter Wuille, Andrew Poelstra                   *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_MUSIG_BENCH_H
#define SECP256K1_MODULE_MUSIG_BENCH_H

#include "../../../include/secp256k1_musig.h"

typedef struct {
    const secp256k1_context *ctx;
    secp256k1_pubkey point;
    unsigned char scalar[32];
} bench_musig_data;

static void bench_musig_setup(void* arg) {
    int i;
    bench_musig_data *data = (bench_musig_data*)arg;
    const unsigned char point[] = {
        [0]=0x03,
        [1]=0x54, [2]=0x94, [3]=0xc1, [4]=0x5d, [5]=0x32, [6]=0x09, [7]=0x97, [8]=0x06,
        [9]=0xc2, [10]=0x39, [11]=0x5f, [12]=0x94, [13]=0x34, [14]=0x87, [15]=0x45, [16]=0xfd,
        [17]=0x75, [18]=0x7c, [19]=0xe3, [20]=0x0e, [21]=0x4e, [22]=0x8c, [23]=0x90, [24]=0xfb,
        [25]=0xa2, [26]=0xba, [27]=0xd1, [28]=0x84, [29]=0xf8, [30]=0x83, [31]=0xc6, [32]=0x9f
    };

    for (i = 0; i < 32; i++) {
        data->scalar[i] = i + 1;
    }
    CHECK(secp256k1_ec_pubkey_parse(ctx: data->ctx, pubkey: &data->point, input: point, inputlen: sizeof(point)) == 1);
}

static void bench_musig(void* arg, int iters) {
    int i;
    unsigned char res[32];
    bench_musig_data *data = (bench_musig_data*)arg;

    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_musig(ctx: data->ctx, output: res, pubkey: &data->point, seckey: data->scalar, hashfp: NULL, data: NULL) == 1);
    }
}

static void run_musig_bench(int iters, int argc, char** argv) {
    bench_musig_data data;
    int d = argc == 1;

    data.ctx = secp256k1_context_static;

    if (d || have_flag(argc, argv, "musig")) run_benchmark("musig", bench_musig, bench_musig_setup, NULL, &data, 10, iters);
}

#endif /* SECP256K1_MODULE_MUSIG_BENCH_H */

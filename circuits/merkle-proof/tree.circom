pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/switcher.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

/*
 * Hashes input of nBits and produces 256 bits output
 * Ensure hash(left) + hash(right) if right is none zero
 * otherwiser hash(left).
 */
template ShaHashing(nBits) {
    signal input left[nBits];
    signal input right[nBits];
    signal input selector;
    signal output out[256];

    component switcher[nBits];
    component hash = Sha256(nBits + nBits);
    for (var s=0; s < nBits; s++ ) {
        switcher[s] = Switcher();
        switcher[s].sel <== selector;
        switcher[s].L <== left[s];
        switcher[s].R <== right[s];
        
        hash.in[s] <== switcher[s].outL;
        hash.in[s + nBits] <== switcher[s].outR;
    }

    // Check if all the bits of right are zero
    component right_is_zero = IsZero();
    component b2n = Bits2Num(nBits);
    b2n.in <== right;
    right_is_zero.in <== b2n.out;

    signal k_left[256];
    signal k_left_right[256];
    for (var j=0; j < 256; j++ ) {
        k_left[j] <== right_is_zero.out * left[j];
        k_left_right[j] <== (1 - right_is_zero.out) * hash.out[j];
        out[j] <==  k_left[j] + k_left_right[j];
    }
}


template Sha256_2(nBits) {
    signal input left[nBits];
    signal input right[nBits];
    signal output out[256];

    component hash = Sha256(nBits + nBits);
    for (var i=0; i < nBits; i++ ) {
        hash.in[i] <== left[i];
        hash.in[i + nBits] <== right[i];
    }

    out <== hash.out;
}

/*
    Verify the merkle path considering only non-zero nodes
*/
template VerifyMerklePath(nLevels) {
    signal input path[nLevels][256];
    signal input root[256];
    // left or right indicator
    signal input key;

    component n2b = Num2Bits(nLevels - 1);
    n2b.in <== key;

    component levels[nLevels - 1];

    levels[0] = ShaHashing(256);
    levels[0].selector <== n2b.out[0];
    levels[0].left <== path[0];
    levels[0].right <== path[1];

    for (var i=1; i < nLevels -1; i++ ) {
        levels[i] = ShaHashing(256);
        levels[i].selector <== n2b.out[i];
        levels[i].left <== levels[i - 1].out;
        levels[i].right <== path[i + 1];
    }
    root === levels[nLevels - 2].out;
}



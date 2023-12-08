pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/switcher.circom";
// hashes input of nBits and produces 256 bits output
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

    out<== hash.out;
}

template VerifyMerklePath(nLevels) {
    signal input path[nLevels][256];
    signal input root[256];
    // left/ right indicator
    signal input key;

    //  1  2        3          ...       // inputs nLevel( =3 )
    //  |/          |
    //  s0 --root-> s1 -root-> ...       // hashers
    
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

        root === levels[nLevels - 2].out;

    }
}

component main { public [ root ] } = VerifyMerklePath(3);


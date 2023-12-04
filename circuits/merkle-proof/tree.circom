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
        hash.in[s + 256] <== switcher[s].outR;
    }

    out<== hash.out;
}



component main { public [ left, right ] } = ShaHashing(256);

/* INPUT = {
   "left": [0,1,0,1,1,1,1,1,1,1,1,0,1,1,0,0,1,1,1,0,1,0,1,1,0,1,1,0,0,1,1,0,1,1,1,1,1,1,1,1,1,1,0,0,1,0,0,0,0,1,1,0,1,1,1,1,0,0,1,1,1,0,0,0,1,1,0,1,1,0,0,1,0,1,0,1,0,0,1,0,0,1,1,1,1,0,0,0,0,1,1,0,1,1,0,0,0,1,1,0,1,1,0,1,0,1,1,0,1,0,0,1,0,1,1,0,1,1,0,0,0,1,1,1,1,0,0,1,1,1,0,0,0,0,1,0,1,1,0,1,1,0,1,1,1,1,0,0,0,0,1,0,0,0,1,1,1,0,0,1,1,1,0,1,1,1,0,1,0,1,0,0,1,1,1,0,1,0,0,1,0,0,0,1,1,0,1,1,0,1,0,0,0,1,1,0,0,1,1,1,0,0,1,0,1,0,0,1,1,1,0,1,0,1,1,1,0,0,1,1,1,0,1,0,0,0,1,0,0,1,1,1,1,1,1,1,1,0,1,1,0,1,0,1,0,1,1,1,1,1,1,0,1,0,0,1],
    "right": [0,1,0,1,1,1,1,1,1,1,1,0,1,1,0,0,1,1,1,0,1,0,1,1,0,1,1,0,0,1,1,0,1,1,1,1,1,1,1,1,1,1,0,0,1,0,0,0,0,1,1,0,1,1,1,1,0,0,1,1,1,0,0,0,1,1,0,1,1,0,0,1,0,1,0,1,0,0,1,0,0,1,1,1,1,0,0,0,0,1,1,0,1,1,0,0,0,1,1,0,1,1,0,1,0,1,1,0,1,0,0,1,0,1,1,0,1,1,0,0,0,1,1,1,1,0,0,1,1,1,0,0,0,0,1,0,1,1,0,1,1,0,1,1,1,1,0,0,0,0,1,0,0,0,1,1,1,0,0,1,1,1,0,1,1,1,0,1,0,1,0,0,1,1,1,0,1,0,0,1,0,0,0,1,1,0,1,1,0,1,0,0,0,1,1,0,0,1,1,1,0,0,1,0,1,0,0,1,1,1,0,1,0,1,1,1,0,0,1,1,1,0,1,0,0,0,1,0,0,1,1,1,1,1,1,1,1,0,1,1,0,1,0,1,0,1,1,1,1,1,1,0,1,0,0,1],
    "selector" : 0
} */
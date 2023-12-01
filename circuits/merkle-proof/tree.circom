pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/sha256/sha256.circom";
// hashes input of nBits and produces 256 bits output
template ShaHashing(nBits) {
    signal input in[nBits];
    signal output out[256];
    component hash = Sha256(nBits);
    for (var i=0; i< nBits; i++) {
        hash.in[i] <== in[i];
    }
    out<== hash.out;
}

component main { public [ in ] } = ShaHashing(8);

/* INPUT = {
    "in": [0,0,1,1,0,0,0,0]
} */
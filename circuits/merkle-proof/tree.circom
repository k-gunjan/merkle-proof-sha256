pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
// hashes input of nBits and produces 256 bits output
template ShaHashing(nBits) {
    signal input in[nBits];
    signal input bits_as_num;
    signal output out[256];
    component hash = Sha256(nBits);
    for (var i=0; i< nBits; i++) {
        hash.in[i] <== in[i];
    }
    out<== hash.out;

    component n2b = Num2Bits(nBits);
    n2b.in <== bits_as_num;

    component hash_of_num = Sha256(nBits);
    for ( var j=0; j < nBits; j++ ) {
        //Num to Bits circuit output is in revers order
        // so MSB goes to LSB of hash circuit
        hash_of_num.in[j] <== n2b.out[ nBits - j - 1 ];
    }

    hash_of_num.out === out;
}

component main { public [ in ] } = ShaHashing(8);

/* INPUT = {
    "in": [0,0,1,1,0,0,0,0],
    "bits_as_num": 48
} */
pragma circom 2.1.6;

include "./tree.circom";
include "../../node_modules/circomlib/circuits/sha256/sha256.circom";

template Login(nLevels) {
    signal input identityNullifier[256];
    signal input path[nLevels][256];
    signal input key;
    signal input root[256];

    component leafHash = Sha256(256);
    leafHash.in <== identityNullifier;

    // constrain secret knowledge with leaf
    path[0] === leafHash.out;

    // Verify path
    component verifyPath = VerifyMerklePath(nLevels);
    verifyPath.path <== path;
    verifyPath.root <== root;
    verifyPath.key <== key;

}

component main { public [ root ] } = Login(4);
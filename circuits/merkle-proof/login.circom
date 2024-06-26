pragma circom 2.1.6;

include "./tree.circom";

template Login(nLevels) {
    signal input identityNullifier[256];
    signal input secret[256];
    signal input path[nLevels][256];
    signal input key;
    signal input root[256];
    signal input appId[256];
    signal output loginId[256];

    component leafHash = Sha256_2(256);
    leafHash.left <== identityNullifier;
    leafHash.right <== secret;

    // constrain secret knowledge with leaf
    path[0] === leafHash.out;

    // Verify path
    component verifyPath = VerifyMerklePath(nLevels);
    verifyPath.path <== path;
    verifyPath.root <== root;
    verifyPath.key <== key;

    component id = Sha256_2(256);
    id.left <== identityNullifier;
    id.right <== appId;

    loginId <== id.out;
}

component main { public [ root, appId ] } = Login(8);
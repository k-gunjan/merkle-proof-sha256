import assert from "chai";
import wasm_tester from "circom_tester";

import { F1Field, Scalar } from "ffjavascript";
export const p = Scalar.fromString("21888242871839275222246405745257275088548364400416034343698204186575808495617");
export const Fr = new F1Field(p);
import "./../node_modules/circomlib/test/helpers/sha256.js";
import crypto from "crypto";


function buffer2bitArray(b) {
    const res = [];
    for (let i = 0; i < b.length; i++) {
        for (let j = 0; j < 8; j++) {
            res.push((b[i] >> (7 - j) & 1));
        }
    }
    return res;
}

function bitArray2buffer(a) {
    const len = Math.floor((a.length - 1) / 8) + 1;
    const b = new Buffer.alloc(len);

    for (let i = 0; i < a.length; i++) {
        const p = Math.floor(i / 8);
        b[p] = b[p] | (Number(a[i]) << (7 - (i % 8)));
    }
    return b;
}


describe("prove path with different selectors", function () {
    let circuit;
    this.timeout(100000);
    before(async () => {
        circuit = await wasm_tester.wasm(`./circuits/merkle-proof/tree.circom`);
    })

    it("Should calculate a root of path and match with root, selector  0b00  => 0", async () => {

        const h1 = "5FECEB66FFC86F38D952786C6D696C79C2DBC239DD4E91B46729D73A27FB57E9"; //'0'
        const bh1 = Buffer.from(h1, "hex");
        const arrIn_bh1 = buffer2bitArray(bh1);

        const h2 = "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"; //'1'
        const bh2 = Buffer.from(h2, "hex");
        const arrIn_bh2 = buffer2bitArray(bh2);

        const h_12 = "b9b10a1bc77d2a241d120324db7f3b81b2edb67eb8e9cf02af9c95d30329aef5"; // hash(0 + 1)
        const bh12 = Buffer.from(h_12, "hex");
        const arrIn_bh12 = buffer2bitArray(bh12);

        const h3 = "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35"; //'2'
        const bh3 = Buffer.from(h3, "hex");
        const arrIn_bh3 = buffer2bitArray(bh3);

        const root = "c80f77387d860fa469920d7ac2f8a959ef83a651f76dc54923734ed76daaef53"; // hash( 12 + 3)
        const broot = Buffer.from(root, "hex");
        const arrIn_root = buffer2bitArray(broot);

        const witness = await circuit.calculateWitness({ "path": [arrIn_bh1, arrIn_bh2, arrIn_bh3, Array(256).fill(0), Array(256).fill(0), Array(256).fill(0), Array(256).fill(0), Array(256).fill(0)], "key": 0, "root": arrIn_root }, true);
    });

    it("Should calculate a root of path and match with root, selector  0b001  => 1", async () => {
        // Num2Bits for number 1 -->  100   (in 3 bits, Num2Bits gives reversed bit array)

        const h1 = "5FECEB66FFC86F38D952786C6D696C79C2DBC239DD4E91B46729D73A27FB57E9"; //'0'
        const bh1 = Buffer.from(h1, "hex");
        const arrIn_bh1 = buffer2bitArray(bh1);

        const h2 = "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"; //'1'
        const bh2 = Buffer.from(h2, "hex");
        const arrIn_bh2 = buffer2bitArray(bh2);

        const h_21 = "ee90f071cfb31af4d9230c8b9d11d0279e1e4f92992a860882aa338b3b60cef9"; // hash(1 + 0)
        const bh21 = Buffer.from(h_21, "hex");
        const arrIn_bh21 = buffer2bitArray(bh21);

        const h3 = "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35"; //'2'
        const bh3 = Buffer.from(h3, "hex");
        const arrIn_bh3 = buffer2bitArray(bh3);

        const root = "9786eccf677fa12554d15c5febff2583a04767f1bd309a2e0ff68ba3e455b4d5"; // hash( 21 + 3)
        const broot = Buffer.from(root, "hex");
        const arrIn_root = buffer2bitArray(broot);

        const witness = await circuit.calculateWitness({ "path": [arrIn_bh1, arrIn_bh2, arrIn_bh3, Array(256).fill(0), Array(256).fill(0), Array(256).fill(0), Array(256).fill(0), Array(256).fill(0)], "key": 1, "root": arrIn_root }, true);
    });
});


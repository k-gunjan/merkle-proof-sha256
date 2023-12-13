import assert from "chai";
import wasm_tester from "circom_tester";

// import { F1Field, Scalar } from "ffjavascript";
// export const p = Scalar.fromString("21888242871839275222246405745257275088548364400416034343698204186575808495617");
// export const Fr = new F1Field(p);
import crypto from "crypto";
import "circomlib/test/helpers/sha256.js";
import { bitArray2buffer, buffer2bitArray } from "./helper.js";

describe("check path and secrets then produce login id", function () {
    let circuit;
    this.timeout(100000);
    let arrIn_identity, arrIn_app_id, arrIn_secret, arrIn_bh1, arrIn_bh2, arrIn_bh3, arrIn_root;
    let hash_identity_buffer, hash_app_id_buffer;

    before(async () => {
        circuit = await wasm_tester.wasm(`./circuits/merkle-proof/login.circom`);

        const identity_nullifier = "hello";
        const identity_nullifier_b = Buffer.from(identity_nullifier, "utf8");
        const hash_identity = crypto.createHash("sha256")
            .update(identity_nullifier_b)
            .digest("hex");
        console.log("hash identity:", hash_identity);
        hash_identity_buffer = Buffer.from("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", 'hex');
        arrIn_identity = buffer2bitArray(hash_identity_buffer);

        const secret = "world";
        const secret_b = Buffer.from(secret, "utf8");
        const hash_secret = crypto.createHash("sha256")
            .update(secret_b)
            .digest("hex");
        console.log("hash secret:", hash_secret);
        const hash_secret_buffer = Buffer.from(hash_secret, 'hex');
        arrIn_secret = buffer2bitArray(hash_secret_buffer);

        // hash identity: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        // hash secret: 486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7
        // leaf_hash : "7305db9b2abccd706c256db3d97e5ff48d677cfe4d3a5904afb7da0e3950e1e2" // hash( identity + secret)

        const app_id = "facebook";
        const app_id_b = Buffer.from(app_id, "utf8");
        const hash_app_id = crypto.createHash("sha256")
            .update(app_id_b)
            .digest("hex");
        hash_app_id_buffer = Buffer.from(hash_app_id, 'hex');
        arrIn_app_id = buffer2bitArray(hash_app_id_buffer);

        const h1 = "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"; //'0'
        const bh1 = Buffer.from(h1, "hex");
        arrIn_bh1 = buffer2bitArray(bh1);

        const h2 = "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"; //'1'
        const bh2 = Buffer.from(h2, "hex");
        arrIn_bh2 = buffer2bitArray(bh2);

        // const h_12 = "81d188718e9bf14e0cb365f55ac704410e2387b53bcac5dd608cae1c9b39525d"; // hash(0 + 1)

        const h3 = "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35"; //'2'
        const bh3 = Buffer.from(h3, "hex");
        arrIn_bh3 = buffer2bitArray(bh3);

        const root = "865cc3c976c65c66e32b5272924ada102315b919b036b0313c3098a99fc42a6b"; // hash( 12 + 3)
        const broot = Buffer.from(root, "hex");
        arrIn_root = buffer2bitArray(broot);

    })

    it("Should calculate a root of path and match with root, match the secrets with leaf. selector  0b00  => 0", async () => {

        const input = {
            "identityNullifier": arrIn_identity,
            // "secret": arrIn_secret,
            "path": [arrIn_bh1, arrIn_bh2, arrIn_bh3, Array(256).fill(0)],
            "key": 0,
            "root": arrIn_root,
            // "appId": arrIn_app_id,
        }
        const witness = await circuit.calculateWitness(input, true);
        // const idOut = witness.slice(1, 257);
        // const hash2 = bitArray2buffer(idOut).toString("hex");
        // const id_hash = crypto.createHash("sha256").update(hash_identity_buffer).update(hash_app_id_buffer).digest("hex");
        // assert.assert.equal(hash2, id_hash);

    });

    it("Should fail for wrong root", async () => {

        // Toggle the first bit of root
        arrIn_root[0] = arrIn_root[0] === 1 ? 0 : 1;

        const input = {
            "identityNullifier": arrIn_identity,
            // "secret": arrIn_secret,
            "path": [arrIn_bh1, arrIn_bh2, arrIn_bh3, Array(256).fill(0)],
            "key": 0,
            "root": arrIn_root,
            // "appId": arrIn_app_id,
        }

        try {
            await circuit.calculateWitness(input, true);
        } catch (err) {
            // console.log(err);
            assert.assert(err.message.includes("Assert Failed"));
        }
    });
});


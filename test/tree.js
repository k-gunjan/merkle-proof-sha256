import assert from "chai";
import wasm_tester from "circom_tester";

describe("test sha hashing", function () {
    let circuit;
    this.timeout(100000);
    before(async () => {
        circuit = await wasm_tester.wasm(`./circuits/merkle-proof/tree.circom`);
    })
    it("hash 8 bits input ", async () => {
        const input = {
            "in": [0, 0, 1, 1, 0, 0, 0, 0]
        };
        const witness = await circuit.calculateWitness(input);
        await circuit.assertOut(witness, {});
    });
});
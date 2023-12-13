import { plonk } from 'snarkjs';
import crypto from "crypto";
import "circomlib/test/helpers/sha256.js";
import { bitArray2buffer, buffer2bitArray } from "./utils/utils.js";
import { readFileSync } from 'fs';

let arrIn_bh1, arrIn_bh2, arrIn_bh3, arrIn_root;

const identity_nullifier = "hello";
const identity_nullifier_b = Buffer.from(identity_nullifier, "utf8");
const hash_identity = crypto.createHash("sha256")
    .update(identity_nullifier_b)
    .digest("hex");
// console.log("hash identity:", hash_identity);
const hash_identity_buffer = Buffer.from("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", 'hex');
const arrIn_identity = buffer2bitArray(hash_identity_buffer);

const secret = "world";
const secret_b = Buffer.from(secret, "utf8");
const hash_secret = crypto.createHash("sha256")
    .update(secret_b)
    .digest("hex");
// console.log("hash secret:", hash_secret);
const hash_secret_buffer = Buffer.from(hash_secret, 'hex');
const arrIn_secret = buffer2bitArray(hash_secret_buffer);

// hash identity: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
// hash secret: 486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7
// leaf_hash : "7305db9b2abccd706c256db3d97e5ff48d677cfe4d3a5904afb7da0e3950e1e2" // hash( identity + secret)

const app_id = "facebook";
const app_id_b = Buffer.from(app_id, "utf8");
const hash_app_id = crypto.createHash("sha256")
    .update(app_id_b)
    .digest("hex");
const hash_app_id_buffer = Buffer.from(hash_app_id, 'hex');
const arrIn_app_id = buffer2bitArray(hash_app_id_buffer);

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

const input = {
    "identityNullifier": arrIn_identity,
    // "secret": arrIn_secret,
    "path": [arrIn_bh1, arrIn_bh2, arrIn_bh3, Array(256).fill(0),],
    "key": 0,
    "root": arrIn_root,
    // "appId": arrIn_app_id,
}
const wasm_path = "build/circuits/login_js/login.wasm";
const zkey_path = "artifacts/proving-key.zkey";

async function generateProof(input, wasm_path, zkey_path) {
    const { proof, publicSignals } = await plonk.fullProve(
        input,
        wasm_path,
        zkey_path
    )
    console.log(publicSignals);
    console.log(proof);

    return { proof, publicSignals };
}

async function prove(vk, proof, publicSignals) {
    const status = await plonk.verify(vk, publicSignals, proof);
    console.log("proof verification status: ", status);
}

const { proof, publicSignals } = await generateProof(input, wasm_path, zkey_path);
// comment above to bypass proof generation while testing and uncomment bellow 
// as proof generation can take very long (hours .. on local machines )
// const publicSignals = [
//     1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1
// ]
// const proof = {
//     A: [
//         '2719999633323190792869685222239523433583455338674172326659851069944568452674',
//         '13421880634439769416370570991314683464353240068062074909585469002884952031636',
//         '1'
//     ],
//     B: [
//         '11372729884529589589177657929348105993155854394563891283779430371449297248103',
//         '12934106542039711194731503025071648712818637829939084420053679864685273864832',
//         '1'
//     ],
//     C: [
//         '19259380997220269287636763733504339794585957626645635135575623846448342494430',
//         '4613475402396273599918650122310435099350230519810245222383258060718800655022',
//         '1'
//     ],
//     Z: [
//         '12140949388462247895068029179303289998784557365233716258213394135957022418453',
//         '4017269508813132477786465254779092788965220651800908151675824785029886549951',
//         '1'
//     ],
//     T1: [
//         '11232483015521724193551890937971426088031367191744754723378820818818861751204',
//         '4805708190893173286580546635556731926124489556069219751672005556901404393056',
//         '1'
//     ],
//     T2: [
//         '20649992549236402167381488735502120425587279642083003611072150571342449128174',
//         '14121996440333101856173538545814786942053744751047352207650201167321437223618',
//         '1'
//     ],
//     T3: [
//         '19683080318536914518270474480685268731813775470738631700337878396427676592944',
//         '8039838428429017050126351078175869814724311710011709076711323760993598068279',
//         '1'
//     ],
//     Wxi: [
//         '10952862640970003532520303720259334806102879766401739532595744729575200834800',
//         '7750826355106494305807409170689833746291422231997339338815166958656121067418',
//         '1'
//     ],
//     Wxiw: [
//         '18672885342696553578671335518414814692428886276243612086132578274626540262885',
//         '7215605875886097089785040955596993460693510539979564049349620686497670852707',
//         '1'
//     ],
//     eval_a: '2877161073498479781087432818125360135676296117759572692650709457634257228660',
//     eval_b: '17975748755124074251729722576875537502048378414100512099627607557664048907108',
//     eval_c: '11138212544111436992546141545105573180496812038248728611885433721446528649350',
//     eval_s1: '11299153189083468434322530585617009574511699897033131006647815000229179419910',
//     eval_s2: '19179478226744559118956717614755089748061744315015755423251242496946104998230',
//     eval_zw: '14860731769243875904448124421778079899388208143222418514650894264473004168522',
//     protocol: 'plonk',
//     curve: 'bn128'
// }


const filePath = './artifacts/verification_key.json';
const data = readFileSync(filePath, 'utf-8');
const vk = JSON.parse(data);

prove(vk, proof, publicSignals).then(() => {
    process.exit(0);
});
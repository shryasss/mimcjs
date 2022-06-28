const fs = require("fs");
const { ethers } = require("ethers");
const path = require("path");

// Read default parameters

let rawdata = fs.readFileSync(path.resolve(__dirname, "config.json"));
const config = JSON.parse(rawdata);

const DEFAULT_ROUNDS = config["DEFAULT_ROUNDS"];
const DEFAULT_EXPONENT = config["DEFAULT_EXPONENT"];
const ROUND_CONSTANTS = config["ROUND_CONSTANTS"];
ROUND_CONSTANTS.forEach(
    (c, index) => (ROUND_CONSTANTS[index] = parseBigInt(c))
);
const P = BigInt(config["SNARK_SCALAR_FIELD"]);

const IVs = [
    "149674538925118052205057075966660054952481571156186698930522557832224430770",
    "9670701465464311903249220692483401938888498641874948577387207195814981706974",
    "18318710344500308168304415114839554107298291987930233567781901093928276468271",
    "6597209388525824933845812104623007130464197923269180086306970975123437805179",
    "21720956803147356712695575768577036859892220417043839172295094119877855004262",
    "10330261616520855230513677034606076056972336573153777401182178891807369896722",
    "17466547730316258748333298168566143799241073466140136663575045164199607937939",
    "18881017304615283094648494495339883533502299318365959655029893746755475886610",
    "21580915712563378725413940003372103925756594604076607277692074507345076595494",
    "12316305934357579015754723412431647910012873427291630993042374701002287130550",
    "18905410889238873726515380969411495891004493295170115920825550288019118582494",
    "12819107342879320352602391015489840916114959026915005817918724958237245903353",
    "8245796392944118634696709403074300923517437202166861682117022548371601758802",
    "16953062784314687781686527153155644849196472783922227794465158787843281909585",
    "19346880451250915556764413197424554385509847473349107460608536657852472800734",
    "14486794857958402714787584825989957493343996287314210390323617462452254101347",
    "11127491343750635061768291849689189917973916562037173191089384809465548650641",
    "12217916643258751952878742936579902345100885664187835381214622522318889050675",
    "722025110834410790007814375535296040832778338853544117497481480537806506496",
    "15115624438829798766134408951193645901537753720219896384705782209102859383951",
    "11495230981884427516908372448237146604382590904456048258839160861769955046544",
    "16867999085723044773810250829569850875786210932876177117428755424200948460050",
    "1884116508014449609846749684134533293456072152192763829918284704109129550542",
    "14643335163846663204197941112945447472862168442334003800621296569318670799451",
    "1933387276732345916104540506251808516402995586485132246682941535467305930334",
    "7286414555941977227951257572976885370489143210539802284740420664558593616067",
    "16932161189449419608528042274282099409408565503929504242784173714823499212410",
    "16562533130736679030886586765487416082772837813468081467237161865787494093536",
    "6037428193077828806710267464232314380014232668931818917272972397574634037180",
];

/**
 * Parse BigInt from a string
 * @param {*} value the string
 * @returns a BigInt
 */
function parseBigInt(value) {
    if (typeof value === "string") {
        const m = value.match(/(-?\d+)n/);
        if (m && m[0] === value) {
            value = BigInt(m[1]);
        }
    }
    return value;
}

/**
 * MiMC Cipher
 * @param {*} input input data
 * @param {*} roundConstants round constants
 * @param {*} k key
 * @returns the ciphertext
 */
function mimcCipher(input, roundConstants, k) {
    var origInput = input;
    var a = 0;
    for (var i = 0; i < DEFAULT_ROUNDS; i++) {
        a = (input + BigInt(roundConstants[i]) + k) % P;
        input = BigInt(a ** BigInt(DEFAULT_EXPONENT));
    }
    return (input + k + k + origInput) % P;
}

/**
 * MiMC Hash
 * based on https://github.com/HarryR/ethsnarks/blob/master/ethsnarks/mimc/permutation.py
 * @param {*} input a point
 * @param {*} roundConstants round constants
 * @returns the hash
 */
function mimcHash(input, roundConstants, k) {
    // k = BigInt(k); // TODO - Change back to zero
    for (var i = 0; i < input.length; i++) {
        input[i] = input[i] % P;
        k = mimcCipher(input[i], roundConstants, k);
    }
    return k;
}

/**
 * Convert inputs and perform mimc hash
 * @param {*} preimage a point
 * @returns the hash
 */
function mimc(preimage, k) {
    if (!Array.isArray(preimage)) {
        throw "Expected preimage should be array of bigInts";
    }
    let inputs = [];
    for (var i = 0; i < preimage.length; i++) {
        inputs.push(preimage[i]);
    }
    return mimcHash(inputs, ROUND_CONSTANTS, k);
}

function mimcHashPair(left, right, k) {
    let preimage = [BigInt(left), BigInt(right)];
    k = BigInt(IVs[k]);
    return mimc(preimage, k);
}

function mimcHashStr(str) {
    let hexStr = "";
    for (var i = 0; i < str.length; i++) {
        hexStr += str.charCodeAt(i).toString(16);
    }
    let preimage = [];
    for (var i = 0; i < str.length; i += 32) {
        preimage.push(BigInt(`0x${hexStr.substr(i, 32)}`));
    }
    mimc(preimage, 0);
}

module.exports = { mimc, mimcHash, mimcHashPair, mimcHashStr };

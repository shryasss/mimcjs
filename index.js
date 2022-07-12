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
    for (var i = 0; i < input.length; i++) {
        input[i] = input[i] % P;
        k = mimcCipher(input[i], roundConstants, k);
    }
    return k;
}

function mimcHashAny(inputs) {
    if (!Array.isArray(inputs)) {
        throw "Expected inputs should be array"; 
    }
    if (typeof k == "undefined") {
        k = BigInt(0);
    }
    let preimage = [];
    for (var i = 0; i < inputs.length; i++) {
        preimage.push(BigInt(inputs[i]));
    }
    return mimcHash(preimage, ROUND_CONSTANTS, k);
}

module.exports = { mimcHashAny };

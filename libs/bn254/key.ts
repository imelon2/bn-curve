import { PrivKey, numberToBytesBE } from '@noble/curves/abstract/utils';
import { bn254 } from '@noble/curves/bn254'; // also known as alt_bn128

export class Key {
    constructor() {}

    static randomPrivateKey() {
        return bn254.utils.randomPrivateKey();
    }

    static getPrivateKey(number:number) {
        return numberToBytesBE(number,bn254.CURVE.nByteLength)
    }

    static getPublicKey(privateKey:PrivKey) {
        return bn254.getPublicKey(privateKey)
    }

    static isVaildSk(privateKey:PrivKey) {
        return bn254.utils.isValidPrivateKey(privateKey)
    }
}
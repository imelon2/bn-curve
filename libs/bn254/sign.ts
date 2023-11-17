import { Hex, PrivKey, utf8ToBytes } from '@noble/curves/abstract/utils';
import { bn254 } from '@noble/curves/bn254'; // also known as alt_bn128

type SignatureLike = { r: bigint; s: bigint }

export class Signature {

    static signMessage(message:string,privateKey:PrivKey) {
        return bn254.sign(utf8ToBytes(message), privateKey);
    }

    static verifySignature(signature:Hex | SignatureLike,message:string, publicKey:Hex) {
        return bn254.verify(signature, utf8ToBytes(message), publicKey);
    }

}
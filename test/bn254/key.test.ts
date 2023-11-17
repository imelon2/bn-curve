import { Key } from '../../libs/bn254/key'
import { bytesToHex } from '@noble/curves/abstract/utils';

describe("Test BN254 - Key",() => {
    it("get Random Secret Key",() => {
        const sk = Key.randomPrivateKey();
        console.log(`SecretKey : 0x${bytesToHex(sk)}`);
    })

    it("get Secret Key by number",() => {
        const sk = Key.getPrivateKey(1);
        console.log(`SecretKey : 0x${bytesToHex(sk)}`);
    }) 

    it("get Public Key by Secret Key",() => {
        const sk = Key.getPrivateKey(30);
        console.log(`SecretKey : 0x${bytesToHex(sk)}`);
        const pk = Key.getPublicKey(sk)
        console.log(`PublicKey : 0x${bytesToHex(pk)}`);
    })   
})
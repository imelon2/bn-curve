import { bytesToHex } from '@noble/curves/abstract/utils';
import { MCL } from '../../libs/mcl/mcl';
import { FIELD_ORDER, hashToField, stringToHex, toBig } from '../../libs/mcl/utils';
import { Fr, G2 } from 'mcl-wasm';
import { BigNumber } from 'ethers';

describe("Test BN254",() => {
    let mcl:MCL;
    let sk:Fr;
    let pk:G2;
    beforeAll(async () => {
        mcl = new MCL();
        await mcl.init()
    })
    describe("Test Key",() => {
        // it("get Random Secret Key",() => {
        //     const sk = mcl.randomSecretKey();
        //     console.log(`SecretKey : ${sk.serializeToHexStr()}`);
        // })

        // it("get Random Key Pair",() => {
        //     const {pubkey : pk, secret : sk} = mcl.newKeyPair();
        //     console.log(`SecretKey : ${sk.serializeToHexStr()}`);
        //     console.log(`PublicKey : ${pk.serializeToHexStr()}`);
            
            
            
        //     console.log(toBig(1));
            
        //     console.log(`X : ${pk.getX().serialize()}`);
        //     // console.log(`X : ${mcl.mclToHex(pk.getX())}`);

        // })
    
        // it("get Public Key by Secret Key",() => {
        //     const sk_ser = "8c5952254dcc12055497235697740e9cf4c10d43402eedaa44816a1b79522e18"
        //     sk = mcl.getPrivateKeyByHexSerialize(sk_ser)

        //     expect(sk_ser).toBe(sk.serializeToHexStr());
        //     console.log(`SecretKey : ${sk.serializeToHexStr()}`);
        //     pk = mcl.getPublicKey(sk)
        //     console.log(`PublicKey : ${pk.serializeToHexStr()}`);
        // })   

        it("get Random Secret Key",() => {
            let message = "Sign Message";
            console.log(stringToHex(message));
            
            const { signature, M }= mcl.sign(stringToHex(message),sk);
            let message_ser = mcl.g1ToBN(M);
            let pubkey_ser = mcl.g2ToBN(pk);
            let sig_ser = mcl.g1ToBN(signature);
            console.log("message : " + message_ser);
            console.log("public key : " + pubkey_ser);
            console.log("signature : " + sig_ser);
            
        })
    })
})
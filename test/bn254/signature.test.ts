import { Hex, PrivKey, bytesToHex, utf8ToBytes } from "@noble/curves/abstract/utils";
import { Key } from "../../libs/bn254/key";
import { Signature } from "../../libs/bn254/sign";
import { SignatureType } from "@noble/curves/abstract/weierstrass";

describe("Test BN254 - Signature", () => {
    let number = 30;
    const sk_ser = "0x8c5952254dcc12055497235697740e9cf4c10d43402eedaa44816a1b79522e18"
    let sk:PrivKey; // 0x000000000000000000000000000000000000000000000000000000000000001e
    let pk:Hex; // 0x02036083bfa420b15a4c11f66a3cffd55318b019feb45f833a876e93848625f5ae
    let message = "Sign Message";
    let signature:SignatureType;
    beforeAll(() => {
        
        sk = Key.getPrivateKey(number);
        pk = Key.getPublicKey(sk)

        console.log(`SecretKey : 0x${bytesToHex(sk)}`);
        console.log(`PublicKey : 0x${bytesToHex(pk)}`);
        console.log("-------------------------------");
        
    })

    describe("📝 Test noble-curves Library",() => {
        it("Sign Message",() => {
            console.log(utf8ToBytes(message));
            signature = Signature.signMessage(message,sk_ser)
            console.log(`Signature : 0x${signature.toCompactHex()}`);
        })
    
        // it("Verify Signature",() => {
        //     const isValid = Signature.verifySignature(signature,message,pk)
        //     console.log(`Is Valid ?? : ${isValid}`);
        // })
    })

})
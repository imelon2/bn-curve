import { ethers } from "ethers";
import { FIELD_ORDER, hashToField, randHex, toBig } from "./utils";
import _mcl, { Fp, Fp2, Fr, G1, G2 } from "mcl-wasm"
import { isHexString } from "ethers/lib/utils";

export class MCL {
  private mcl = _mcl || require("mcl-wasm")

  constructor() { }

  async init() {
    await this.mcl.init(this.mcl.BN_SNARK1);
    this.mcl.setMapToMode(0);
  }

  test() {
    return this.mcl;
  }

  /**
   * @function setByCSPRNG() : 안전한 난수(CSPRNG : Cryptographically Secure Pseudo-Random Number Generator) 생성
   * @returns 
   */
  #_randFr() {
    let fr = new this.mcl.Fr();
    fr.setByCSPRNG();
    return fr;
  }


  mclToHex(p:Fp|Fp2, prefix: boolean = true) {
    const arr = p.serialize();
    let s = '';
    for (let i = arr.length - 1; i >= 0; i--) {
      s += ('0' + arr[i].toString(16)).slice(-2);
    }
    return prefix ? '0x' + s : s;
  }

  /**
   * @description G1 상의 좌표 숫자(bignumber)로 변환
   * @param p G1
   * @returns 좌표 x(32 bytes), y(32 bytes)
   */
  g1ToBN(p: G1) {
    p.normalize();
    const x = toBig(this.mclToHex(p.getX())); // serialize[byte array] -> Hex -> number(n)
    const y = toBig(this.mclToHex(p.getY()));
    return [x, y]; // 64 bytes
  }

  /**
   * @description G2 상의 좌표 숫자(bignumber)로 변환
   * @param p G2
   * @returns 좌표 x(64 bytes), y(64 bytes)
   */
  g2ToBN(p: G2) {
    const x = this.mclToHex(p.getX(), false);
    const y = this.mclToHex(p.getY(), false);
    return [
      toBig('0x' + x.slice(64)), // 32 bytes
      toBig('0x' + x.slice(0, 64)), // 32 bytes
      toBig('0x' + y.slice(64)), // 32 bytes
      toBig('0x' + y.slice(0, 64)), // 32 bytes
    ]; // 128 bytes
  }

  mapToPoint(eHex: string) {
    const e0 = toBig(eHex);
    let e1 = new this.mcl.Fp();
    e1.setStr(e0.mod(FIELD_ORDER).toString());
    return e1.mapToG1();
  }

  hashToPoint(msg: string) {
    if (!isHexString(msg)) {
      throw new Error('message is expected to be hex string');
    }
    const DOMAIN_STR = '';
    const DOMAIN = Uint8Array.from(Buffer.from(DOMAIN_STR, 'utf8'));
    const _msg = Uint8Array.from(Buffer.from(msg.slice(2), 'hex'));
    const hashRes = hashToField(DOMAIN, _msg, 2);
    const e0 = hashRes[0];
    const e1 = hashRes[1];
    const p0 = this.mapToPoint(e0.toHexString());
    const p1 = this.mapToPoint(e1.toHexString());
    const p = this.mcl.add(p0, p1);
    p.normalize();
    return p;
  }

  /**
   * @description bn254 G1의 base point 설정
   * @readonly 서명 데이터 표현 
   * @returns bn254 G1의 base point
   */
  g1() {
    const g1 = new this.mcl.G1();
    g1.setStr('1 0x01 0x02', 16);
    return g1;
  }

  /**
   * @description bn254 G2의 base point 설정
   * @readonly 공개키 표현
   * @returns bn254 G2의 base point
   */
  g2() {
    const g2 = new this.mcl.G2();
    g2.setStr(
      '1 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b'
    );
    return g2;
  }

  randomSecretKey() {
    return this.#_randFr()
  }

  newKeyPair() {
    const secret = this.#_randFr();
    const pubkey = this.mcl.mul(this.g2(), secret);
    pubkey.normalize();
    return { pubkey, secret };
  }

  getPrivateKeyByHexSerialize(serialize: string) {
    let fr = new this.mcl.Fr();
    fr.deserializeHexStr(serialize)
    return fr;
  }

  getPublicKey(secret: Fr) {
    const pubkey = this.mcl.mul(this.g2(), secret);
    pubkey.normalize();
    return pubkey
  }

  sign(message: string, secret: any) {
    const M = this.hashToPoint(message);
    const signature = this.mcl.mul(M, secret);
    signature.normalize();
    return { signature, M };
  }
}
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = decrypt;
const crypto_1 = __importDefault(require("crypto"));
const http_ece_1 = __importDefault(require("http_ece"));
// Parses a header value like "dh=BASE64; p256ecdsa=BASE64" into { dh: "BASE64", p256ecdsa: "BASE64" }
function parseHeaderParams(header) {
    return Object.fromEntries(header
        .split(';')
        .map(part => {
        const [key, ...rest] = part.trim().split('=');
        const trimmedKey = key.trim();
        const value = rest.join('=').trim();
        return [trimmedKey, value];
    })
        .filter(([key]) => key !== ''));
}
// https://tools.ietf.org/html/draft-ietf-webpush-encryption-03
function decrypt(object, keys) {
    const cryptoKey = object.appData.find(item => item.key === 'crypto-key');
    if (!cryptoKey)
        throw new Error('crypto-key is missing');
    const salt = object.appData.find(item => item.key === 'encryption');
    if (!salt)
        throw new Error('salt is missing');
    const cryptoKeyParams = parseHeaderParams(cryptoKey.value);
    const saltParams = parseHeaderParams(salt.value);
    if (!cryptoKeyParams.dh)
        throw new Error('crypto-key header is missing dh parameter');
    if (!saltParams.salt)
        throw new Error('encryption header is missing salt parameter');
    const dh = crypto_1.default.createECDH('prime256v1');
    dh.setPrivateKey(keys.privateKey, 'base64');
    const params = {
        version: 'aesgcm',
        authSecret: keys.authSecret,
        dh: cryptoKeyParams.dh,
        privateKey: dh,
        salt: saltParams.salt,
    };
    const decrypted = http_ece_1.default.decrypt(object.rawData, params);
    return JSON.parse(decrypted);
}
//# sourceMappingURL=decrypt.js.map
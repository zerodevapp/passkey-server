import { type Address, type Hex } from "viem";
import { decode } from "cbor-web";

const authenticationdata = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA"

export const b64ToBytes = (base64: string): Uint8Array => {
    const paddedBase64 = base64.replace(/-/g, '+').replace(/_/g, '/').padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
    const binString = atob(paddedBase64);
    return Uint8Array.from(binString, (m) => m.codePointAt(0) ?? 0);
};

export const uint8ArrayToHexString = (array: Uint8Array): string => {
    return '0x' + Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
};

console.log(uint8ArrayToHexString(b64ToBytes(authenticationdata)))

export function checkAuthenticatorDataFlags(authData: Uint8Array | string, requireUserVerification: boolean): boolean {
    const AUTH_DATA_FLAGS_UP = 0x01; // User Present
    const AUTH_DATA_FLAGS_UV = 0x04; // User Verified
    const AUTH_DATA_FLAGS_BE = 0x08; // Backup Eligibility
    const AUTH_DATA_FLAGS_BS = 0x10; // Backup State

    let data: Uint8Array;

    if (typeof authData === 'string') {
        // Convert hex string to Uint8Array
        data = new Uint8Array(authData.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
    } else {
        data = authData;
    }

    // Extract the flags byte from the authenticator data
    const flagsByte = data[32];

    // Check the UP flag - User Present (bit 0)
    if ((flagsByte & AUTH_DATA_FLAGS_UP) !== AUTH_DATA_FLAGS_UP) {
        return false;
    }

    // Check the UV flag - User Verified (bit 2)
    if (requireUserVerification && (flagsByte & AUTH_DATA_FLAGS_UV) !== AUTH_DATA_FLAGS_UV) {
        return false;
    }

    // Check the BE and BS flags - Backup Eligibility and Backup State (bits 3 and 4)
    if ((flagsByte & AUTH_DATA_FLAGS_BE) !== AUTH_DATA_FLAGS_BE) {
        if ((flagsByte & AUTH_DATA_FLAGS_BS) === AUTH_DATA_FLAGS_BS) {
            return false;
        }
    }

    // If all checks pass
    return true;
}

console.log(checkAuthenticatorDataFlags(b64ToBytes(authenticationdata), true))

const sig = "MEUCIQC124Ld03QqpdSpU1L_H01WFBjB5Rbuf50ygLv09XqZhAIgYLdCO942oYkKqJHBiWsoQPotke2OTmPy_XALjF0Wguc"
console.log(uint8ArrayToHexString(b64ToBytes(sig)))

const sigHex = "0x3045022100b5db82ddd3742aa5d4a95352ff1f4d561418c1e516ee7f9d3280bbf4f57a9984022060b7423bde36a1890aa891c1896b2840fa2d91ed8e4e63f2fd700b8c5d1682e7"

function splitECDSASignature(signatureHex: string): { r: BigInt; s: BigInt } {
    // Remove 0x prefix if present
    const formattedSignatureHex = signatureHex.startsWith('0x') ? signatureHex.substring(2) : signatureHex;

    // Convert hex to Buffer
    const signatureBuffer = Buffer.from(formattedSignatureHex, 'hex');

    // Check if it's a valid DER sequence
    if (signatureBuffer[0] !== 0x30) {
        throw new Error('Invalid signature format');
    }

    // Get the length of the entire signature
    const totalLength = signatureBuffer[1];

    // Check if the total length matches the length of the signature minus the first two bytes
    if (totalLength !== signatureBuffer.length - 2) {
        throw new Error('Invalid signature length');
    }

    // Initialize pointers for parsing
    let index = 2; // Start after the 0x30 and length byte

    // Parse R value
    if (signatureBuffer[index] !== 0x02) {
        throw new Error('Invalid R value format');
    }
    index++; // Move past the 0x02 byte
    const rLength = signatureBuffer[index];
    index++; // Move past the length byte
    const rValue = signatureBuffer.subarray(index, index + rLength).toString('hex');
    index += rLength;

    // Parse S value
    if (signatureBuffer[index] !== 0x02) {
        throw new Error('Invalid S value format');
    }
    index++; // Move past the 0x02 byte
    const sLength = signatureBuffer[index];
    index++; // Move past the length byte
    const sValue = signatureBuffer.subarray(index, index + sLength).toString('hex');
    index += sLength;

    return { r: BigInt('0x' + rValue), s: BigInt('0x' + sValue) };
}




console.log(splitECDSASignature(sigHex))

const publicKeyBase64 = "pQECAyYgASFYIPNXhseRO+WdxEpIFqCHFf1DOSmnP6YuK0W0NjeAWuRBIlggioKnJkagBV1WBPN8k/qLSj+VsRQK5xNk5EJODJ7dwqE="

export function convertBase64PublicKeyToXY(publicKey: string): { x: BigInt, y: BigInt } {
    const publicKeyBuffer = b64ToBytes(publicKey);
    if (typeof decode !== 'function') {
        throw new Error('CBOR decode function is not available');
    }
    const publicKeyObject = decode(new Uint8Array(publicKeyBuffer.buffer));
    const xBuffer = publicKeyObject.get(-2);
    const yBuffer = publicKeyObject.get(-3);
    if (!(xBuffer instanceof Uint8Array) || !(yBuffer instanceof Uint8Array)) {
        throw new Error('Invalid public key object structure');
    }
    const x = BigInt('0x' + Array.from(xBuffer).map((byte: number) => byte.toString(16).padStart(2, '0')).join(''));
    const y = BigInt('0x' + Array.from(yBuffer).map((byte: number) => byte.toString(16).padStart(2, '0')).join(''));
    return { x, y };
}

console.log(convertBase64PublicKeyToXY(publicKeyBase64))


const clientDataJSON = `{"type":"webauthn.get","challenge":"ud4HobLgZGAU2Y_dOZQo5P59xSO2YqQjI80Q63_tY_o","origin":"http://localhost:5173","crossOrigin":false}`

export const findQuoteIndices = (input: string): { beforeT: BigInt, beforeChallenge: BigInt } => {
    const beforeTIndex = input.lastIndexOf('"t');
    const beforeChallengeIndex = input.lastIndexOf('"challenge"');
    if (beforeTIndex === -1 || beforeChallengeIndex === -1) {
        throw new Error('Invalid client data JSON');
    }
    const beforeT = BigInt(beforeTIndex);
    const beforeChallenge = BigInt(beforeChallengeIndex);
    return { beforeT, beforeChallenge };
};

console.log(findQuoteIndices(clientDataJSON))

function hexToUtf8String(hex: string): string {
    // Ensure the hex string is formatted correctly
    const formattedHex = hex.startsWith('0x') ? hex.slice(2) : hex;

    // Convert the hex string to a UTF-8 string
    let utf8String = '';
    for (let i = 0; i < formattedHex.length; i += 2) {
        utf8String += String.fromCharCode(parseInt(formattedHex.substr(i, 2), 16));
    }

    return utf8String;
}

// Example usage
const challengeHex = '0x00768318523586d88aeaa05610d5699233e2b29487203d5ffc482c82903bea26';
const message = hexToUtf8String(challengeHex);
console.log("message", message);

//create a function utf8StringToHex that does the reverse
function utf8StringToHex(utf8String: string): string {
    // Convert the UTF-8 string to a hex string
    let hex = '';
    for (let i = 0; i < utf8String.length; i++) {
        hex += utf8String.charCodeAt(i).toString(16);
    }

    return '0x' + hex;
}
console.log("utf8StringToHex", utf8StringToHex(message));


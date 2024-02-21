import { base64 } from "@scure/base"
import { p256 } from "@noble/curves/p256"
import {
    Hex,
    bytesToBigInt,
    hexToBytes,
    bytesToHex,
    createPublicClient,
    http
} from "viem"
import { polygonMumbai } from "viem/chains"
import { decode, decodeAllSync } from "cbor-web"
import { Buffer } from "buffer"

const derPrefix = "0x3059301306072a8648ce3d020106082a8648ce3d03010703420004"

export type CreateResult = {
    rawClientDataJSONB64: string
    rawAttestationObjectB64: string
}

export type SignResult = {
    passkeyName: string
    rawClientDataJSONB64: string
    rawAuthenticatorDataB64: string
    signatureB64: string
}

export async function postJson(url: string, body: any): Promise<any> {
    const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
    })
    return response.ok ? response.json() : response.text()
}

export function log(message: any): void {
    const logsEl = document.getElementById("logs")
    if (logsEl) {
        logsEl.innerHTML += `<pre>${JSON.stringify(message, null, 2)}</pre>`
        logsEl.hidden = false
    }
}
export function status(message: string): void {
    const statusEl = document.getElementById("status")
    if (statusEl) {
        statusEl.textContent = message
        statusEl.hidden = false
    }
}

// Parses authenticatorData buffer to struct
// https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
export function parseMakeCredAuthData(buffer: Uint8Array) {
    const rpIdHash = buffer.slice(0, 32)
    buffer = buffer.slice(32)
    const flagsBuf = buffer.slice(0, 1)
    buffer = buffer.slice(1)
    const flags = flagsBuf[0]
    const counterBuf = buffer.slice(0, 4)
    buffer = buffer.slice(4)
    const counter = Buffer.from(counterBuf).readUInt32BE(0)
    const aaguid = buffer.slice(0, 16)
    buffer = buffer.slice(16)
    const credIDLenBuf = buffer.slice(0, 2)
    buffer = buffer.slice(2)
    const credIDLen = Buffer.from(credIDLenBuf).readUInt16BE(0)
    const credID = buffer.slice(0, credIDLen)
    buffer = buffer.slice(credIDLen)
    const COSEPublicKey = buffer

    return {
        rpIdHash,
        flagsBuf,
        flags,
        counter,
        counterBuf,
        aaguid,
        credID,
        COSEPublicKey
    }
}

// Takes COSE encoded public key and converts it to DER keys
// https://www.rfc-editor.org/rfc/rfc8152.html#section-13.1
function COSEECDHAtoDER(COSEPublicKey: Uint8Array): Hex {
    const coseStruct = decodeAllSync(COSEPublicKey)[0]
    const x = coseStruct.get(-2)
    const y = coseStruct.get(-3)

    return contractFriendlyKeyToDER([
        `0x${Buffer.from(x).toString("hex")}`,
        `0x${Buffer.from(y).toString("hex")}`
    ])
}

// Parses Webauthn MakeCredential response
// https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred
export function parseCreateResponse(result: CreateResult) {
    const rawAttestationObject = base64.decode(result.rawAttestationObjectB64)
    const attestationObject = decode(rawAttestationObject)
    const authData = parseMakeCredAuthData(attestationObject.authData)
    const pubKey = COSEECDHAtoDER(authData.COSEPublicKey)
    return pubKey
}

// Parses Webauthn GetAssertion response
// https://www.w3.org/TR/webauthn-2/#sctn-op-get-assertion
export function parseSignResponse(result: SignResult) {
    const derSig = base64.decode(result.signatureB64)
    const rawAuthenticatorData = base64.decode(result.rawAuthenticatorDataB64)
    const passkeyName = result.passkeyName
    const [accountName, keySlotStr] = passkeyName.split(".") // Assumes account name does not have periods (.) in it.
    const keySlot = parseInt(keySlotStr, 10)

    const clientDataJSON = Buffer.from(
        base64.decode(result.rawClientDataJSONB64)
    ).toString("utf-8")

    const challengeLocation = BigInt(clientDataJSON.indexOf('"challenge":"'))
    const responseTypeLocation = BigInt(clientDataJSON.indexOf('"type":"'))

    return {
        derSig: bytesToHex(derSig),
        rawAuthenticatorData,
        accountName,
        keySlot,
        clientDataJSON,
        challengeLocation,
        responseTypeLocation
    }
}

export function isDERPubKey(pubKeyHex: Hex): boolean {
    return (
        pubKeyHex.startsWith(derPrefix) &&
        pubKeyHex.length === derPrefix.length + 128
    )
}

export function derKeytoContractFriendlyKey(pubKeyHex: Hex): [Hex, Hex] {
    if (!isDERPubKey(pubKeyHex)) {
        throw new Error("Invalid public key format")
    }

    const pubKey = pubKeyHex.substring(derPrefix.length)
    // assert(pubKey.length === 128);

    const key1 = `0x${pubKey.substring(0, 64)}` as Hex
    const key2 = `0x${pubKey.substring(64)}` as Hex
    return [key1, key2]
}

export function contractFriendlyKeyToDER(
    accountPubkey: readonly [Hex, Hex]
): Hex {
    return (derPrefix +
        accountPubkey[0].substring(2) +
        accountPubkey[1].substring(2)) as Hex
}

// Parse DER-encoded P256-SHA256 signature to contract-friendly signature
// and normalize it so the signature is not malleable.
export function parseAndNormalizeSig(derSig: Hex): { r: bigint; s: bigint } {
    const parsedSignature = p256.Signature.fromDER(derSig.slice(2))
    const bSig = hexToBytes(`0x${parsedSignature.toCompactHex()}`)
    // assert(bSig.length === 64, "signature is not 64 bytes");
    const bR = bSig.slice(0, 32)
    const bS = bSig.slice(32)

    // Avoid malleability. Ensure low S (<= N/2 where N is the curve order)
    const r = bytesToBigInt(bR)
    let s = bytesToBigInt(bS)
    const n = BigInt(
        "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
    )
    if (s > n / 2n) {
        s = n - s
    }
    return { r, s }
}

export function checkAuthenticatorDataFlags(
    authData: Uint8Array | string,
    requireUserVerification: boolean
): boolean {
    const AUTH_DATA_FLAGS_UP = 0x01 // User Present
    const AUTH_DATA_FLAGS_UV = 0x04 // User Verified
    const AUTH_DATA_FLAGS_BE = 0x08 // Backup Eligibility
    const AUTH_DATA_FLAGS_BS = 0x10 // Backup State

    let data: Uint8Array

    if (typeof authData === "string") {
        // Convert hex string to Uint8Array
        data = new Uint8Array(
            authData.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
        )
    } else {
        data = authData
    }

    // Extract the flags byte from the authenticator data
    const flagsByte = data[32]

    // Check the UP flag - User Present (bit 0)
    if ((flagsByte & AUTH_DATA_FLAGS_UP) !== AUTH_DATA_FLAGS_UP) {
        return false
    }

    // Check the UV flag - User Verified (bit 2)
    if (
        requireUserVerification &&
        (flagsByte & AUTH_DATA_FLAGS_UV) !== AUTH_DATA_FLAGS_UV
    ) {
        return false
    }

    // Check the BE and BS flags - Backup Eligibility and Backup State (bits 3 and 4)
    if ((flagsByte & AUTH_DATA_FLAGS_BE) !== AUTH_DATA_FLAGS_BE) {
        if ((flagsByte & AUTH_DATA_FLAGS_BS) === AUTH_DATA_FLAGS_BS) {
            return false
        }
    }

    // If all checks pass
    return true
}

export const b64ToBytes = (base64: string): Uint8Array => {
    const paddedBase64 = base64
        .replace(/-/g, "+")
        .replace(/_/g, "/")
        .padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=")
    const binString = atob(paddedBase64)
    return Uint8Array.from(binString, (m) => m.codePointAt(0) ?? 0)
}

const WEBAUTHN_WRAPPER_ABI = [
    {
        type: "function",
        name: "verify",
        inputs: [
            { name: "challenge", type: "bytes", internalType: "bytes" },
            { name: "authenticatorData", type: "bytes", internalType: "bytes" },
            {
                name: "userVerificationRequired",
                type: "bool",
                internalType: "bool"
            },
            { name: "clientDataJSON", type: "string", internalType: "string" },
            {
                name: "challengeLocation",
                type: "uint256",
                internalType: "uint256"
            },
            {
                name: "responseTypeLocation",
                type: "uint256",
                internalType: "uint256"
            },
            { name: "r", type: "uint256", internalType: "uint256" },
            { name: "s", type: "uint256", internalType: "uint256" },
            { name: "x", type: "uint256", internalType: "uint256" },
            { name: "y", type: "uint256", internalType: "uint256" }
        ],
        outputs: [{ name: "", type: "bool", internalType: "bool" }],
        stateMutability: "view"
    }
]
const WEBAUTHN_WRAPPER_ADDRESS = "0x98f79C2A71981Da661136b077E9F28c5A8962B58"

const publicClient = createPublicClient({
    chain: polygonMumbai,
    transport: http()
})

export const verify = async (
    challenge: string,
    authenticatorData: string,
    userVerificationRequired: boolean,
    clientDataJSON: string,
    challengeLocation: BigInt,
    responseTypeLocation: BigInt,
    r: BigInt,
    s: BigInt,
    x: BigInt,
    y: BigInt
) => {
    const result = await publicClient.readContract({
        abi: WEBAUTHN_WRAPPER_ABI,
        address: WEBAUTHN_WRAPPER_ADDRESS,
        functionName: "verify",
        args: [
            challenge,
            authenticatorData,
            userVerificationRequired,
            clientDataJSON,
            challengeLocation,
            responseTypeLocation,
            r,
            s,
            x,
            y
        ]
    })
    return result
}

export const uint8ArrayToHexString = (array: Uint8Array): `0x${string}` => {
    return `0x${Array.from(array, (byte) =>
        byte.toString(16).padStart(2, "0")
    ).join("")}` as `0x${string}`
}

export function splitECDSASignature(signatureHex: Hex): { r: Hex; s: Hex } {
    // Remove 0x prefix if present
    const formattedSignatureHex = signatureHex.startsWith("0x")
        ? signatureHex.substring(2)
        : signatureHex

    // Convert hex to Buffer
    const signatureBuffer = Buffer.from(formattedSignatureHex, "hex")

    // Check if it's a valid DER sequence
    if (signatureBuffer[0] !== 0x30) {
        throw new Error("Invalid signature format")
    }

    // Get the length of the entire signature
    const totalLength = signatureBuffer[1]

    // Check if the total length matches the length of the signature minus the first two bytes
    if (totalLength !== signatureBuffer.length - 2) {
        throw new Error("Invalid signature length")
    }

    // Initialize pointers for parsing
    let index = 2
    if (signatureBuffer[index] !== 0x02) {
        throw new Error("Invalid R value format")
    }
    index++
    const rLength = signatureBuffer[index]
    index++
    const rValue = `0x${signatureBuffer
        .subarray(index, index + rLength)
        .toString("hex")}` as Hex
    index += rLength

    if (signatureBuffer[index] !== 0x02) {
        throw new Error("Invalid S value format")
    }
    index++
    const sLength = signatureBuffer[index]
    index++
    const sValue = `0x${signatureBuffer
        .subarray(index, index + sLength)
        .toString("hex")}` as Hex

    return { r: rValue, s: sValue }
}

//use COSEECDHAtoDER
export function convertBase64PublicKeyToXY(publicKey: string): {
    x: Hex
    y: Hex
} {
    const publicKeyBuffer = b64ToBytes(publicKey)
    if (typeof decode !== "function") {
        throw new Error("CBOR decode function is not available")
    }
    const publicKeyObject = decode(new Uint8Array(publicKeyBuffer.buffer))
    const xBuffer = publicKeyObject.get(-2)
    const yBuffer = publicKeyObject.get(-3)
    if (!(xBuffer instanceof Uint8Array) || !(yBuffer instanceof Uint8Array)) {
        throw new Error("Invalid public key object structure")
    }
    const x = uint8ArrayToHexString(xBuffer)
    const y = uint8ArrayToHexString(yBuffer)
    return { x, y }
}

export const findQuoteIndices = (
    input: string
): { beforeType: bigint; beforeChallenge: bigint } => {
    const beforeTypeIndex = BigInt(input.lastIndexOf('"type":"webauthn.get"'))
    const beforeChallengeIndex = BigInt(input.indexOf('"challenge'))
    return {
        beforeType: beforeTypeIndex,
        beforeChallenge: beforeChallengeIndex
    }
}

export function hexToUtf8String(hex: string): string {
    // Ensure the hex string is formatted correctly
    const formattedHex = hex.startsWith("0x") ? hex.slice(2) : hex

    // Convert the hex string to a UTF-8 string
    let utf8String = ""
    for (let i = 0; i < formattedHex.length; i += 2) {
        utf8String += String.fromCharCode(
            parseInt(formattedHex.substr(i, 2), 16)
        )
    }

    return utf8String
}

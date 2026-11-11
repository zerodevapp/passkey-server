import { cose, decodeCredentialPublicKey, isoBase64URL, isoUint8Array } from "@simplewebauthn/server/helpers"

// DER prefix of a P-256 SubjectPublicKeyInfo, up to the uncompressed-point marker (0x04).
const P256_SPKI_PREFIX = isoUint8Array.fromHex(
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
)

/**
 * The SPKI public key (base64url) browsers report as `response.publicKey`, rebuilt from the
 * verified COSE key. Browsers without `getPublicKey()` omit it. Null when the key is not P-256,
 * the only curve the Kernel passkey validator supports.
 */
export function spkiFromCosePublicKey(cosePublicKey: Uint8Array): string | null {
    const key = decodeCredentialPublicKey(cosePublicKey)
    if (!cose.isCOSEPublicKeyEC2(key) || key.get(cose.COSEKEYS.crv) !== cose.COSECRV.P256) {
        return null
    }
    const x = key.get(cose.COSEKEYS.x)
    const y = key.get(cose.COSEKEYS.y)
    if (x?.length !== 32 || y?.length !== 32) return null
    return isoBase64URL.fromBuffer(isoUint8Array.concat([P256_SPKI_PREFIX, x, y]))
}

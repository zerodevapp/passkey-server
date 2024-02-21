import { Base64URLString } from "@simplewebauthn/typescript-types"

export type User = {
    username: string
    data: string
    credentials: Record<string, Credential>
}

export type Credential = {
    pubKey?: string
    credentialID: Base64URLString // serialize to handle Uint8Array in Redis
    credentialPublicKey: Base64URLString // serialize to handle Uint8Array in Redis
    counter: number
}

export type Challenge = boolean

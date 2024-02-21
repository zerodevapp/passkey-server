import {
    generateAuthenticationOptions,
    generateRegistrationOptions,
    verifyAuthenticationResponse,
    verifyRegistrationResponse
} from "@simplewebauthn/server"
import type {
    AuthenticationResponseJSON,
    Base64URLString,
    RegistrationResponseJSON
} from "@simplewebauthn/typescript-types"
import { jwtVerify, SignJWT } from "jose"
import { Hono } from "hono"
import { getSignedCookie, setSignedCookie } from "hono/cookie"
import { serveStatic } from "hono/bun"
import { logger } from "hono/logger"
import { cors } from "hono/cors"
import { z } from "zod"
import {
    parseMakeCredAuthData,
    parseCreateResponse,
    parseSignResponse,
    derKeytoContractFriendlyKey,
    parseAndNormalizeSig,
    uint8ArrayToHexString,
    findQuoteIndices,
    convertBase64PublicKeyToXY,
    splitECDSASignature,
    b64ToBytes
} from "./utils"
import { AuthenticatorDevice } from "@simplewebauthn/typescript-types"
import { base64URLStringToBuffer } from "@simplewebauthn/browser"
import { encodeAbiParameters } from "viem"
import PasskeyRepository from "./src/repository/PasskeyRepository"

// TODO: make the key more unique

// CONSTANTS

const SECRET = new TextEncoder().encode(process.env.JWT_SECRET ?? "development")
// const RP_ID = process.env.WEBAUTHN_RP_ID ?? "localhost"
// const RP_NAME = process.env.WEBAUTHN_RP_NAME ?? "Bun Passkeys Demo"
const CHALLENGE_TTL = Number(process.env.WEBAUTHN_CHALLENGE_TTL) || 60_000

// UTILS
const registerOptionsSchema = z.object({
    username: z.string().min(1)
})

const registerVerifySchema = z.object({
    username: z.string().min(1)
})

function generateJWT(userId: string) {
    return new SignJWT({ userId })
        .setProtectedHeader({ alg: "HS256" })
        .sign(SECRET)
}

function verifyJWT(token: string) {
    return jwtVerify(token, SECRET)
}

function generateRandomID() {
    const id = crypto.getRandomValues(new Uint8Array(32))

    return btoa(
        Array.from(id)
            .map((c) => String.fromCharCode(c))
            .join("")
    )
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "")
}

const authenticatorDevice = {
    credentialID: new Uint8Array(),
    credentialPublicKey: new Uint8Array(),
    counter: 0
}

async function recoverPublicKeyFromSignature(
    cred: AuthenticationResponseJSON
): Promise<string | null> {
    try {
        const verification = await verifyAuthenticationResponse({
            response: cred,
            expectedChallenge: cred.response.clientDataJSON,
            expectedOrigin: "the expected origin",
            expectedRPID: RP_ID,
            authenticator: authenticatorDevice
        })

        if (verification.verified && verification.authenticationInfo) {
            const { signature, authenticatorData } = cred.response
            const { credentialPublicKey } = authenticatorDevice

            const publicKey = await crypto.subtle.importKey(
                "raw",
                credentialPublicKey,
                {
                    name: "ECDSA",
                    namedCurve: "P-256"
                },
                true,
                ["verify"]
            )

            const signatureArray = base64urlToUint8Array(signature)
            const authenticatorDataArray =
                base64urlToUint8Array(authenticatorData)

            const result = await crypto.subtle.verify(
                {
                    name: "ECDSA",
                    hash: "SHA-256"
                },
                publicKey,
                signatureArray,
                authenticatorDataArray
            )

            if (result) {
                return btoa(
                    String.fromCharCode(
                        ...Array.from(
                            new Uint8Array(credentialPublicKey.buffer, 27, 65)
                        )
                    )
                )
            }
        }
    } catch (error) {
        console.error(error)
    }
    return null
}

function base64urlToUint8Array(base64url: string): Uint8Array {
    const padding = "=".repeat((4 - (base64url.length % 4)) % 4)
    const base64 = (base64url + padding).replace(/\-/g, "+").replace(/_/g, "/")

    const rawData = atob(base64)
    const outputArray = new Uint8Array(rawData.length)

    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i)
    }

    return outputArray
}

function uint8ArrayToBase64(uint8Array: Uint8Array): string {
    return Buffer.from(uint8Array).toString("base64")
}

function fromBase64ToUint8Array(base64String): Uint8Array {
    return Uint8Array.from(Buffer.from(base64String, "base64"))
}

type User = {
    username: string
    data: string
    credentials: Record<string, Credential>
}

type Credential = {
    pubKey?: string
    credentialID: Base64URLString // serialize to handle Uint8Array in Redis
    credentialPublicKey: Base64URLString // serialize to handle Uint8Array in Redis
    counter: number
}

type Challenge = boolean

// RP SERVER

const app = new Hono()

app.use("*", logger())

app.use("*", cors({ credentials: true, origin: (origin) => origin || "*" }))

app.get("/index.js", serveStatic({ path: "./index.js" }))

app.get("/", serveStatic({ path: "./index.html" }))

// app.get("/dummy-signature/:userId", async (c) => {
//     const userId = c.req.param("userId")

//     // Ensure the userId is provided
//     if (!userId) {
//         return c.text("User ID is required", 400)
//     }

//     // Retrieve the dummy signature from the KV store
//     const dummySignatureData = await kv.get<string>(["dummySignature", userId])

//     // Check if the dummy signature exists
//     if (!dummySignatureData) { // Don't need to use .value
//         return c.text("Dummy signature not found", 404)
//     }

//     // Return the dummy signature to the client
//     return c.json({ dummySignature: dummySignatureData.value })
// })

// // Add new endpoint to process and display data
// app.post("/process-authentication", async (c) => {
//     const { cred } = await c.req.json()
//     const parsedData = parseSignResponse(cred)
//     const { r, s } = parseAndNormalizeSig(parsedData.derSig)
//     const [x, y] = derKeytoContractFriendlyKey(parseCreateResponse(cred))

//     return c.json({ r: r.toString(), s: s.toString(), x, y })
// })

app.post("/api/v2/:projectId/register/options", async (c) => {
    const { username } = await c.req.json<{ username: string }>()

    const projectId = c.req.param("projectId")
    const passkeyRepo = new PasskeyRepository()

    const domainName = await passkeyRepo.getPasskeyDomainByProjectId(projectId)

    const userID = generateRandomID()

    const options = await generateRegistrationOptions({
        rpName: domainName,
        rpID: domainName,
        userID,
        userName: username,
        userDisplayName: username,
        authenticatorSelection: {
            residentKey: "required",
            userVerification: "required",
            authenticatorAttachment: "platform"
        }
    })

    console.log({ options })

    passkeyRepo.set(["challenges", domainName, options.challenge], true, {
        expireIn: CHALLENGE_TTL
    })

    await setSignedCookie(c, "userId", userID, SECRET, {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        path: "/",
        maxAge: CHALLENGE_TTL
    })

    return c.json(options)
})

// app.get("/public-key/:credentialId", async (c) => {
//     const credentialId = c.req.param("credentialId")
//     const user = await kv.get<User>(["credentials", credentialId])
//     if (!user.value) return c.text("Credential not found", 404)

//     const publicKey = user.value.credentials[credentialId].credentialPublicKey
//     const publicKeyBase64 = btoa(
//         String.fromCharCode(...new Uint8Array(publicKey.buffer))
//     )

//     return c.json({ publicKey: publicKeyBase64 })
// })

app.post("/api/v2/:projectId/register/verify", async (c) => {
    // const validationResult = registerVerifySchema.safeParse(c.body)
    // if (!validationResult.success) {
    //     return c.json({ error: "Invalid request data" }, { status: 400 })
    // }

    const { username, cred } = await c.req.json<{
        username: string
        cred: RegistrationResponseJSON
    }>()

    // base64url to Uint8Array
    const pubKey = cred.response.publicKey!

    const userId = await getSignedCookie(c, SECRET, "userId")
    if (!userId) return new Response("Unauthorized", { status: 401 })

    const passkeyRepo = new PasskeyRepository()

    const domainName = await passkeyRepo.getPasskeyDomainByProjectId(
        c.req.param("projectId")
    )

    const clientData = JSON.parse(atob(cred.response.clientDataJSON))

    const challenge = await passkeyRepo.get([
        "challenges",
        domainName,
        clientData.challenge
    ])

    if (!challenge) {
        return c.text("Invalid challenge", 400)
    }

    const verification = await verifyRegistrationResponse({
        response: cred,
        expectedChallenge: clientData.challenge,
        expectedRPID: domainName,
        expectedOrigin: c.req.header("origin")!, //! Allow from any origin
        requireUserVerification: true
    })

    if (verification.verified) {
        const { credentialID, credentialPublicKey, counter } =
            verification.registrationInfo!

        await passkeyRepo.delete(["challenges", clientData.challenge])

        await passkeyRepo.set(["users", domainName, userId], {
            username: username,
            data: "Private user data for " + (username || "Anon"),
            credentials: {
                [cred.id]: {
                    pubKey,
                    credentialID: uint8ArrayToBase64(credentialID),
                    credentialPublicKey:
                        uint8ArrayToBase64(credentialPublicKey),
                    counter
                }
            }
        } as User)

        await setSignedCookie(c, "token", await generateJWT(userId), SECRET, {
            httpOnly: true,
            secure: true,
            sameSite: "None",
            path: "/",
            maxAge: 600_000
        })

        return c.json(verification)
    }

    return c.text("Unauthorized", 401)
})

app.get("/v1/health", (c) => c.json({ status: "ok" }))

app.post("/api/v2/:projectId/login/options", async (c) => {
    const projectId = c.req.param("projectId")
    const passkeyRepo = new PasskeyRepository()

    const domainName = await passkeyRepo.getPasskeyDomainByProjectId(projectId)

    const options = await generateAuthenticationOptions({
        userVerification: "required",
        rpID: domainName
    })

    await passkeyRepo.set(["challenges", domainName, options.challenge], true, {
        expireIn: CHALLENGE_TTL
    })

    return c.json(options)
})

app.post("/api/v2/:projectId/login/verify", async (c) => {
    const projectId = c.req.param("projectId")
    const passkeyRepo = new PasskeyRepository()

    const domainName = await passkeyRepo.getPasskeyDomainByProjectId(projectId)

    const { cred } = await c.req.json<{ cred: AuthenticationResponseJSON }>()

    const clientData = JSON.parse(atob(cred.response.clientDataJSON))

    const clientDataJSON = atob(cred.response.clientDataJSON)
    console.log({ clientData })
    if (typeof clientDataJSON !== "string") {
        throw new Error("clientDataJSON must be a string")
    }

    const userId = cred.response.userHandle
    if (!userId) return c.json({ error: "Unauthorized" }, { status: 401 })

    const user = await passkeyRepo.get<User>(["users", domainName, userId])
    if (!user) return c.json({ error: "Unauthorized" }, { status: 401 })
    console.log({ user })

    const challenge = await passkeyRepo.get<Challenge>([
        "challenges",
        domainName,
        clientData.challenge
    ])
    if (!challenge) {
        return c.text("Invalid challenge", 400)
    }

    const credential = user.credentials[cred.id]

    // Convert from Base64 to Uint8Array
    const credentialID = base64urlToUint8Array(
        credential.credentialID as string
    )
    const credentialPublicKey = base64urlToUint8Array(
        credential.credentialPublicKey as string
    )

    const verification = await verifyAuthenticationResponse({
        response: cred,
        expectedChallenge: clientData.challenge,
        expectedOrigin: c.req.header("origin")!, //! Allow from any origin
        expectedRPID: domainName,
        authenticator: {
            ...credential,
            credentialID: credentialID,
            credentialPublicKey: credentialPublicKey
        }
    })

    if (verification.verified) {
        const { newCounter } = verification.authenticationInfo

        await passkeyRepo.delete(["challenges", clientData.challenge])

        const newUser = user
        newUser.credentials[cred.id].counter = newCounter

        await passkeyRepo.set(["users", domainName, userId], newUser, {
            overwrite: true
        })

        await setSignedCookie(c, "token", await generateJWT(userId), SECRET, {
            httpOnly: true,
            secure: true,
            sameSite: "None",
            path: "/",
            maxAge: 600_000
        })

        return c.json({
            verification,
            pubkey: user.credentials[cred.id].pubKey
        })
    }
    return c.text("Unauthorized", 401)
})

app.post("/api/v2/:projectId/sign-initiate", async (c) => {
    const projectId = c.req.param("projectId")
    const passkeyRepo = new PasskeyRepository()

    const domainName = await passkeyRepo.getPasskeyDomainByProjectId(projectId)

    const { data } = await c.req.json<{ data: string }>()
    const token = await getSignedCookie(c, SECRET, "token")
    if (!token) return new Response("Unauthorized", { status: 401 })

    const result = await verifyJWT(token)
    const user = await passkeyRepo.get<User>([
        "users",
        domainName,
        result.payload.userId as string
    ])
    if (!user) return new Response("Unauthorized", { status: 401 })

    console.log("user", user)

    // Utility function to convert hex string to Uint8Array
    function hexStringToUint8Array(hexString: string): Uint8Array {
        hexString = hexString.startsWith("0x") ? hexString.slice(2) : hexString
        const byteArray = new Uint8Array(hexString.length / 2)
        for (let i = 0; i < hexString.length; i += 2) {
            byteArray[i / 2] = parseInt(hexString.substring(i, i + 2), 16)
        }
        return byteArray
    }

    // Convert data (hex string) to Uint8Array
    const dataUint8Array = hexStringToUint8Array(data)

    const credentialsArray = Object.values(user.credentials)

    const transformedCredentials = credentialsArray.map((cred) => ({
        ...cred,
        credentialID: fromBase64ToUint8Array(cred.credentialID),
        credentialPublicKey: fromBase64ToUint8Array(cred.credentialPublicKey)
    }))

    const options = await generateAuthenticationOptions({
        challenge: dataUint8Array,
        userVerification: "required",
        rpID: domainName,
        allowCredentials: transformedCredentials.map((cred) => ({
            id: cred.credentialID,
            type: "public-key"
        }))
    })

    await passkeyRepo.set(["challenges", domainName, options.challenge], data, {
        expireIn: CHALLENGE_TTL,
        overwrite: true
    })

    console.log("options", options)

    return c.json(options)
})

app.post("/api/v2/:projectId/sign-verify", async (c) => {
    const projectId = c.req.param("projectId")
    const passkeyRepo = new PasskeyRepository()

    const domainName = await passkeyRepo.getPasskeyDomainByProjectId(projectId)

    const { cred } = await c.req.json<{ cred: AuthenticationResponseJSON }>()
    const clientData = JSON.parse(atob(cred.response.clientDataJSON))
    const challenge = await passkeyRepo.get<string>([
        "challenges",
        domainName,
        clientData.challenge
    ])
    if (!challenge) return c.text("Invalid challenge", 400)

    const user = await passkeyRepo.get<User>([
        "users",
        domainName,
        cred.response.userHandle as string
    ])
    if (!user) return c.text("Unauthorized", 401)

    console.log("cred", cred)

    const credential = user.credentials[cred.id]

    // Convert from Base64 to Uint8Array
    const credentialID = base64urlToUint8Array(
        credential.credentialID as string
    )
    const credentialPublicKey = base64urlToUint8Array(
        credential.credentialPublicKey as string
    )

    const verification = await verifyAuthenticationResponse({
        response: cred,
        expectedChallenge: clientData.challenge,
        expectedOrigin: c.req.header("origin")!,
        expectedRPID: domainName,
        authenticator: {
            ...credential,
            credentialID: credentialID,
            credentialPublicKey: credentialPublicKey
        }
    })

    if (verification.verified) {
        await passkeyRepo.delete(["challenges", clientData.challenge])
        const signature = cred.response.signature
        const publicKey = user.credentials[cred.id].credentialPublicKey
        const publicKeyBase64 = btoa(
            String.fromCharCode(
                ...new Uint8Array(base64urlToUint8Array(publicKey))
            )
        )

        const authenticatorData = cred.response.authenticatorData
        return c.json({
            success: true,
            signedData: challenge,
            signature,
            authenticatorData,
            publicKeyBase64
        })
    } else {
        return c.text("Unauthorized", 401)
    }
})

// app.get("/private", async (c) => {
//     const token = await getSignedCookie(c, SECRET, "token")
//     if (!token) return new Response("Unauthorized", { status: 401 })
//     console.log({ token })

//     const result = await verifyJWT(token)
//     console.log({ result })

//     const user = await kv.get<User>(["users", result.payload.userId as string])
//     if (!user.value) return new Response("Unauthorized", { status: 401 })

//     return c.json({
//         id: result.payload.userId,
//         username: user.value.username || "Anon",
//         data: user.value.data
//     })
// })

// health check
app.get("/health", (c) => c.json({ status: "ok" }))

Bun.serve({
    port: 8080, // defaults to $BUN_PORT, $PORT, $NODE_PORT otherwise 3000
    fetch: app.fetch
})

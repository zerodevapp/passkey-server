import {
    generateAuthenticationOptions,
    generateRegistrationOptions,
    verifyAuthenticationResponse,
    verifyRegistrationResponse
} from "@simplewebauthn/server"
import type {
    AuthenticationResponseJSON,
    RegistrationResponseJSON
} from "@simplewebauthn/typescript-types"
import { jwtVerify, SignJWT } from "jose"
import { Hono } from "hono"
import { serveStatic } from "hono/bun"
import { getSignedCookie, setCookie, setSignedCookie } from "hono/cookie"
import { logger } from "hono/logger"
import { cors } from "hono/cors"
import { v4 as uuidv4 } from "uuid"
import PasskeyRepository from "./src/repository/PasskeyRepository"
import { Challenge } from "./src/types"
import { InMemoryCache } from "./src/cache/inMemoryCache"

// CONSTANTS
const SECRET = new TextEncoder().encode(process.env.JWT_SECRET ?? "development")
const CHALLENGE_TTL = Number(process.env.WEBAUTHN_CHALLENGE_TTL) || 60_000

// UTILS
function generateJWT(userId: string) {
    return new SignJWT({ userId })
        .setProtectedHeader({ alg: "HS256" })
        .sign(SECRET)
}

function verifyJWT(token: string) {
    return jwtVerify(token, SECRET)
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

function uint8ArrayToBase64Url(uint8Array: Uint8Array): string {
    const base64String = Buffer.from(uint8Array).toString("base64")
    const base64UrlString = base64String
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "")
    return base64UrlString
}

function fromBase64ToUint8Array(base64String): Uint8Array {
    return Uint8Array.from(Buffer.from(base64String, "base64"))
}

// RP SERVER

const app = new Hono()

const passkeyRepo = new PasskeyRepository()
const domainNameCache = new InMemoryCache()

app.use("*", logger())

app.use("*", cors({ credentials: true, origin: (origin) => origin || "*" }))

app.get("/index.js", serveStatic({ path: "./index.js" }))

app.get("/", serveStatic({ path: "./index.html" }))

app.post("/api/v2/:projectId/register/options", async (c) => {
    const { username } = await c.req.json<{ username: string }>()

    const projectId = c.req.param("projectId")

    let domainName = await domainNameCache.get(projectId)
    if (!domainName) {
        console.log("cache miss")
        domainName = await passkeyRepo.getPasskeyDomainByProjectId(projectId)
        console.log("got domain name", domainName)
        await domainNameCache.set(projectId, domainName)
    }

    const userID = uuidv4()

    const options = await generateRegistrationOptions({
        rpName: domainName,
        rpID: domainName,
        userID,
        userName: username,
        userDisplayName: username,
        authenticatorSelection: {
            residentKey: "required",
            userVerification: "required"
        }
    })

    passkeyRepo.set(["challenges", domainName, options.challenge], true, {
        expireIn: CHALLENGE_TTL
    })

    await setSignedCookie(c, "userId", userID, SECRET, {
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        path: "/",
        maxAge: CHALLENGE_TTL
    })

    return c.json({ options })
})

app.post("/api/v3/:projectId/register/options", async (c) => {
    const { username } = await c.req.json<{ username: string }>()

    const projectId = c.req.param("projectId")

    let domainName = await domainNameCache.get(projectId)
    if (!domainName) {
        console.log("cache miss")
        domainName = await passkeyRepo.getPasskeyDomainByProjectId(projectId)
        console.log("got domain name", domainName)
        await domainNameCache.set(projectId, domainName)
    }

    const userId = uuidv4()

    const options = await generateRegistrationOptions({
        rpName: domainName,
        rpID: domainName,
        userID: userId,
        userName: username,
        userDisplayName: username,
        authenticatorSelection: {
            residentKey: "required",
            userVerification: "required"
        }
    })

    passkeyRepo.set(["challenges", domainName, options.challenge], true, {
        expireIn: CHALLENGE_TTL
    })

    return c.json({ options, userId })
})

app.post("/api/v2/:projectId/register/verify", async (c) => {
    const { username, cred } = await c.req.json<{
        userId: string
        username: string
        cred: RegistrationResponseJSON
    }>()

    // base64url to Uint8Array
    const pubKey = cred.response.publicKey!

    const userId = await getSignedCookie(c, SECRET, "userId")
    if (!userId) return new Response("UserId not found", { status: 401 })

    const projectId = c.req.param("projectId")

    let domainName = await domainNameCache.get(projectId)
    if (!domainName) {
        domainName = await passkeyRepo.getPasskeyDomainByProjectId(projectId)
        await domainNameCache.set(projectId, domainName)
    }

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

        await passkeyRepo.createUser({
            userId,
            username,
            projectId: c.req.param("projectId")
        })

        await passkeyRepo.createCredential({
            userId,
            credentialId: uint8ArrayToBase64Url(credentialID),
            publicKey: pubKey,
            counter,
            credentialPublicKey: uint8ArrayToBase64Url(credentialPublicKey)
        })

        await setSignedCookie(c, "token", await generateJWT(userId), SECRET, {
            httpOnly: true,
            secure: true,
            sameSite: "Lax",
            path: "/",
            maxAge: 600_000
        })

        return c.json(verification)
    }

    return c.text("Unauthorized", 401)
})

app.post("/api/v3/:projectId/register/verify", async (c) => {
    const { userId, username, cred } = await c.req.json<{
        userId: string
        username: string
        cred: RegistrationResponseJSON
    }>()

    // base64url to Uint8Array
    const pubKey = cred.response.publicKey!

    if (!userId) return new Response("UserId Not Found", { status: 401 })

    const projectId = c.req.param("projectId")

    let domainName = await domainNameCache.get(projectId)
    if (!domainName) {
        domainName = await passkeyRepo.getPasskeyDomainByProjectId(projectId)
        await domainNameCache.set(projectId, domainName)
    }

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

        await passkeyRepo.createUser({
            userId,
            username,
            projectId: c.req.param("projectId")
        })

        await passkeyRepo.createCredential({
            userId,
            credentialId: uint8ArrayToBase64Url(credentialID),
            publicKey: pubKey,
            counter,
            credentialPublicKey: uint8ArrayToBase64Url(credentialPublicKey)
        })

        return c.json(verification)
    }

    return c.text("Unauthorized", 401)
})

app.get("/v1/health", (c) => c.json({ status: "ok" }))

app.post("/api/v2/:projectId/login/options", async (c) => {
    const projectId = c.req.param("projectId")

    let domainName = await domainNameCache.get(projectId)
    if (!domainName) {
        domainName = await passkeyRepo.getPasskeyDomainByProjectId(projectId)
        await domainNameCache.set(projectId, domainName)
    }

    const options = await generateAuthenticationOptions({
        userVerification: "required",
        rpID: domainName
    })

    await passkeyRepo.set(["challenges", domainName, options.challenge], true, {
        expireIn: CHALLENGE_TTL
    })

    return c.json(options)
})

app.post("/api/v3/:projectId/login/options", async (c) => {
    const projectId = c.req.param("projectId")

    let domainName = await domainNameCache.get(projectId)
    if (!domainName) {
        domainName = await passkeyRepo.getPasskeyDomainByProjectId(projectId)
        await domainNameCache.set(projectId, domainName)
    }

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

    let domainName = await domainNameCache.get(projectId)
    if (!domainName) {
        domainName = await passkeyRepo.getPasskeyDomainByProjectId(projectId)
        await domainNameCache.set(projectId, domainName)
    }

    const { cred } = await c.req.json<{ cred: AuthenticationResponseJSON }>()

    const clientData = JSON.parse(atob(cred.response.clientDataJSON))

    const clientDataJSON = atob(cred.response.clientDataJSON)
    if (typeof clientDataJSON !== "string") {
        throw new Error("clientDataJSON must be a string")
    }

    const userId = cred.response.userHandle
    if (!userId) return c.json({ error: "UserId Not Found" }, { status: 401 })

    const user = await passkeyRepo.getPasskeyUserById(userId)
    const credential = await passkeyRepo.getCredentialById(cred.id)
    if (!user) return c.json({ error: "Unauthorized" }, { status: 401 })
    if (!credential) return c.json({ error: "Unauthorized" }, { status: 401 })

    const challenge = await passkeyRepo.get<Challenge>([
        "challenges",
        domainName,
        clientData.challenge
    ])
    if (!challenge) {
        return c.text("Invalid challenge", 400)
    }

    // Convert from Base64url to Uint8Array
    const credentialID = base64urlToUint8Array(
        credential.credentialId as string
    )
    const credentialPublicKey = base64urlToUint8Array(
        credential.publicKey as string
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

        await passkeyRepo.updateCredentialCounter(cred.id, newCounter)

        await setSignedCookie(c, "token", await generateJWT(userId), SECRET, {
            httpOnly: true,
            secure: true,
            sameSite: "Lax",
            path: "/",
            maxAge: 600_000
        })

        return c.json({
            verification,
            pubkey: credential.pubKey
        })
    }
    return c.text("Unauthorized", 401)
})

app.post("/api/v3/:projectId/login/verify", async (c) => {
    const projectId = c.req.param("projectId")

    let domainName = await domainNameCache.get(projectId)
    if (!domainName) {
        domainName = await passkeyRepo.getPasskeyDomainByProjectId(projectId)
        await domainNameCache.set(projectId, domainName)
    }

    const { cred } = await c.req.json<{ cred: AuthenticationResponseJSON }>()

    const clientData = JSON.parse(atob(cred.response.clientDataJSON))

    const clientDataJSON = atob(cred.response.clientDataJSON)
    if (typeof clientDataJSON !== "string") {
        throw new Error("clientDataJSON must be a string")
    }

    const userId = cred.response.userHandle
    if (!userId) return c.json({ error: "UserId Not Found" }, { status: 401 })

    const user = await passkeyRepo.getPasskeyUserById(userId)
    const credential = await passkeyRepo.getCredentialById(cred.id)
    if (!user) return c.json({ error: "Unauthorized" }, { status: 401 })
    if (!credential) return c.json({ error: "Unauthorized" }, { status: 401 })

    const challenge = await passkeyRepo.get<Challenge>([
        "challenges",
        domainName,
        clientData.challenge
    ])
    if (!challenge) {
        return c.text("Invalid challenge", 400)
    }

    // Convert from Base64url to Uint8Array
    const credentialID = base64urlToUint8Array(
        credential.credentialId as string
    )
    const credentialPublicKey = base64urlToUint8Array(
        credential.publicKey as string
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

        await passkeyRepo.updateCredentialCounter(cred.id, newCounter)

        return c.json({
            verification,
            pubkey: credential.pubKey,
            userId
        })
    }
    return c.text("Unauthorized", 401)
})

app.post("/api/v2/:projectId/sign-initiate", async (c) => {
    const projectId = c.req.param("projectId")

    let domainName = await domainNameCache.get(projectId)
    if (!domainName) {
        domainName = await passkeyRepo.getPasskeyDomainByProjectId(projectId)
        await domainNameCache.set(projectId, domainName)
    }

    const { data } = await c.req.json<{ data: string }>()
    const token = await getSignedCookie(c, SECRET, "token")
    if (!token) return new Response("Unauthorized", { status: 401 })

    const result = await verifyJWT(token)
    const user = await passkeyRepo.getPasskeyUserById(
        result.payload.userId as string
    )
    if (!user) return new Response("Unauthorized", { status: 401 })
    const credentials = await passkeyRepo.getCredentialsByUserId(
        result.payload.userId as string
    )
    if (!credentials) return new Response("Unauthorized", { status: 401 })

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

    const transformedCredentials = credentials.map((cred) => ({
        ...cred,
        credentialID: fromBase64ToUint8Array(cred.credentialId),
        credentialPublicKey: fromBase64ToUint8Array(cred.publicKey)
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

    return c.json(options)
})

app.post("/api/v3/:projectId/sign-initiate", async (c) => {
    const projectId = c.req.param("projectId")

    let domainName = await domainNameCache.get(projectId)
    if (!domainName) {
        domainName = await passkeyRepo.getPasskeyDomainByProjectId(projectId)
        await domainNameCache.set(projectId, domainName)
    }

    const { data, userId } = await c.req.json<{
        data: string
        userId: string
    }>()

    const user = await passkeyRepo.getPasskeyUserById(userId)
    if (!user) return new Response("User Not Found", { status: 401 })
    const credentials = await passkeyRepo.getCredentialsByUserId(userId)
    if (!credentials)
        return new Response("Credentials Not Found", { status: 401 })

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

    const transformedCredentials = credentials.map((cred) => ({
        ...cred,
        credentialID: fromBase64ToUint8Array(cred.credentialId),
        credentialPublicKey: fromBase64ToUint8Array(cred.publicKey)
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

    return c.json(options)
})

app.post("/api/v2/:projectId/sign-verify", async (c) => {
    const projectId = c.req.param("projectId")

    let domainName = await domainNameCache.get(projectId)
    if (!domainName) {
        domainName = await passkeyRepo.getPasskeyDomainByProjectId(projectId)
        await domainNameCache.set(projectId, domainName)
    }

    const { cred } = await c.req.json<{ cred: AuthenticationResponseJSON }>()
    const clientData = JSON.parse(atob(cred.response.clientDataJSON))
    const challenge = await passkeyRepo.get<string>([
        "challenges",
        domainName,
        clientData.challenge
    ])
    if (!challenge) return c.text("Invalid challenge", 400)

    const user = await passkeyRepo.getPasskeyUserById(
        cred.response.userHandle as string
    )
    if (!user) return c.text("User Not Found", 401)
    const credential = await passkeyRepo.getCredentialById(cred.id)
    if (!credential) return c.text("Credentials Not Found", 401)

    // Convert from Base64url to Uint8Array
    const credentialID = base64urlToUint8Array(
        credential.credentialId as string
    )
    const credentialPublicKey = base64urlToUint8Array(
        credential?.publicKey as string
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
        const publicKey = credential.publicKey
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

app.post("/api/v3/:projectId/sign-verify", async (c) => {
    const projectId = c.req.param("projectId")

    let domainName = await domainNameCache.get(projectId)
    if (!domainName) {
        domainName = await passkeyRepo.getPasskeyDomainByProjectId(projectId)
        await domainNameCache.set(projectId, domainName)
    }

    const { cred } = await c.req.json<{ cred: AuthenticationResponseJSON }>()
    const clientData = JSON.parse(atob(cred.response.clientDataJSON))
    const challenge = await passkeyRepo.get<string>([
        "challenges",
        domainName,
        clientData.challenge
    ])
    if (!challenge) return c.text("Invalid challenge", 400)

    const user = await passkeyRepo.getPasskeyUserById(
        cred.response.userHandle as string
    )
    if (!user) return c.text("User Not Found", 401)
    const credential = await passkeyRepo.getCredentialById(cred.id)
    if (!credential) return c.text("Credentials Not Found", 401)

    // Convert from Base64url to Uint8Array
    const credentialID = base64urlToUint8Array(
        credential.credentialId as string
    )
    const credentialPublicKey = base64urlToUint8Array(
        credential?.publicKey as string
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
        const publicKey = credential.publicKey
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

// health check
app.get("/health", (c) => c.json({ status: "ok" }))

Bun.serve({
    port: 8080, // defaults to $BUN_PORT, $PORT, $NODE_PORT otherwise 3000
    fetch: app.fetch
})

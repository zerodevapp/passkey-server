import {
    generateAuthenticationOptions,
    generateRegistrationOptions,
    verifyAuthenticationResponse,
    verifyRegistrationResponse,
} from "@simplewebauthn/server"
import type {
    AuthenticationResponseJSON,
    Base64URLString,
    RegistrationResponseJSON,
} from "@simplewebauthn/typescript-types"
import { jwtVerify, SignJWT } from "jose"
import { Hono } from "hono"
import { getSignedCookie, setSignedCookie } from "hono/cookie"
import { serveStatic } from "hono/bun"
import { logger } from "hono/logger"
import { cors } from "hono/cors"
import PasskeyRepository from "./src/repository/PasskeyRepository"

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
            authenticatorAttachment: "platform",
        },
    })

    passkeyRepo.set(["challenges", domainName, options.challenge], true, {
        expireIn: CHALLENGE_TTL,
    })

    await setSignedCookie(c, "userId", userID, SECRET, {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        path: "/",
        maxAge: CHALLENGE_TTL,
    })

    return c.json(options)
})

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
        clientData.challenge,
    ])

    if (!challenge) {
        return c.text("Invalid challenge", 400)
    }

    const verification = await verifyRegistrationResponse({
        response: cred,
        expectedChallenge: clientData.challenge,
        expectedRPID: domainName,
        expectedOrigin: c.req.header("origin")!, //! Allow from any origin
        requireUserVerification: true,
    })

    if (verification.verified) {
        const { credentialID, credentialPublicKey, counter } =
            verification.registrationInfo!

        await passkeyRepo.delete(["challenges", clientData.challenge])

        await passkeyRepo.createUser({
            userId,
            username,
            data: "Private user data for " + (username || "Anon")
        })

        await passkeyRepo.createCredential({
            userId,
            credentialId: uint8ArrayToBase64(credentialID),
            publicKey: pubKey,
            counter,
            credentialPublicKey: uint8ArrayToBase64(credentialPublicKey),
        })

        // await passkeyRepo.set(["users", domainName, userId], {
        //     username: username,
        //     data: "Private user data for " + (username || "Anon"),
        //     credentials: {
        //         [cred.id]: {
        //             pubKey,
        //             credentialID: uint8ArrayToBase64(credentialID),
        //             credentialPublicKey:
        //                 uint8ArrayToBase64(credentialPublicKey),
        //             counter,
        //         },
        //     },
        // } as User)

        await setSignedCookie(c, "token", await generateJWT(userId), SECRET, {
            httpOnly: true,
            secure: true,
            sameSite: "None",
            path: "/",
            maxAge: 600_000,
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
        rpID: domainName,
    })

    await passkeyRepo.set(["challenges", domainName, options.challenge], true, {
        expireIn: CHALLENGE_TTL,
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
    if (typeof clientDataJSON !== "string") {
        throw new Error("clientDataJSON must be a string")
    }

    const userId = cred.response.userHandle
    if (!userId) return c.json({ error: "Unauthorized" }, { status: 401 })

    const user = await passkeyRepo.get<User>(["users", domainName, userId])
    if (!user) return c.json({ error: "Unauthorized" }, { status: 401 })

    const challenge = await passkeyRepo.get<Challenge>([
        "challenges",
        domainName,
        clientData.challenge,
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
            credentialPublicKey: credentialPublicKey,
        },
    })

    if (verification.verified) {
        const { newCounter } = verification.authenticationInfo

        await passkeyRepo.delete(["challenges", clientData.challenge])

        const newUser = user
        newUser.credentials[cred.id].counter = newCounter

        await passkeyRepo.set(["users", domainName, userId], newUser, {
            overwrite: true,
        })

        await setSignedCookie(c, "token", await generateJWT(userId), SECRET, {
            httpOnly: true,
            secure: true,
            sameSite: "None",
            path: "/",
            maxAge: 600_000,
        })

        return c.json({
            verification,
            pubkey: user.credentials[cred.id].pubKey,
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
        result.payload.userId as string,
    ])
    if (!user) return new Response("Unauthorized", { status: 401 })

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
        credentialPublicKey: fromBase64ToUint8Array(cred.credentialPublicKey),
    }))

    const options = await generateAuthenticationOptions({
        challenge: dataUint8Array,
        userVerification: "required",
        rpID: domainName,
        allowCredentials: transformedCredentials.map((cred) => ({
            id: cred.credentialID,
            type: "public-key",
        })),
    })

    await passkeyRepo.set(["challenges", domainName, options.challenge], data, {
        expireIn: CHALLENGE_TTL,
        overwrite: true,
    })

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
        clientData.challenge,
    ])
    if (!challenge) return c.text("Invalid challenge", 400)

    const user = await passkeyRepo.get<User>([
        "users",
        domainName,
        cred.response.userHandle as string,
    ])
    if (!user) return c.text("Unauthorized", 401)

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
            credentialPublicKey: credentialPublicKey,
        },
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
            publicKeyBase64,
        })
    } else {
        return c.text("Unauthorized", 401)
    }
})

// health check
app.get("/health", (c) => c.json({ status: "ok" }))

Bun.serve({
    port: 8080, // defaults to $BUN_PORT, $PORT, $NODE_PORT otherwise 3000
    fetch: app.fetch,
})

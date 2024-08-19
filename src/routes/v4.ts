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
import { Context, Hono } from "hono"
import { v4 as uuidv4 } from "uuid"
import PasskeyRepository from "../repository/PasskeyRepository"
import { base64urlToUint8Array, uint8ArrayToBase64Url } from "../utils"
import { Challenge } from "../types"

export function registerV4Routes(
    app: Hono,
    passkeyRepo: PasskeyRepository,
    CHALLENGE_TTL: number
) {
    const getDomainName = (c: Context) => {
        const origin = c.req.header("origin")
        if (!origin) {
            return null
        }
        return new URL(origin).hostname
    }

    app.post("/api/v4/register/options", async (c) => {
        const { username } = await c.req.json<{ username: string }>()
        const domainName = getDomainName(c)
        if (!domainName) return c.text("Origin header is missing", 400)

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

    app.post("/api/v4/register/verify", async (c) => {
        const { userId, username, cred } = await c.req.json<{
            userId: string
            username: string
            cred: RegistrationResponseJSON
        }>()

        // base64url to Uint8Array
        const pubKey = cred.response.publicKey!

        if (!userId) return new Response("UserId Not Found", { status: 401 })

        const domainName = getDomainName(c)
        if (!domainName) return c.text("Origin header is missing", 400)

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
                projectId: null
            })

            await passkeyRepo.createCredential({
                credentialId: uint8ArrayToBase64Url(credentialID),
                userId,
                credentialPublicKey: uint8ArrayToBase64Url(credentialPublicKey),
                counter,
                publicKey: pubKey
            })

            return c.json(verification)
        }

        return c.text("Unauthorized", 401)
    })

    app.post("/api/v4/login/options", async (c) => {
        const domainName = getDomainName(c)
        if (!domainName) return c.text("Origin header is missing", 400)

        const options = await generateAuthenticationOptions({
            userVerification: "required",
            rpID: domainName
        })

        await passkeyRepo.set(
            ["challenges", domainName, options.challenge],
            true,
            {
                expireIn: CHALLENGE_TTL
            }
        )

        return c.json(options)
    })

    app.post("/api/v4/login/verify", async (c) => {
        try {
            const domainName = getDomainName(c)
            if (!domainName) return c.text("Origin header is missing", 400)

            const { cred } = await c.req.json<{
                cred: AuthenticationResponseJSON
            }>()

            const clientData = JSON.parse(atob(cred.response.clientDataJSON))

            const clientDataJSON = atob(cred.response.clientDataJSON)
            if (typeof clientDataJSON !== "string") {
                throw new Error("clientDataJSON must be a string")
            }

            const userId = cred.response.userHandle
            if (!userId)
                return c.json({ error: "UserId Not Found" }, { status: 401 })

            const credential = await passkeyRepo.getCredentialById(cred.id)
            if (!credential)
                return c.json({ error: "Unauthorized" }, { status: 401 })

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
        } catch (error) {
            console.error(error)
            return c.text("Internal Server Error", 500)
        }
    })
}

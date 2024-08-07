import { redisClient } from "../db"
import db, { sql } from "../db"
import { passkeyDomainObject } from "../objects/passkeyDomainObject"
import { credentialObject } from "../objects/credentialObject"
import { userObject } from "../objects/userObject"

class PasskeyRepository {
    static passkeyRepository: PasskeyRepository

    constructor() {
        if (PasskeyRepository.passkeyRepository) {
            return PasskeyRepository.passkeyRepository
        }
        PasskeyRepository.passkeyRepository = this
    }

    async set(
        key: (string | number)[],
        value: any,
        options?: { expireIn?: number; overwrite?: boolean }
    ) {
        const serializedKey = JSON.stringify(key)
        const valueToStore = JSON.stringify(value)
        const { expireIn, overwrite } = options || {}

        const exists = await redisClient.exists(serializedKey)
        if (exists && !overwrite) {
            throw new Error("Key already exists")
        }

        if (expireIn !== undefined) {
            await redisClient.setex(serializedKey, expireIn, valueToStore)
        } else {
            await redisClient.set(serializedKey, valueToStore)
        }
    }

    async get<T>(key: (string | number)[]): Promise<T | null> {
        const value = await redisClient.get(JSON.stringify(key))
        return value ? (JSON.parse(value) as T) : null
    }

    async delete(key: (string | number)[]) {
        await redisClient.del(JSON.stringify(key))
    }

    async getPasskeyDomainByProjectId(projectId: string): Promise<string> {
        const result = await (
            await db
        ).maybeOne(sql.type(passkeyDomainObject)`
      SELECT passkey_domain
      FROM project_passkey
      WHERE project_id = ${projectId}
    `)
        console.log({ result })
        if (!result) {
            // if no passkey domain is found, return localhost
            return "localhost"
        }
        return getDomainFromUrl(result.passkeyDomain)
    }

    async createUser(user: {
        userId: string
        username: string
        projectId: string | null
    }) {
        const isValidUUID =
            /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(
                user.userId
            )
        if (!isValidUUID) {
            throw new Error("Invalid UUID format for userId")
        }

        try {
            await (
                await db
            ).query(sql.typeAlias("void")`
                INSERT INTO passkey_users (passkey_user_id, username, project_id)
                VALUES (${user.userId}, ${user.username}, ${user.projectId})
            `)
        } catch (error) {
            console.error("Error creating user:", error)
            throw error
        }
    }

    async getPasskeyUserById(userId: string) {
        try {
            const user = await (
                await db
            ).maybeOne(sql.type(userObject)`
                SELECT * FROM passkey_users WHERE passkey_user_id = ${userId}
            `)
            return user
        } catch (error) {
            console.error("Error retrieving user:", error)
            return null
        }
    }

    async createCredential(credential: {
        credentialId: string
        userId: string
        credentialPublicKey: string
        counter: number
        publicKey: string
    }) {
        const {
            credentialId,
            userId,
            credentialPublicKey,
            counter,
            publicKey
        } = credential
        try {
            await (
                await db
            ).query(sql.typeAlias("void")`
                INSERT INTO passkey_credentials (credential_id, passkey_user_id, public_key, counter, pub_key)
                VALUES (${credentialId}, ${userId}, ${credentialPublicKey}, ${counter}, ${publicKey})
            `)
        } catch (error) {
            console.error("Error creating credential:", error)
            throw error
        }
    }

    async getCredentialById(credentialId: string) {
        try {
            const credential = await (
                await db
            ).maybeOne(sql.type(credentialObject)`
                SELECT * FROM passkey_credentials WHERE credential_id = ${credentialId}
            `)
            return credential
        } catch (error) {
            console.error("Error retrieving credential:", error)
            return null
        }
    }

    async getCredentialsByUserId(userId: string) {
        try {
            const credentials = await (
                await db
            ).any(sql.type(credentialObject)`
                SELECT * FROM passkey_credentials WHERE passkey_user_id = ${userId}
            `)
            return credentials
        } catch (error) {
            console.error("Error retrieving credentials:", error)
            return []
        }
    }

    async updateCredentialCounter(credentialId: string, newCounter: number) {
        try {
            await (
                await db
            ).query(sql.typeAlias("void")`
                UPDATE passkey_credentials SET counter = ${newCounter} WHERE credential_id = ${credentialId}
            `)
        } catch (error) {
            console.error("Error updating credential counter:", error)
            throw error
        }
    }
}

export default PasskeyRepository

function getDomainFromUrl(url: string): string {
    try {
        const hostname = new URL(url).hostname
        // Directly return the hostname for RP ID purposes
        return hostname
    } catch (error) {
        console.error("Invalid URL:", error)
        return ""
    }
}

import { redisClient } from "../db"
import db, { sql } from "../db"
import { passkeyDomainObject } from "../objects/passkeyDomainObject"

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

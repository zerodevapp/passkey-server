// A simple in-memory cache utility
export class InMemoryCache {
    private cache = new Map<string, any>()
    private ttl = 60 * 1000 // Default TTL of 1 minute

    constructor(ttl?: number) {
        if (ttl) this.ttl = ttl
    }

    set(key: string, value: any) {
        const item = {
            value,
            expiry: Date.now() + this.ttl
        }
        this.cache.set(key, item)
    }

    get(key: string) {
        const item = this.cache.get(key)
        if (!item) return null
        if (Date.now() > item.expiry) {
            this.cache.delete(key)
            return null
        }
        return item.value
    }
}

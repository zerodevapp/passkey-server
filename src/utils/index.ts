export function base64urlToUint8Array(base64url: string): Uint8Array {
    const padding = "=".repeat((4 - (base64url.length % 4)) % 4)
    const base64 = (base64url + padding).replace(/\-/g, "+").replace(/_/g, "/")

    const rawData = atob(base64)
    const outputArray = new Uint8Array(rawData.length)

    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i)
    }

    return outputArray
}

export function uint8ArrayToBase64Url(uint8Array: Uint8Array): string {
    const base64String = Buffer.from(uint8Array).toString("base64")
    const base64UrlString = base64String
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "")
    return base64UrlString
}

export function fromBase64ToUint8Array(base64String: string): Uint8Array {
    return Uint8Array.from(Buffer.from(base64String, "base64"))
}

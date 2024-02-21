import { z } from "zod"
import { extendApi } from "@anatine/zod-openapi"

export const passkeyDomainObject = extendApi(
    z.object({
        passkeyDomain: extendApi(z.string().url(), {
            description: "URL for the passkey domain",
            example: "http://zerodev.app"
        })
    })
)

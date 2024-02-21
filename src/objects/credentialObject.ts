import { z } from "zod"
import { extendApi } from "@anatine/zod-openapi"

export const credentialObject = extendApi(
    z.object({
        credentialId: z.string(),
        passkeyUserId: z.string(),
        publicKey: z.string(),
        counter: z.number(),
        pubKey: z.string()
    })
)

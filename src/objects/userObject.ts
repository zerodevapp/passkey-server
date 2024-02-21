import { z } from "zod"
import { extendApi } from "@anatine/zod-openapi"

export const userObject = extendApi(
    z.object({
        passkeyUserId: z.string(),
        username: z.string(),
        projectId: z.string()
    })
)

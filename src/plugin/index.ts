import type { KernelValidator } from "@zerodev/sdk/types"
import { createPasskeyValidator } from "./toWebAuthnValidator"

export { createPasskeyValidator, type KernelValidator }

export const WEBAUTHN_VALIDATOR_ADDRESS =
    "0x0Bc1C061878deAb416B2249D6009D07A72E367C3"

// old one: 0x940c1F08923E22B33d8dFeDC25e5C1Fc369Ee61a
// new one with bypass: 0x4f4e99f0aff4c46e2d7aa207cba7b3a8a5d52377
// new one with deffered: 0x640E8971889fAC073e6F5DC948C4ff25872d3543

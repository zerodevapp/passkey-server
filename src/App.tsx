import { useState } from "react"
import { Chain, Transport, zeroAddress } from "viem"
import "./App.css"
import {
    getEntryPoint,
    getKernelAccountClient,
    getZeroDevPaymasterClient,
    loginToWebAuthnKernelAccount,
    registerWebAuthnKernelAccount
} from "./utils"
import { KernelAccountClient, KernelSmartAccount } from "@zerodev/sdk"

const projectId = "06cf2ab0-9a15-4049-b826-c6a61b62ef17"
// const URL = `http://localhost:4003/projects/${projectId}/passkey`
// const URL = 'http://localhost:8080'
const url = `https://passkeys.zerodev.app/api/v2/${projectId}`

let account
let kernelClient: KernelAccountClient<Transport, Chain, KernelSmartAccount>

function App() {
    const [status, setStatus] = useState<string>("")
    const [name, setName] = useState<string>("")

    const handleRegister = async () => {
        account = await registerWebAuthnKernelAccount(
            name,
            `${url}/register/options`,
            `${url}/register/verify`,
            `${url}/sign-initiate`,
            `${url}/sign-verify`
        )
        kernelClient = await getKernelAccountClient({
            account,
            sponsorUserOperation: async ({ userOperation }) => {
                const zerodevPaymaster = getZeroDevPaymasterClient()
                const entryPoint = getEntryPoint()
                return zerodevPaymaster.sponsorUserOperation({
                    userOperation,
                    entryPoint
                })
            }
        })

        console.log("account", account)
        setStatus(`Registered: ${JSON.stringify(account)}`)
    }

    const handleLogin = async () => {
        account = await loginToWebAuthnKernelAccount(
            `${url}/login/options`,
            `${url}/login/verify`,
            `${url}/sign-initiate`,
            `${url}/sign-verify`
        )

        kernelClient = await getKernelAccountClient({
            account,
            sponsorUserOperation: async ({ userOperation }) => {
                const zerodevPaymaster = getZeroDevPaymasterClient()
                const entryPoint = getEntryPoint()
                return zerodevPaymaster.sponsorUserOperation({
                    userOperation,
                    entryPoint
                })
            }
        })

        console.log("account", account)
        setStatus(`Sign in: ${JSON.stringify(account)}`)
    }

    const handleSendUserOp = async () => {
        const response = await kernelClient.sendUserOperation({
            userOperation: {
                callData: await kernelClient.account.encodeCallData({
                    to: zeroAddress,
                    value: 0n,
                    data: "0x"
                })
                // maxPriorityFeePerGas: 2575000000n,
                // maxFeePerGas: 2575000000n,
                // verificationGasLimit: 700000n
            }
        })
        setStatus(`Sent UserOp: ${JSON.stringify(response)}`)
    }

    return (
        <>
            <h1>WebAuthn Demo</h1>
            <div className="card">
                <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Enter your name"
                />
                <div>
                    <button onClick={handleRegister}>Register</button>
                    <button onClick={handleLogin}>Login</button>
                    <button onClick={handleSendUserOp}>Send UserOp</button>
                </div>
                <p>Status: {status}</p>
            </div>
        </>
    )
}

export default App

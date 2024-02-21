import {
    KernelAccountClient,
    KernelSmartAccount,
    createKernelAccount,
    createKernelAccountClient,
    createZeroDevPaymasterClient
} from "@zerodev/sdk"
import { BundlerClient, createBundlerClient } from "permissionless"
import {
    type SmartAccount,
    signerToSimpleSmartAccount
} from "permissionless/accounts"
import { SponsorUserOperationMiddleware } from "permissionless/actions/smartAccount"
import {
    http,
    AbiItem,
    Address,
    Hex,
    type Log,
    type PublicClient,
    Transport,
    type WalletClient,
    createPublicClient,
    createWalletClient,
    decodeEventLog,
    encodeFunctionData
} from "viem"
import { type Account, privateKeyToAccount } from "viem/accounts"
import { type Chain, goerli } from "viem/chains"
import * as allChains from "viem/chains"
import { EntryPointAbi } from "./abis/EntryPoint.js"
import { createPasskeyValidator } from "./plugin/index.js"
import { getPasskeyValidator } from "./plugin/toWebAuthnValidator.js"

export const Test_ERC20Address = "0x3870419Ba2BBf0127060bCB37f69A1b1C090992B"
export const getFactoryAddress = (): Address => {
    const factoryAddress = import.meta.env.FACTORY_ADDRESS
    if (!factoryAddress) {
        throw new Error("FACTORY_ADDRESS environment variable not set")
    }
    return factoryAddress as Address
}

export const getPrivateKeyAccount = (): Account => {
    const privateKey = import.meta.env.VITE_TEST_PRIVATE_KEY
    if (!privateKey) {
        throw new Error("TEST_PRIVATE_KEY environment variable not set")
    }
    return privateKeyToAccount(privateKey as Hex)
}

export const getTestingChain = (): Chain => {
    const testChainId = import.meta.env.VITE_TEST_CHAIN_ID
    const chainId = testChainId ? parseInt(testChainId, 10) : goerli.id
    const chain = Object.values(allChains).find((c) => c.id === chainId)
    if (!chain) {
        throw new Error(`Chain with id ${chainId} not found`)
    }
    return chain
}

export const getSignerToSimpleSmartAccount =
    async (): Promise<SmartAccount> => {
        const privateKey = import.meta.env.VITE_TEST_PRIVATE_KEY as Hex
        if (!privateKey) {
            throw new Error("TEST_PRIVATE_KEY environment variable not set")
        }

        const publicClient = await getPublicClient()
        const signer = privateKeyToAccount(privateKey)

        return signerToSimpleSmartAccount(publicClient, {
            entryPoint: getEntryPoint(),
            factoryAddress: getFactoryAddress(),
            signer: { ...signer, source: "local" as "local" | "external" }
        })
    }

const DEFAULT_PROVIDER = "ALCHEMY"

const getBundlerRpc = (): string => {
    const zeroDevProjectId = import.meta.env.VITE_ZERODEV_PROJECT_ID
    const zeroDevBundlerRpcHost = import.meta.env.VITE_ZERODEV_BUNDLER_RPC_HOST
    if (!zeroDevProjectId || !zeroDevBundlerRpcHost) {
        throw new Error(
            "ZERODEV_PROJECT_ID and ZERODEV_BUNDLER_RPC_HOST environment variables must be set"
        )
    }

    return `${zeroDevBundlerRpcHost}/${zeroDevProjectId}?bundlerProvider=${DEFAULT_PROVIDER}`
}

const getPaymasterRpc = (): string => {
    const zeroDevProjectId = import.meta.env.VITE_ZERODEV_PROJECT_ID
    const zeroDevPaymasterRpcHost = import.meta.env
        .VITE_ZERODEV_PAYMASTER_RPC_HOST
    if (!zeroDevProjectId || !zeroDevPaymasterRpcHost) {
        throw new Error(
            "ZERODEV_PROJECT_ID and ZERODEV_PAYMASTER_RPC_HOST environment variables must be set"
        )
    }

    return `${zeroDevPaymasterRpcHost}/${zeroDevProjectId}?paymasterProvider=${DEFAULT_PROVIDER}`
}

export const getKernelAccountClient = async ({
    account,
    sponsorUserOperation
}: SponsorUserOperationMiddleware & {
    account?: SmartAccount
} = {}) => {
    const chain = getTestingChain()
    const resolvedAccount = account ?? (await getSignerToSimpleSmartAccount())

    return createKernelAccountClient({
        account: resolvedAccount,
        chain,
        transport: http(getBundlerRpc()),
        sponsorUserOperation
    }) as KernelAccountClient<Transport, Chain, KernelSmartAccount>
}

export const getEoaWalletClient = (): WalletClient => {
    const rpcUrl = import.meta.env.VITE_RPC_URL
    if (!rpcUrl) {
        throw new Error("RPC_URL environment variable not set")
    }

    return createWalletClient({
        account: getPrivateKeyAccount(),
        chain: getTestingChain(),
        transport: http(rpcUrl)
    })
}

export const registerWebAuthnKernelAccount = async (
    passkeyName: string,
    registerOptionUrl: string,
    registerVerifyUrl: string,
    signInitiateUrl: string,
    signVerifyUrl: string
): Promise<SmartAccount> => {
    const publicClient = await getPublicClient()
    const webAuthnValidatorPlugin = await createPasskeyValidator(publicClient, {
        passkeyName,
        registerOptionUrl,
        registerVerifyUrl,
        signInitiateUrl,
        signVerifyUrl,
        entryPoint: getEntryPoint()
    })

    return createKernelAccount(publicClient, {
        entryPoint: getEntryPoint(),
        plugins: {
            sudo: webAuthnValidatorPlugin
        }
    })
}

export const loginToWebAuthnKernelAccount = async (
    loginOptionUrl: string,
    loginVerifyUrl: string,
    signInitiateUrl: string,
    signVerifyUrl: string
): Promise<SmartAccount> => {
    const publicClient = await getPublicClient()
    const webAuthnValidatorPlugin = await getPasskeyValidator(publicClient, {
        loginOptionUrl,
        loginVerifyUrl,
        signInitiateUrl,
        signVerifyUrl,
        entryPoint: getEntryPoint()
    })

    return createKernelAccount(publicClient, {
        entryPoint: getEntryPoint(),
        plugins: {
            sudo: webAuthnValidatorPlugin
        }
    })
}

export const getEntryPoint = (): Address => {
    const entryPointAddress = import.meta.env.VITE_ENTRYPOINT_ADDRESS as Address
    if (!entryPointAddress) {
        throw new Error("ENTRYPOINT_ADDRESS environment variable not set")
    }
    return entryPointAddress
}

export const getPublicClient = async (): Promise<PublicClient> => {
    const rpcUrl = import.meta.env.VITE_RPC_URL
    if (!rpcUrl) {
        throw new Error("RPC_URL environment variable not set")
    }

    const publicClient = createPublicClient({
        transport: http(rpcUrl)
    })

    const chainId = await publicClient.getChainId()
    const testingChain = getTestingChain()

    if (chainId !== testingChain.id) {
        throw new Error(
            `Testing Chain ID (${testingChain.id}) not supported by RPC URL`
        )
    }

    return publicClient
}

export const getKernelBundlerClient = (): BundlerClient => {
    const chain = getTestingChain()

    return createBundlerClient({
        chain,
        transport: http(getBundlerRpc())
    })
}

export const getZeroDevPaymasterClient = () => {
    if (!import.meta.env.VITE_ZERODEV_PAYMASTER_RPC_HOST)
        throw new Error(
            "ZERODEV_PAYMASTER_RPC_HOST environment variable not set"
        )
    if (!import.meta.env.VITE_ZERODEV_PROJECT_ID)
        throw new Error("ZERODEV_PROJECT_ID environment variable not set")

    const chain = getTestingChain()

    return createZeroDevPaymasterClient({
        chain: chain,
        transport: http(getPaymasterRpc())
    })
}

export const getZeroDevERC20PaymasterClient = () => {
    if (!import.meta.env.VITE_ZERODEV_PAYMASTER_RPC_HOST)
        throw new Error(
            "ZERODEV_PAYMASTER_RPC_HOST environment variable not set"
        )
    if (!import.meta.env.VITE_ZERODEV_PROJECT_ID)
        throw new Error("ZERODEV_PROJECT_ID environment variable not set")

    const chain = getTestingChain()

    return createZeroDevPaymasterClient({
        chain: chain,
        transport: http(
            // currently the ERC20 paymaster must be used with StackUp
            `${import.meta.env.VITE_ZERODEV_PAYMASTER_RPC_HOST}/${
                import.meta.env.VITE_ZERODEV_PROJECT_ID
            }?paymasterProvider=STACKUP`
        )
    })
}

export const isAccountDeployed = async (
    accountAddress: Address
): Promise<boolean> => {
    const publicClient = await getPublicClient()
    const contractCode = await publicClient.getBytecode({
        address: accountAddress
    })
    return (contractCode?.length ?? 0) > 2
}

export const getDummySignature = (): Hex => {
    return "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c"
}

export const getOldUserOpHash = (): Hex => {
    return "0xe9fad2cd67f9ca1d0b7a6513b2a42066784c8df938518da2b51bb8cc9a89ea34"
}

export const sleep = async (milliseconds: number): Promise<void> => {
    return new Promise((resolve) => setTimeout(resolve, milliseconds))
}

export const waitForNonceUpdate = async (): Promise<void> => {
    return sleep(10000)
}

export const generateApproveCallData = (paymasterAddress: Address): Hex => {
    const maxUint256 = BigInt(
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    const approveAbi: AbiItem[] = [
        {
            inputs: [
                { name: "_spender", type: "address" },
                { name: "_value", type: "uint256" }
            ],
            name: "approve",
            outputs: [{ name: "", type: "bool" }],
            stateMutability: "nonpayable",
            type: "function"
        }
    ]

    return encodeFunctionData({
        abi: approveAbi,
        functionName: "approve",
        args: [paymasterAddress, maxUint256]
    })
}

export const findUserOperationEvent = (logs: Log[]): boolean => {
    return logs.some((log) => {
        try {
            const event = decodeEventLog({
                abi: EntryPointAbi,
                ...log
            })
            return event.eventName === "UserOperationEvent"
        } catch {
            return false
        }
    })
}

export const uint8ArrayToHexString = (array: Uint8Array): `0x${string}` => {
    return `0x${Array.from(array, (byte) =>
        byte.toString(16).padStart(2, "0")
    ).join("")}` as `0x${string}`
}

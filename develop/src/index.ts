import { AptosAccount, BCS, AptosClient, TxnBuilderTypes, HexString, MaybeHexString, FaucetClient } from "aptos";
import yaml from "js-yaml";
import path from "path"
import * as crypto from "crypto-js";
import fs from 'fs'
import { execSync } from "child_process";
const prompt_ = require('prompt-sync')();

export const delay = (ms: number) => { return new Promise(resolve => setTimeout(resolve, ms)) };

class MoveTemplateType {
    head: string;
    typeArgs: Array<string>;

    constructor(head: string, typeArgs: string[]) {
        this.head = head;
        this.typeArgs = typeArgs;
    }

    static fromString(s: string): MoveTemplateType | null {
        try {
            // Remove empty space
            const ms = s.match(/^(.+?)<(.*)>$/) as RegExpMatchArray;
            const head = ms[1];
            const inner = ms[2];
            let typeArgs: string[] = [];
            let braceCounter: number = 0;

            let currentArg = "";
            for (let i = 0; i < inner.length; i += 1) {

                const c = inner[i];
                const nc = (i + 1 < inner.length) ? inner[i + 1] : ""

                if (c === '<') { braceCounter += 1; }
                else if (c === '>') { braceCounter -= 1; }

                if (c === ',' && braceCounter === 0) { 
                    if (currentArg !== "") {
                        typeArgs.push(currentArg);
                    }
                    currentArg = "";
                    if (nc === ' ') {
                        i += 1;
                    }
                }
                else {
                    currentArg += c;
                }
            }

            if (currentArg !== "") {
                typeArgs.push(currentArg);
            }

            return { head, typeArgs }
        } catch {}

        return null;
    }
}

export interface AptosNetwork {
    type: "local" | "devnet" | "testnet" | "mainnet";
    fullnode: string;
    faucet: string | null;
}

class Network {
    static local: () => AptosNetwork = () => {
        return { fullnode: "http://127.0.0.1:8080/v1", faucet: "http://127.0.0.1:8081", type: "local" }
    }

    static devnet: () => AptosNetwork = () => {
        return { fullnode: "https://fullnode.devnet.aptoslabs.com/v1", faucet: "https://faucet.devnet.aptoslabs.com", type: "devnet" }
    }

    static testnet: () => AptosNetwork = () => {
        return { fullnode: "https://testnet.aptoslabs.com/v1", faucet: null, type: "testnet" }
    }
}

class Cipher {
    static encrypt = (text: string, secretKey_: string) => {
        const secretKey = secretKey_ + Array(43 - secretKey_.length).fill("0").join("");
        var keyHex = crypto.enc.Base64.parse(secretKey);
        var messageHex = crypto.enc.Utf8.parse(text);
        var encrypted = crypto.AES.encrypt(messageHex, keyHex, {
            "mode": crypto.mode.ECB,
            "padding": crypto.pad.Pkcs7
        });
        return encrypted.toString();
    }

    static decrypt(textBase64: string, secretKey_: string) {
        const secretKey = secretKey_ + Array(43 - secretKey_.length).fill("0").join("");
        var keyHex = crypto.enc.Base64.parse(secretKey);
        var decrypt = crypto.AES.decrypt(textBase64, keyHex, {
            "mode": crypto.mode.ECB,
            "padding": crypto.pad.Pkcs7
        });
        return crypto.enc.Utf8.stringify(decrypt);
    }
}

export type AptosTransacationArgument = string | number | bigint | ["address" | "string", string] | ["u8" | "u16" | "u32" | "u64" | "u128", number | bigint];

export interface AptosTransactionType {
    function: string;
    type_arguments: string[];
    arguments: AptosTransacationArgument[];
}

export interface AptosTransactionOptions {
    maxGasAmount: bigint;
    gasUnitPrice: bigint;
    expirationSecond?: number;
}

const serializeTransactionArgument = (v: AptosTransacationArgument) => {
    let vs: any = v;
    if (typeof v === "string") {
        vs = v.startsWith("0x") ? ["address", v] : ["string", v];
    }
    else if (typeof v === "number") {
        vs = ["u64", v];
    }
    else if (typeof v === "bigint") {
        vs = ["u64", v];
    }
    else {
        vs = v;
    }

    const tag = vs[0] as "address" | "string" | "u8" | "u16" | "u32" | "u64" | "u128";
    const value = vs[1] as (string | number | bigint);
    if (tag === "address") {
        return BCS.bcsToBytes(TxnBuilderTypes.AccountAddress.fromHex(value.toString()));
    }
    else if (tag === "string") {
        return BCS.bcsSerializeStr(value.toString());
    }
    else if (tag === "u8") {
        return BCS.bcsSerializeU8(Number(value));
    }
    else if (tag === "u16") {
        return BCS.bcsSerializeU16(Number(value));
    }
    else if (tag === "u32") {
        return BCS.bcsSerializeU32(Number(value));
    }
    else if (tag === "u64") {
        return BCS.bcsSerializeUint64(BigInt(value));
    }
    else if (tag === "u128") {
        return BCS.bcsSerializeU128(BigInt(value));
    }
    throw Error(`BCS serialize error on argument: ${v}`)
}

const serializeTransactionTypeToPayload = (t: AptosTransactionType) => {
    const transactionFunctionSplit = t.function.split("::");
    const moduleName = transactionFunctionSplit.slice(0, -1).join("::");
    const functionName = transactionFunctionSplit.slice(-1)[0];
    const typeArguments = t.type_arguments.map(ty => new TxnBuilderTypes.TypeTagStruct(TxnBuilderTypes.StructTag.fromString(ty)));
    const args = t.arguments.map(x => serializeTransactionArgument(x));

    const payload = new TxnBuilderTypes.TransactionPayloadEntryFunction(
        TxnBuilderTypes.EntryFunction.natural(
            moduleName,
            functionName,
            typeArguments,
            args
        )
    );
    return payload;
}

let _MOVE_CALL_GAS_SCHEDULE: Array<{key: string, val: string}> | undefined = undefined;
let _MOVE_CALL_MIN_GAS_UNIT_PRICE: bigint | undefined = undefined;

const prepareMoveCall = async (client: AptosClient) => {
    if (_MOVE_CALL_GAS_SCHEDULE === undefined) {
        _MOVE_CALL_GAS_SCHEDULE = ((await client.getAccountResource("0x1", "0x1::gas_schedule::GasScheduleV2")).data as any).entries;
        for (const entry of (_MOVE_CALL_GAS_SCHEDULE) ?? []) {
            if (entry.key === "txn.min_price_per_gas_unit") {
                _MOVE_CALL_MIN_GAS_UNIT_PRICE = BigInt(entry.val);
                console.log(`[INFO] Setting min_gas_price to ${_MOVE_CALL_MIN_GAS_UNIT_PRICE}`)
            }
        }
    }

    if (_MOVE_CALL_MIN_GAS_UNIT_PRICE === undefined) {
        throw Error("Unable to get min_gas_price from network");
    }
}

const executeMoveCall = async (client: AptosClient, account: AptosAccount, transaction: AptosTransactionType, exit: boolean = true, option?: AptosTransactionOptions) => {

    await prepareMoveCall(client);

    console.log(`[INFO] Executing move call: ${transaction.function}<${transaction.type_arguments.join(" ")}>(...)`);

    const payload = serializeTransactionTypeToPayload(transaction);

    const rawTxn = await client.generateRawTransaction(
        account.address(),
        payload,
        {
            maxGasAmount: option?.maxGasAmount ?? BigInt(20000),
            gasUnitPrice: option?.gasUnitPrice ?? _MOVE_CALL_MIN_GAS_UNIT_PRICE,
            expireTimestamp: BigInt(Math.floor(Date.now() / 1000) + (option?.expirationSecond ?? 60.0))
        }
    );

    const signedTransaction = await client.signTransaction(account, rawTxn);
    const submitTransaction = await client.submitSignedBCSTransaction(signedTransaction);

    try {
        const reuslt = await client.waitForTransactionWithResult(submitTransaction.hash, { timeoutSecs: 60.0, checkSuccess: true });
        const gasUsed = (reuslt as any).gas_used;
        if (gasUsed !== undefined) {
            const gasUsedShow = gasUsed / (10 ** 8);
            console.log(`[INFO] Gas used: ${gasUsed}(${gasUsedShow})`)
        }
    } catch (e) {
        let reason: string | undefined = undefined;

        const transaction = (e as any).transaction;
        if (transaction !== undefined) {
            reason = transaction.vm_status;
        }

        if (exit) {
            errorAndExit(e, 1, reason);
        }
        else {
            console.log(`[WARNING] Execution failed on ${transaction.function} [REASON: ${reason}]`);
        }
    }

    return submitTransaction.hash;
}

const workspaceFolder = path.resolve(path.join(process.cwd(), ".."));

const prompt = (s: string, default_?: string): string => {
    const i = prompt_(s);
    if (default_ !== undefined && i.trim().length === 0) {
        return default_;
    }
    return i;
}

const hexToBytes = (hex: string) => {
    console.log(hex);
    let bytes: number[] = [];
    for (let c = (hex.startsWith("0x") ? 2 : 0); c < hex.length; c += 2) {
        const b = hex.slice(c, c + 2);
        bytes.push(parseInt(b, 16));
    }
    return new Uint8Array(bytes);
}

const errorAndExit = (s: any, exitCode?: number, reason?: string) => {
    const reasonOrNull = (reason === undefined) ? "" : `[Reason: ${reason}]`
    console.log(`[ERROR] ${s} ${reasonOrNull}`);
    process.exit(exitCode ?? 1);
}

const cmd = (s: string, exit: boolean = true, env?: any) => {
    try {
        console.log(`[EXECUTE] ${s}`)
        return execSync(s, { "encoding": "utf-8", env: (env !== undefined) ? { ...process.env, ...env } : process.env })
    } catch (e) {
        console.log((e as any).stdout);
        console.log((e as any).stderr)
        if (exit) {
            errorAndExit(`Command failed when executing \'${s}\"`)
        }
    }
    return "";
}

const getBalance = async (client: AptosClient, accountAddress: MaybeHexString) => {
    try {
        const resource = await client.getAccountResource(
            accountAddress,
            `0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>`,
        );
        return BigInt((resource.data as any)["coin"]["value"]);
    } catch (_) {
        return BigInt(0);
    }
}

const publishModule = async (client: AptosClient, accountFrom: AptosAccount, moduleHexes: Uint8Array[], metadata: Uint8Array, option?: AptosTransactionOptions) => {
    await prepareMoveCall(client);

    let txnHash = await client.publishPackage(
        accountFrom, metadata, 
        moduleHexes.map(hex => new TxnBuilderTypes.Module(hex)),
        {
            maxGasAmount: option?.maxGasAmount ?? BigInt(20000),
            gasUnitPrice: option?.gasUnitPrice ?? _MOVE_CALL_MIN_GAS_UNIT_PRICE,
            expireTimestamp: BigInt(Math.floor(Date.now() / 1000) + (option?.expirationSecond ?? 60.0))
        }
    );
    await client.waitForTransaction(txnHash, { checkSuccess: true });
    return txnHash;
}

const newAccount = () => {
    const password = prompt("Enter the email/password to renew a account[format: <email>/<password>]: ").trim();

    process.chdir(workspaceFolder); {
        if (fs.existsSync(".aptos")) {
            fs.rmSync(".aptos", { "force": true, "recursive": true });
        }
        cmd("aptos init");
    }

    console.log("Encrypt:")
    console.log("================================================")
    const text = fs.readFileSync(".aptos/config.yaml", "utf-8");
    const encrypted = Cipher.encrypt(text, password);
    console.log(encrypted);
    console.log("================================================\n")

    console.log("Text:")
    console.log("================================================")
    const decripted = Cipher.decrypt(encrypted, password);
    console.log(decripted);
    console.log("================================================")

    process.chdir(workspaceFolder); {
        fs.rmSync(".aptos", { "force": true, "recursive": true });
    }
}

const getAccount = () => {
    const encrypted = "NXt1fScxw3c4U7MjwiBlMNUlo0AV+EZ7qF1F/b1q09h9yU9zbBSeFZWLD7y4tsnEpsTrx8up/RoNlUaa/5Rt4xV/t3SmLr5zID88JKnTfk7pbdpjBzDjTln/yOi5GMwpXOyb87dLfc4nbZftgqBxc0MMWcZ8lDsiUg/d4nQ2icMJU4cUCpQPZEq+QsajXM+nyQwu5RdrENLE1lXmKt0p2iSv8RcOBgm0KEqKhlzx8hZySqwbo0PTuEmbwotg4EI1AhYn8oTOVpN4ONOH7I3aTOdqwfGabyRqYwgRHI950qeptdpGbJPid9PADFQofd0DfDUfdFECn10aDRPAv+FD9rGlaon1keal1mMYl9proH51n4Hif8Jf6EGM+GtHfEayetYa9o2qxZ7AlppQmvLVUToYwUALy3u2PafwgDjgwQCvQqpuJuoXbKLjTDpRO3NYD01Pdy4OogXgrYt3LqHSYWBysoKh9V9r1IN0zh/FQ0jx4T/z9XZ697386rY/VeswEf+SBpIC9rDXzhkKB3essQ==";
    const password = prompt("Enter the email/password to get a account[format: <email>/<password>]: ").trim();
    const decrypted = Cipher.decrypt(encrypted, password);

    console.log(`[INFO] Use the following config.yaml:\n=======================================\n${decrypted}\n`);

    process.chdir(workspaceFolder); {
        if (!fs.existsSync(".aptos")) {
            fs.mkdirSync(".aptos");
        }

        const configPath = path.join(".aptos", "config.yaml");
        if (fs.existsSync(configPath)) {
            fs.rmSync(configPath, { "force": true, "recursive": true });
        }

        fs.writeFileSync(configPath, decrypted);
    }

    const accountConfig = yaml.load(decrypted) as any;
    const accountPrivateKey = hexToBytes(accountConfig.profiles.default.private_key);
    const accountAddress = accountConfig.profiles.default.account;
    const account = new AptosAccount(accountPrivateKey, accountAddress);

    return account;
}

const getMoveCode = () => {
    const moduleFilenames = [
        'utils.mv',
        'pool.mv',
    ];

    const buffers = moduleFilenames.map(
        moduleFilename => {
            const modulePath = path.join(workspaceFolder, "build", "Aptoswap", "bytecode_modules", moduleFilename);
            const buffer = fs.readFileSync(modulePath);
            return new HexString(buffer.toString("hex")).toUint8Array();
        }
    )

    return buffers;
}

const getMoveMetadata = () => {
    const metadataPath = path.join(workspaceFolder, "build", "Aptoswap", "package-metadata.bcs");
    const buffer = fs.readFileSync(metadataPath);
    return new HexString(buffer.toString("hex")).toUint8Array();
}

type SetupType = [AptosAccount, AptosClient, FaucetClient | null, AptosNetwork];

const setup: () => Promise<SetupType> = async () => {
    // Get the network

    let selectNetworkInput = prompt("Select your network [devnet|localhost|testnet] (default: localhost): ", "localhost").trim();
    const n: AptosNetwork = ({
        devnet: Network.devnet(),
        localhost: Network.local(),
        testnet: Network.testnet()
    } as any)[selectNetworkInput];

    if (n === undefined) {
        errorAndExit("Invalid network input");
    }

    const client = new AptosClient(n.fullnode);
    const account = getAccount();
    const faucetClient = (n.faucet !== null) ? new FaucetClient(n.fullnode, n.faucet) : null;

    return [account, client, faucetClient, n] as [AptosAccount, AptosClient, FaucetClient | null, AptosNetwork];
}

const autoFund = async (account: AptosAccount, client: AptosClient, faucetClient: FaucetClient | null, target?: number) => {
    if (faucetClient !== null) {
        console.log(`[BEGIN] Funding...`)

        while (true) {
            await faucetClient.fundAccount(account.address(), 100000 * (10 ** 8));


            if (target === undefined) {
                break;
            }

            const balance = await getBalance(client, account.address());
            if (Number(balance) / (10 ** 8) < target) {
                await delay(3000.0);
                continue;
            }

            break;
        }

        console.log(`[DONE] Funding...`)
    }
}

const actionCreatePool = async (args: string[], setups?: SetupType) => {
    const [account, client, faucetClient, net] = setups ?? (await setup());

    const HIPPO_TOKEN_PACKAGE_ADDR = "0x498d8926f16eb9ca90cab1b3a26aa6f97a080b3fcbe6e83ae150b7243a00fb68";
    const CELER_TOKEN_PACKAGE_ADDR = "0xbc954a7df993344c9fec9aaccdf96673a897025119fc38a8e0f637598496b47a";
    const BLUE_MOVE_PACKAGE_ADDR = "0xe4497a32bf4a9fd5601b27661aa0b933a923191bf403bd08669ab2468d43b379";
    const TORTUGA_FINANCE_PACKAGE_ADDR = {
        "devnet": "0x12d75d5bde2535789041cd380e832038da873a4ba86348ca891d374e1d0e15ab",
        "testnet": "0x2a2ad97dfdbe4e34cdc9321c63592dda455f18bc25c9bb1f28260312159eae27"
    }[net.type as string];

    if (TORTUGA_FINANCE_PACKAGE_ADDR === undefined) {
        throw new Error(`TORTUGA_FINANCE_PACKAGE_ADDR not configure for ${net.type}`);
    }

    const accountAddr = account.address();
    const packageAddr = accountAddr;
    await autoFund(account, client, faucetClient, 0.8);

    const currentBalance = await getBalance(client, accountAddr);
    const currentBalanceShow = Number(currentBalance) / (10 ** 8);
    console.log(`[INFO] Current balance: ${currentBalance}(${currentBalanceShow})`);

    const aptoswap = {
        fee: {
            adminFee: 3,
            lpFee: 26,
            incentiveFee: 0,
            connectFee: 1,
            withdrawFee: 10,
        },
        tokens: [
            { coin: [`${packageAddr}::pool::TestToken`, "0x1::aptos_coin::AptosCoin"], direction: "Y" },
            { coin: [`${packageAddr}::pool::Token`, "0x1::aptos_coin::AptosCoin"], direction: "Y" }
        ]
    }

    const hippo = {
        fee: {
            adminFee: 3,
            lpFee: 26,
            incentiveFee: 0,
            connectFee: 1,
            withdrawFee: 10,
        },
        tokens: [
            { coin: [`${HIPPO_TOKEN_PACKAGE_ADDR}::devnet_coins::DevnetBTC`, "0x1::aptos_coin::AptosCoin"], direction: "Y" },
            { coin: [`${HIPPO_TOKEN_PACKAGE_ADDR}::devnet_coins::DevnetDAI`, "0x1::aptos_coin::AptosCoin"], direction: "Y" },
            { coin: [`${HIPPO_TOKEN_PACKAGE_ADDR}::devnet_coins::DevnetUSDC`, "0x1::aptos_coin::AptosCoin"], direction: "Y" },
            { coin: [`${HIPPO_TOKEN_PACKAGE_ADDR}::devnet_coins::DevnetUSDT`, "0x1::aptos_coin::AptosCoin"], direction: "Y" },

            { coin: [`${HIPPO_TOKEN_PACKAGE_ADDR}::devnet_coins::DevnetBTC`, `${HIPPO_TOKEN_PACKAGE_ADDR}::devnet_coins::DevnetDAI`], direction: "Y" },
            { coin: [`${HIPPO_TOKEN_PACKAGE_ADDR}::devnet_coins::DevnetBTC`, `${HIPPO_TOKEN_PACKAGE_ADDR}::devnet_coins::DevnetUSDC`], direction: "Y" },
            { coin: [`${HIPPO_TOKEN_PACKAGE_ADDR}::devnet_coins::DevnetBTC`, `${HIPPO_TOKEN_PACKAGE_ADDR}::devnet_coins::DevnetUSDT`], direction: "Y" },
        ]
    }

    const celer = {
        fee: {
            adminFee: 0,
            lpFee: 27,
            incentiveFee: 3,
            connectFee: 0,
            withdrawFee: 10,
        },
        tokens: [
            { coin: ["0x1::aptos_coin::AptosCoin", `${CELER_TOKEN_PACKAGE_ADDR}::test_mint_dai_coin::TestMintCoin`],  direction: "Y" },
            { coin: ["0x1::aptos_coin::AptosCoin", `${CELER_TOKEN_PACKAGE_ADDR}::test_mint_usdc_coin::TestMintCoin`], direction: "Y" },
            { coin: ["0x1::aptos_coin::AptosCoin", `${CELER_TOKEN_PACKAGE_ADDR}::test_mint_usdt_coin::TestMintCoin`], direction: "Y" },
            { coin: [`${CELER_TOKEN_PACKAGE_ADDR}::test_mint_wbtc_coin::TestMintCoin`, "0x1::aptos_coin::AptosCoin"], direction: "Y" },
            { coin: [`${CELER_TOKEN_PACKAGE_ADDR}::test_mint_weth_coin::TestMintCoin`, "0x1::aptos_coin::AptosCoin"], direction: "Y" }
        ]
    }

    const tortuga = {
        fee: {
            adminFee: 1,
            lpFee: 4,
            incentiveFee: 1,
            connectFee: 0,
            withdrawFee: 10,
        },
        tokens: [
            { coin: [`${TORTUGA_FINANCE_PACKAGE_ADDR}::staked_aptos_coin::StakedAptosCoin`, "0x1::aptos_coin::AptosCoin"],  direction: "Y" },
        ]
    }

    const bluemove = {
        fee: {
            adminFee: 0,
            lpFee: 27,
            incentiveFee: 3,
            connectFee: 0,
            withdrawFee: 10,
        },
        tokens: [
            { coin: [`${BLUE_MOVE_PACKAGE_ADDR}::move_coin::MoveCoin`, "0x1::aptos_coin::AptosCoin"],  direction: "Y" },
        ]
    }
    

    // Getting the pools
    const createdPoolTypes = (await client.getAccountResources(packageAddr)).filter(resource => resource.type.startsWith(`${packageAddr}::pool::Pool`)).map(x => x.type);

    // Create pool
    for (const poolConfig of [aptoswap, hippo, celer, tortuga, bluemove]) {
        const fee = poolConfig.fee;
        const tokens = poolConfig.tokens;
        for (const tk of tokens) {

            const isPoolNotExists = (createdPoolTypes.every(ty => (!ty.includes(tk.coin[0]) || !ty.includes(tk.coin[1])) ));
            if (!isPoolNotExists) {
                console.log(`Skip creating pool: ${tk.coin[0]}/${tk.coin[1]}`)
                continue;
            }

            await executeMoveCall(
                client, account,
                {
                    function: `${packageAddr}::pool::create_pool`,
                    type_arguments: [tk.coin[0], tk.coin[1]],
                    arguments: [
                        ["u8", tk.direction.toLowerCase() === "x" ? 200 : 201],
                        fee.adminFee,
                        fee.lpFee,
                        fee.incentiveFee,
                        fee.connectFee,
                        fee.withdrawFee
                    ]
                },
                false
            );
        }
    }
}

const actionFreezePool = async (args: string[], setups?: SetupType) => {
    if (args.length === 0) {
        errorAndExit("Filter must be provided for freezing pool");
    }

    const filters = args;

    const [account, client, faucetClient, net] = setups ?? (await setup());
    const accountAddr = account.address();
    const packageAddr = accountAddr;
    await autoFund(account, client, faucetClient, 0.8);

    const resources = (await client.getAccountResources(packageAddr)).filter(resource => resource.type.startsWith(`${packageAddr}::pool::Pool`));
    for (const resource of resources) {
        if (!filters.every(filter => resource.type.includes(filter))) {
            continue;
        }

        const mtt = MoveTemplateType.fromString(resource.type);
        if (mtt === null) {
            continue;
        }

        const xType = mtt.typeArgs[0];
        const yType = mtt.typeArgs[1];
        console.log(`[INFO] Freeze ${xType}/${yType}`);
        await executeMoveCall(
            client, account,
            {
                function: `${packageAddr}::pool::freeze_pool`,
                type_arguments: [xType, yType],
                arguments: []
            },
            false
        );
    }
}

const actionPublish = async (args: string[], setups?: SetupType) => {
    const [account, client, faucetClient, net] = setups ?? (await setup());
    const accountAddr = account.address();
    const packageAddr = accountAddr;
    await autoFund(account, client, faucetClient, 0.8);

    const currentBalance = await getBalance(client, accountAddr);
    const currentBalanceShow = Number(currentBalance) / (10 ** 8);
    console.log(`[INFO] Current balance: ${currentBalance}(${currentBalanceShow})`);

    process.chdir(workspaceFolder); {
        if (fs.existsSync("package_info.json")) {
            fs.rmSync("package_info.json", { "force": true });
        }

        fs.writeFileSync(
            "package_info.json",
            JSON.stringify({
                "package": accountAddr.toString()
            })
        );
    }

    process.chdir(workspaceFolder); {
        // Clean & build
        if (fs.existsSync("build")) {
            fs.rmSync("build", { "force": true, "recursive": true });
        }
        cmd("aptos move clean --assume-yes", false);
        cmd("aptos move compile --named-addresses Aptoswap=default --save-metadata");

        const code = getMoveCode();
        const metadata = getMoveMetadata();

        console.log("[BEGIN] Publish module...")
        const txHashPublish = await publishModule(client, account, code, metadata);
        console.log(`[DONE] Publish module, tx: ${txHashPublish}`);
    }

    // Initialize
    if (prompt("Do you want to call the pool::initialize command [yes/no]", "yes").trim().toLocaleLowerCase() === "yes") {
        await executeMoveCall(
            client, account,
            {
                function: `${packageAddr}::pool::initialize`,
                type_arguments: [],
                arguments: [["u8", 6]]
            },
            true
        );
    }
}

const actionNewAccount = async (args: string[], setups?: SetupType) => { await newAccount(); }

const actionGetAccount = async (args: string[], setups?: SetupType) => { await getAccount(); }

const executeAction = async () => {
    const commands: Map<string, (args: string[], setups?: SetupType) => Promise<void>> = new Map([
        ["publish", actionPublish],
        ["new-account", actionNewAccount],
        ["account", actionGetAccount],
        ["create-pool", actionCreatePool],
        ["freeze-pool", actionFreezePool] 
    ]);

    if (process.argv.length < 3) {
        errorAndExit("Not enough argument, please enter the command");
    }

    const commandStr = process.argv[2].trim();
    const command = commands.get(commandStr);

    if (command !== undefined) {
        await command(process.argv.slice(3));
    }
    else {
        errorAndExit(`Invalid action \"${commandStr}\", possible options: \"${Array(commands.keys()).join("|")}\"`)
    }
}

executeAction()
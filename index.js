import chalk from "chalk";
import { Connection, Keypair } from "@solana/web3.js";
import * as bip39 from "bip39";
import PromptSync from "prompt-sync";
import { HDKey } from 'micro-ed25519-hdkey';
import fs from "fs";
import nacl from "tweetnacl";
import nacl_util from "tweetnacl-util";
import bs58 from "bs58";

const prompt = PromptSync()

const getMessage = async () => {
    const url = "https://api.assisterr.ai/incentive/auth/login/get_message/"

    const headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en,en-US;q=0.9,id;q=0.8',
        'dnt': '1',
        'origin': 'https://build.assisterr.ai',
        'priority': 'u=1, i',
        'referer': 'https://build.assisterr.ai/',
        'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'
    }

    while(true) {
        try {
            const response = await fetch(url, {
                method: "GET",
                headers: headers
            })

            if(!response.ok) {
                throw new Error(`${response.status} ${response.statusText}`)
            }
    
            return await response.json()
        } catch (err) {
            console.log(chalk.red(`❌ Error to get message: ${err.message}`))
        }
    }
}

const getSignature = async (message, secretKey) => {
    const messageBytes = nacl_util.decodeUTF8(message);
    // console.log(bs58.encode(messageBytes))

    const signature = nacl.sign.detached(messageBytes, secretKey);
    // console.log(bs58.encode(signature))

    // const result = nacl.sign.detached.verify(
    //     messageBytes,
    //     signature,
    //     keypair.publicKey.toBytes(),
    // );
    // console.log(result)

    return bs58.encode(signature)
}

const loginKeun = async (pubkey, signature, message) => {
    const url = "https://api.assisterr.ai/incentive/auth/login/"

    const payload = JSON.stringify({
        "message": message,
        "signature": signature,
        "key": pubkey
    })
    
    const headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'origin': 'https://build.assisterr.ai',
        'priority': 'u=1, i',
        'referer': 'https://build.assisterr.ai/',
        'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'
    }

    while(true) {
        try {
            const response = await fetch(url, {
                method: "POST",
                headers: headers,
                body: payload
            })

            if(!response.ok) {
                throw new Error(`${response.status} ${response.statusText}`)
            }
    
            return await response.json()
        } catch (err) {
            console.log(chalk.red(`❌ Error to login: ${err.message}`))
        }
    }
}

const loadPhrase = async () => {
    try {
        console.log(chalk.yellow("\nⓘ Pastikan telah memasukkan Mnemonic atau kumpulan Mnemonic pada mnemonic.txt"))

        // read mnemonic.txt
        const data = fs.readFileSync('mnemonic.txt', 'utf-8');
        const mnemonics = data.split('\n')

        let accessTokens = []

        console.log('🕯 Membuat signature dan akses token...')
        // BIP44
        for (const mnemonic of mnemonics) {
            if(mnemonic!='') {
                // arguments: (mnemonic, password)
                const seed = bip39.mnemonicToSeedSync(mnemonic.trim(), "");
                const hd = HDKey.fromMasterSeed(seed.toString("hex"));
                const path = `m/44'/501'/0'/0'`;
                const keypair = Keypair.fromSeed(hd.derive(path).privateKey);
                const address = keypair.publicKey.toBase58()

                // get message
                const message = await getMessage()
                // console.log(message)

                const signature = await getSignature(message, keypair.secretKey)
                // console.log(address, message, signature)

                const login = await loginKeun(address, signature, message)
                if (login.access_token != undefined) {
                    accessTokens.push(`${address}|${login.access_token}`)
                }
            }
        }

        if (accessTokens.length>0) {
            console.log(chalk.green('✓ Berhasil membuat signature dan akses token\n'))
        }

        //buat tokens.txt
        fs.writeFileSync('tokens.txt', '')

        //masukkan token satu-satu ke tokens.txt
        for (const accessToken of accessTokens) {
            fs.appendFileSync('tokens.txt', `${accessToken}\n`)
        }
        
    } catch (e) {
        // jika mnemonic.txt not exist
        if (e.code == 'ENOENT') {
            console.log(chalk.red('📝 Fill the mnemonic.txt first!'));
            fs.writeFileSync('mnemonic.txt', "mnemonic wallet 1\nmnemonic wallet 2\netc...")
            process.exit()
        } else {
            throw e
        }
    }
}

const loadPkey = async () => {
    try {
        console.log(chalk.yellow("\nⓘ Pastikan telah memasukkan Private Key atau kumpulan Private Key pada pkey.txt"))

        // read pkey.txt
        const data = fs.readFileSync('pkey.txt', 'utf-8');
        const pkeys = data.split('\n')

        let accessTokens = []

        console.log('🕯 Membuat signature dan akses token...')
        // Bytes
        for (const pkey of pkeys) {
            if(pkey!='') {
                // arguments: (mnemonic, password)
                const array = pkey.trim().replace('[','').replace(']','').split(",").map(Number);
                const keypairBytes = Uint8Array.from(array);
                const keypair = Keypair.fromSecretKey(keypairBytes);
                const address = keypair.publicKey.toBase58()

                // get message
                const message = await getMessage()
                // console.log(message)

                const signature = await getSignature(message, keypair.secretKey)
                // console.log(address, message, signature)

                const login = await loginKeun(address, signature, message)
                if (login.access_token != undefined) {
                    accessTokens.push(`${address}|${login.access_token}`)
                }
            }
        }

        if (accessTokens.length>0) {
            console.log(chalk.green('✓ Berhasil membuat signature dan akses token\n'))
        }

        //buat tokens.txt
        fs.writeFileSync('tokens.txt', '')

        //masukkan token satu-satu ke tokens.txt
        for (const accessToken of accessTokens) {
            fs.appendFileSync('tokens.txt', `${accessToken}\n`)
        }
        
    } catch (e) {
        // jika pkey.txt not exist
        if (e.code == 'ENOENT') {
            console.log(chalk.red('📝 Fill the pkey.txt first!'));
            fs.writeFileSync('pkey.txt', "pkey wallet 1\npkey wallet 2\netc...")
            process.exit()
        } else {
            throw e
        }
    }
}

const getMe = async (token) => {
    const url = "https://api.assisterr.ai/incentive/users/me/"

    const headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en-US,en;q=0.9',
        'authorization': `Bearer ${token}`,
        'origin': 'https://build.assisterr.ai',
        'priority': 'u=1, i',
        'referer': 'https://build.assisterr.ai/',
        'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'
    }

    while(true) {
        try {
            const response = await fetch(url, {
                method: "GET",
                headers: headers
            })

            if(!response.ok) {
                throw new Error(`${response.status} ${response.statusText}`)
            }
    
            return await response.json()
        } catch (err) {
            console.log(chalk.red(`❌ Error to get meta: ${err.message}`))
        }
    }
}

const getMeta = async (token) => {
    const url = "https://api.assisterr.ai/incentive/users/me/meta/"

    const headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en-US,en;q=0.9',
        'authorization': `Bearer ${token}`,
        'origin': 'https://build.assisterr.ai',
        'priority': 'u=1, i',
        'referer': 'https://build.assisterr.ai/',
        'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'
    }

    while(true) {
        try {
            const response = await fetch(url, {
                method: "GET",
                headers: headers
            })

            if(!response.ok) {
                throw new Error(`${response.status} ${response.statusText}`)
            }
    
            return await response.json()
        } catch (err) {
            console.log(chalk.red(`❌ Error to get meta: ${err.message}`))
        }
    }
}

const dailyCheck = async (token) => {
    const url = "https://api.assisterr.ai/incentive/users/me/daily_points/"

    const payload = {}

    const headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en-US,en;q=0.9',
        'authorization': `Bearer ${token}`,
        'origin': 'https://build.assisterr.ai',
        'priority': 'u=1, i',
        'referer': 'https://build.assisterr.ai/',
        'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'
    }

    while(true) {
        try {
            const response = await fetch(url, {
                method: "POST",
                headers: headers,
                body: payload
            })

            if(!response.ok) {
                throw new Error(`${response.status} ${response.statusText}`)
            }
    
            return [await response.json(), response.status]
        } catch (err) {
            console.log(chalk.red(`❌ Error to daily check in: ${err.message}`))
        }
    }
}

(async () => {
    console.log("🤖 Assisterr AI Daily Check-in Bot\n")
    
    // const connection = new Connection("https://solana.drpc.org")
    // // console.log(connection)

    console.log("[1] Login dari Mnemonics BIP44 (12 or 24 words)\n[2] Login dari Keypair Bytes")
    let pilihanLogin = prompt("↪ Silakan masukkan pilihan: ")

    if (pilihanLogin == 1) {
        while(true) {
            await loadPhrase()

            try {
                // read tokens.txt
                const data = fs.readFileSync('tokens.txt', 'utf-8');
                const tokens = data.split('\n')
                            
                for (const token of tokens) {
                    if (token!='') {
                        const soladdress = token.split('|')[0]
                        const accesstoken = token.split('|')[1]
                        // wallet
                        console.log(`🔑 SOL address: ${chalk.green(soladdress)}`)
                        
                        // user
                        const me = await getMe(accesstoken)
                        console.log(`🏆 Points: ${chalk.yellow(Number(me.points/100).toLocaleString('en-US'))}\n🐦 Twitter verifed: ${me.twitter_verified==true?chalk.green('✅'):'❌'}\n💬 Discord verifed: ${me.discord_verified==true?chalk.green('✅'):'❌'}\n🥇 Verifed account: ${me.is_verified==true?chalk.green('✅'):'❌'}`)
                    
                        // daily
                        const meta = await getMeta(accesstoken)
                        if (meta.daily_points_start_at==null) {
                            console.log(chalk.green(`✅ Daily check-in tersedia, sedang proses...`))
                            const [checkin, status_checkin] = await dailyCheck(accesstoken)
                            if(status_checkin==200) {
                                console.log(chalk.green(`✅ Berhasil check-in!\n`))
                            } else {
                                console.log()
                            }
                        } else {
                            console.log(chalk.red(`❌ Daily check-in sedang tidak tersedia\n`))
                        }
                    }
                }
            } catch (err) {
                // jika mnemonic.txt not exist
                if (e.code == 'ENOENT') {
                    console.log(chalk.red('📝 Tokens.txt not found!'));
                    process.exit()
                } else {
                    throw e
                }
            }

            console.log('⏳ Delay 2 jam')
            await new Promise(resolve => setTimeout(resolve, 7200*1000))
        } 
    } else if (pilihanLogin == 2) {
        while(true) {
            await loadPkey()

            try {
                // read tokens.txt
                const data = fs.readFileSync('tokens.txt', 'utf-8');
                const tokens = data.split('\n')
                            
                for (const token of tokens) {
                    if (token!='') {
                        const soladdress = token.split('|')[0]
                        const accesstoken = token.split('|')[1]
                        // wallet
                        console.log(`🔑 SOL address: ${chalk.green(soladdress)}`)
                        
                        // user
                        const me = await getMe(accesstoken)
                        console.log(`🏆 Points: ${chalk.yellow(Number(me.points/100).toLocaleString('en-US'))}\n🐦 Twitter verifed: ${me.twitter_verified==true?chalk.green('✅'):'❌'}\n💬 Discord verifed: ${me.discord_verified==true?chalk.green('✅'):'❌'}\n🥇 Verifed account: ${me.is_verified==true?chalk.green('✅'):'❌'}`)
                    
                        // daily
                        const meta = await getMeta(accesstoken)
                        if (meta.daily_points_start_at==null) {
                            console.log(chalk.green(`✅ Daily check-in tersedia, sedang proses...`))
                            const [checkin, status_checkin] = await dailyCheck(accesstoken)
                            if(status_checkin==200) {
                                console.log(chalk.green(`✅ Berhasil check-in!\n`))
                            } else {
                                console.log()
                            }
                        } else {
                            console.log(chalk.red(`❌ Daily check-in sedang tidak tersedia\n`))
                        }
                    }
                }
            } catch (err) {
                // jika mnemonic.txt not exist
                if (e.code == 'ENOENT') {
                    console.log(chalk.red('📝 Tokens.txt not found!'));
                    process.exit()
                } else {
                    throw e
                }
            }

            console.log('⏳ Delay 2 jam')
            await new Promise(resolve => setTimeout(resolve, 7200000))
        } 
    } else {
        console.log(chalk.red("❌ Exit!"))
        process.exit()
    }
})()
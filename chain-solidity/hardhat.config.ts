import '@nomicfoundation/hardhat-ethers';
import 'hardhat-tracer';
import '@nomicfoundation/hardhat-chai-matchers';
import "@nomicfoundation/hardhat-verify";
import { promises as fs } from 'fs';
import path from 'path';
import dotenv from 'dotenv';

import canonicalize from 'canonicalize';
import { TASK_COMPILE } from 'hardhat/builtin-tasks/task-names';
import { HardhatUserConfig, task } from 'hardhat/config';

// Load environment variables
dotenv.config();

import '@typechain/hardhat';

const TASK_EXPORT_ABIS = 'export-abis';

task(TASK_COMPILE, async (_args, hre, runSuper) => {
  await runSuper();
  await hre.run(TASK_EXPORT_ABIS);
});

task(TASK_EXPORT_ABIS, async (_args, hre) => {
  const srcDir = path.basename(hre.config.paths.sources);
  const outDir = path.join(hre.config.paths.root, 'abis');

  const [artifactNames] = await Promise.all([
    hre.artifacts.getAllFullyQualifiedNames(),
    fs.mkdir(outDir, { recursive: true }),
  ]);

  await Promise.all(
    artifactNames.map(async (fqn) => {
      const { abi, bytecode, contractName, sourceName } = await hre.artifacts.readArtifact(fqn);
      if (abi.length === 0 || !sourceName.startsWith(srcDir) || contractName.endsWith('Test')) {
        return;
      }
      await fs.writeFile(`${path.join(outDir, contractName)}.json`, `${canonicalize(abi)}\n`);
      await fs.writeFile(`${path.join(outDir, contractName)}.bin`, bytecode);
    }),
  );
}).setDescription('Saves ABI and bytecode to the "abis" directory');

task('deploy', async (_args, hre) => {
  const {ethers} = hre;

  const dhtlc_factory = await ethers.getContractFactory('DestinationHTLC');
  const dhtlc = await dhtlc_factory.deploy();
  const dhtlc_tx = dhtlc.deploymentTransaction()!;
  console.log('DestinationHTLC tx', dhtlc_tx.hash)
  await dhtlc_tx.wait();

  const shtlc_factory = await ethers.getContractFactory('SourceHTLC');
  const shtlc = await shtlc_factory.deploy();
  const shtlc_tx = shtlc.deploymentTransaction()!;
  console.log('SourceHTLC tx', shtlc_tx.hash)
  await shtlc_tx.wait();

  const chainId = (await ethers.provider.getNetwork()).chainId;

  const config = {
    'node_url': (hre.network.config as any).url,
    'chain_id': chainId.toString(10),
    'dhtlc_address': await dhtlc.getAddress(),
    'shtlc_address': await shtlc.getAddress(),
    'network': hre.network.name,
  };
  console.log('Config', config);
  await fs.writeFile(`${hre.network.name}.json`, JSON.stringify(config));
}).setDescription('Deploy contracts onto chain');

const TEST_HDWALLET = {
  mnemonic: 'test test test test test test test test test test test junk',
  path: "m/44'/60'/0'/0",
  initialIndex: 0,
  count: 20,
  passphrase: '',
};

const accounts = process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : TEST_HDWALLET;

const config: HardhatUserConfig = {
  networks: {
    hardhat: {
      chainId: 1337, // @see https://hardhat.org/metamask-issue.html
    },
    hardhat_local: {
      url: 'http://127.0.0.1:8545/',
    },
    'monad-testnet': {
      url: 'https://testnet-rpc.monad.xyz/',
      chainId: 10143,
      accounts,
    },
    'etherlink-testnet': {
      url: 'https://node.ghostnet.etherlink.com/',
      chainId: 128123,
      accounts,
    },
  },
  solidity: {
    compilers: [
      {
        version: '0.8.28',
        settings: {
          evmVersion: "paris",
          optimizer: {
            enabled: true,
            runs: 200,
          },
          viaIR: true,
        },
      }
    ],
  },
  sourcify: {
    enabled: true,
  },
  etherscan: {
    apiKey: {
      'etherlink-testnet': 'empty'
    },
    customChains: [
      {
        network: "etherlink-testnet",
        chainId: 128123,
        urls: {
          apiURL: "https://testnet.explorer.etherlink.com/api",
          browserURL: "https://testnet.explorer.etherlink.com"
        }
      }
    ]
  },
  typechain: {
    target: 'ethers-v6',
    outDir: 'src/contracts',
  },
  mocha: {
    require: ['ts-node/register/files'],
    timeout: 50_000,
  },
};

export default config;

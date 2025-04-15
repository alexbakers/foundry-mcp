import { McpServer, ResourceTemplate, ReadResourceTemplateCallback } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { exec } from "child_process";
import { promisify } from "util";
import * as path from "path";
import * as fs from "fs/promises";
import * as os from "os";
import * as dotenv from "dotenv"

dotenv.config();

const execAsync = promisify(exec);

const server = new McpServer({
  name: "Foundry MCP Server",
  version: "1.1.1"
}, {
  instructions: `
This server provides tools for Solidity developers using the Foundry toolkit:
- forge: Smart contract development framework
- cast: EVM nodes RPC client and utility tool
- anvil: Local EVM test node

You can interact with local or remote EVM chains, deploy contracts, perform common operations, and analyze smart contract code.
  `
});

 const FOUNDRY_WORKSPACE = path.join(os.homedir(), '.mcp-foundry-workspace');

 async function ensureWorkspaceInitialized(): Promise<string> {
  try {
     await fs.mkdir(FOUNDRY_WORKSPACE, { recursive: true });
    
     const isForgeProject = await fs.access(path.join(FOUNDRY_WORKSPACE, 'foundry.toml'))
      .then(() => true)
      .catch(() => false);
    
    if (!isForgeProject) {
       await executeCommand(`cd ${FOUNDRY_WORKSPACE} && ${forgePath} init --no-git`);
    }
    
    return FOUNDRY_WORKSPACE;
  } catch (error) {
    console.error("Error initializing workspace:", error);
    throw error;
  }
}

const getBinaryPaths = () => {
  const homeDir = os.homedir();

   const FOUNDRY_BIN = path.join(homeDir, '.foundry', 'bin');
  
  return {
    castPath: path.join(FOUNDRY_BIN, "cast"),
    forgePath: path.join(FOUNDRY_BIN, "forge"),
    anvilPath: path.join(FOUNDRY_BIN, "anvil"),
    homeDir
  };
};

const { castPath, forgePath, anvilPath, homeDir } = getBinaryPaths();

const DEFAULT_RPC_URL = process.env.RPC_URL || "http://localhost:8545";

const FOUNDRY_NOT_INSTALLED_ERROR = "Foundry tools are not installed. Please install Foundry: https://book.getfoundry.sh/getting-started/installation";

 
async function checkFoundryInstalled(): Promise<boolean> {
  try {
    await execAsync(`${forgePath} --version`);
    return true;
  } catch (error) {
    console.error("Foundry tools check failed:", error);
    return false;
  }
}

 
async function executeCommand(command: string): Promise<{ success: boolean; message: string }> {
  try {
    const { stdout, stderr } = await execAsync(command);
    if (stderr && !stdout) {
      return { success: false, message: stderr };
    }
    return { success: true, message: stdout };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return { success: false, message: errorMessage };
  }
}
 
async function resolveRpcUrl(rpcUrl: string | undefined): Promise<string> {
  if (!rpcUrl) {
    return DEFAULT_RPC_URL;
  }
  
  // Handle alias lookup in foundry config
  if (!rpcUrl.startsWith('http')) {
    try {
      // Try to find the RPC endpoint in foundry config
      const configPath = path.join(homeDir, '.foundry', 'config.toml');
      const configExists = await fs.access(configPath).then(() => true).catch(() => false);
      
      if (configExists) {
        const configContent = await fs.readFile(configPath, 'utf8');
        const rpcMatch = new RegExp(`\\[rpc_endpoints\\][\\s\\S]*?${rpcUrl}\\s*=\\s*["']([^"']+)["']`).exec(configContent);
        
        if (rpcMatch && rpcMatch[1]) {
          return rpcMatch[1];
        }
      }
    } catch (error) {
      console.error("Error resolving RPC from config:", error);
    }
  }
  
  return rpcUrl;
}


async function getAnvilInfo(): Promise<{ running: boolean; port: string; url: string }> {
  try {
    const { stdout } = await execAsync('ps aux | grep anvil | grep -v grep');
    if (!stdout) {
      return { running: false, port: '', url: '' };
    }
    
    const portMatch = stdout.match(/--port\s+(\d+)/);
    const port = portMatch ? portMatch[1] : '8545';
    
    return {
      running: true,
      port,
      url: `http://localhost:${port}`
    };
  } catch (error) {
    return { running: false, port: '', url: '' };
  }
}

//===================================================================================================
// RESOURCES
//===================================================================================================

// Resource: Anvil status
server.resource(
  "anvil_status",
  new ResourceTemplate("anvil://status", { list: undefined }),
  anvilStatusHandler as ReadResourceTemplateCallback
);

function anvilStatusHandler(
  uri: URL,
  variables: Record<string, unknown>,
  extra: unknown,
  req: unknown,
  res: unknown,
  context: unknown,
  arg7: unknown,
  arg8: unknown,
  ...rest: unknown[]
) {
  const cb = rest[0] as (result: { contents: { type: "text"; text: string; uri: string; mimeType?: string }[] }) => void;
  getAnvilInfo().then(anvilInfo => {
    cb({
      contents: [{
        type: "text",
        text: anvilInfo.running
          ? `Anvil is running on port ${anvilInfo.port}. RPC URL: ${anvilInfo.url}`
          : "Anvil is not running.",
        uri: uri.toString(),
        mimeType: "text/plain"
      }]
    });
  });
}
 
// Resource: Contract source from Etherscan
server.resource(
  "contract_source",
  new ResourceTemplate("contract://{address}/source", { list: undefined }),
  async function contractSourceHandler(uri: URL, variables: Record<string, unknown>, extra: unknown): Promise<{ contents: ({ type: "text"; text: string; uri: string; mimeType?: string } | { type: "resource"; uri: string; blob: string; mimeType?: string })[] }> {
    try {
      const address = typeof variables.address === "string" ? variables.address : String(variables.address);
      const command = `${castPath} etherscan-source ${address}`;
      const { success, message } = await executeCommand(command);
      if (success) {
        return {
          contents: [
            {
              type: "text",
              text: message,
              uri: uri.toString(),
              mimeType: "text/plain"
            },
            {
              type: "resource",
              uri: uri.toString(),
              blob: message,
              mimeType: "text/plain"
            }
          ]
        };
      } else {
        return {
          contents: [{
            type: "text",
            text: JSON.stringify({ error: "Could not retrieve contract source", details: message }),
            uri: uri.toString(),
            mimeType: "text/plain"
          }]
        };
      }
    } catch {
      return {
        contents: [{
          type: "text",
          text: JSON.stringify({ error: "Failed to retrieve contract source" }),
          uri: uri.toString(),
          mimeType: "text/plain"
        }]
      };
    }
  }
);

//===================================================================================================
// CAST TOOLS
//===================================================================================================

// Tool: Call a contract function (read-only)
server.tool(
  "cast_call",
  "Call a contract function (read-only)",
  {
    contractAddress: z.string().describe("Address of the contract"),
    functionSignature: z.string().describe("Function signature (e.g., 'balanceOf(address)')"),
    args: z.array(z.string()).optional().describe("Function arguments"),
    rpcUrl: z.string().optional().describe("JSON-RPC URL (default: http://localhost:8545)"),
    blockNumber: z.string().optional().describe("Block number (e.g., 'latest', 'earliest', or a number)"),
    from: z.string().optional().describe("Address to perform the call as")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    const installed = await checkFoundryInstalled();
    const uri = "cast://call";
    if (!installed) {
      return {
        content: [{ type: "text", text: FOUNDRY_NOT_INSTALLED_ERROR, uri, mimeType: "text/plain" }],
        isError: true
      };
    }

    const resolvedRpcUrl = await resolveRpcUrl(args.rpcUrl);
    let command = `${castPath} call ${args.contractAddress} "${args.functionSignature}"`;
    
    if (args.args?.length && args.args.length > 0) {
      command += " " + (args.args?.join(" ") || "");
    }
    
    if (args.from) {
      command += ` --from ${args.from}`;
    }
    
    if (resolvedRpcUrl) {
      command += ` --rpc-url "${resolvedRpcUrl}"`;
    }
    
    if (args.blockNumber) {
      command += ` --block ${args.blockNumber}`;
    }
    
    const result = await executeCommand(command);
    
    let formattedOutput = result.message;
    if (result.success) {
      if (formattedOutput.includes('\n') && !formattedOutput.includes('Error')) {
        formattedOutput = formattedOutput.split('\n')
          .map(line => line.trim())
          .filter(line => line.length > 0)
          .join('\n');
      }
    }
    
    return {
      content: [{ 
        type: "text", 
        text: result.success 
          ? `Call to ${args.contractAddress}.${args.functionSignature.split('(')[0]} result:\n${formattedOutput}` 
          : `Call failed: ${result.message}` ,
        uri: uri,
        mimeType: "text/plain"
      }],
      isError: !result.success
    };
  }
);

// Tool: Send a transaction to a contract function
server.tool(
  "cast_send",
  "Send a transaction to a contract function",
  {
    contractAddress: z.string().describe("Address of the contract"),
    functionSignature: z.string().describe("Function signature (e.g., 'transfer(address,uint256)')"),
    args: z.array(z.string()).optional().describe("Function arguments"),
    from: z.string().optional().describe("Sender address or private key"),
    value: z.string().optional().describe("Ether value to send with the transaction (in wei)"),
    rpcUrl: z.string().optional().describe("JSON-RPC URL (default: http://localhost:8545)"),
    gasLimit: z.string().optional().describe("Gas limit for the transaction"),
    gasPrice: z.string().optional().describe("Gas price for the transaction (in wei)"),
    confirmations: z.number().optional().describe("Number of confirmations to wait for")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    const installed = await checkFoundryInstalled();
    const uri = "cast://send";
    if (!installed) {
      return {
        content: [{ type: "text", text: FOUNDRY_NOT_INSTALLED_ERROR, uri, mimeType: "text/plain" }],
        isError: true
      };
    }

    const resolvedRpcUrl = await resolveRpcUrl(args.rpcUrl);
    const privateKey = process.env.PRIVATE_KEY;
    let command = `${castPath} send ${args.contractAddress} "${args.functionSignature}" --private-key ${[privateKey]}`;
    
    if (args.args?.length && args.args.length > 0) {
      command += " " + (args.args?.join(" ") || "");
    }
    
    if (args.from) {
      command += ` --from ${args.from}`;
    }
    
    if (args.value) {
      command += ` --value ${args.value}`;
    }
    
    if (resolvedRpcUrl) {
      command += ` --rpc-url "${resolvedRpcUrl}"`;
    }
    
    if (args.gasLimit) {
      command += ` --gas-limit ${args.gasLimit}`;
    }
    
    if (args.gasPrice) {
      command += ` --gas-price ${args.gasPrice}`;
    }
    
    if (args.confirmations) {
      command += ` --confirmations ${args.confirmations}`;
    }
    
    const result = await executeCommand(command);
    
    return {
      content: [{ 
        type: "text", 
        text: result.success 
          ? `Transaction sent successfully:\n${result.message}` 
          : `Transaction failed: ${result.message}` ,
        uri: uri,
        mimeType: "text/plain"
      }],
      isError: !result.success
    };
  }
);

// Tool: Check the ETH balance of an address
server.tool(
  "cast_balance",
  "Check the ETH balance of an address",
  {
    address: z.string().describe("Ethereum address to check balance for"),
    rpcUrl: z.string().optional().describe("JSON-RPC URL (default: http://localhost:8545)"),
    blockNumber: z.string().optional().describe("Block number (e.g., 'latest', 'earliest', or a number)"),
    formatEther: z.boolean().optional().describe("Format the balance in Ether (default: wei)")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    const installed = await checkFoundryInstalled();
    const uri = "cast://balance";
    if (!installed) {
      return {
        content: [{ type: "text", text: FOUNDRY_NOT_INSTALLED_ERROR, uri, mimeType: "text/plain" }],
        isError: true
      };
    }

    const resolvedRpcUrl = await resolveRpcUrl(args.rpcUrl);
    let command = `${castPath} balance ${args.address}`;
    
    if (resolvedRpcUrl) {
      command += ` --rpc-url "${resolvedRpcUrl}"`;
    }
    
    if (args.blockNumber) {
      command += ` --block ${args.blockNumber}`;
    }
    
    if (args.formatEther) {
      command += " --ether";
    }
    
    const result = await executeCommand(command);
    const unit = args.formatEther ? "ETH" : "wei";
    
    return {
      content: [{ 
        type: "text", 
        text: result.success 
          ? `Balance of ${args.address}: ${result.message.trim()} ${unit}` 
          : `Failed to get balance: ${result.message}` ,
        uri: uri,
        mimeType: "text/plain"
      }],
      isError: !result.success
    };
  }
);

// Tool: Get transaction receipt
server.tool(
  "cast_receipt",
  "Get the transaction receipt",
  {
    txHash: z.string().describe("Transaction hash"),
    rpcUrl: z.string().optional().describe("JSON-RPC URL (default: http://localhost:8545)"),
    confirmations: z.number().optional().describe("Number of confirmations to wait for"),
    field: z.string().optional().describe("Specific field to extract (e.g., 'blockNumber', 'status')")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    const installed = await checkFoundryInstalled();
    const uri = "cast://receipt";
    if (!installed) {
      return {
        content: [{ type: "text", text: FOUNDRY_NOT_INSTALLED_ERROR, uri, mimeType: "text/plain" }],
        isError: true
      };
    }

    const resolvedRpcUrl = await resolveRpcUrl(args.rpcUrl);
    let command = `${castPath} receipt ${args.txHash}`;
    
    if (resolvedRpcUrl) {
      command += ` --rpc-url "${resolvedRpcUrl}"`;
    }
    
    if (args.confirmations) {
      command += ` --confirmations ${args.confirmations}`;
    }
    
    if (args.field) {
      command += ` ${args.field}`;
    }
    
    const result = await executeCommand(command);
    
    return {
      content: [{ 
        type: "text", 
        text: result.success 
          ? `Transaction receipt for ${args.txHash}${args.field ? ` (${args.field})` : ""}:\n${result.message}` 
          : `Failed to get receipt: ${result.message}` ,
        uri: uri,
        mimeType: "text/plain"
      }],
      isError: !result.success
    };
  }
);

// Tool: Read a contract's storage at a given slot
server.tool(
  "cast_storage",
  "Read contract storage at a specific slot",
  {
    address: z.string().describe("Contract address"),
    slot: z.string().describe("Storage slot to read"),
    rpcUrl: z.string().optional().describe("JSON-RPC URL (default: http://localhost:8545)"),
    blockNumber: z.string().optional().describe("Block number (e.g., 'latest', 'earliest', or a number)")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    const installed = await checkFoundryInstalled();
    const uri = "cast://storage";
    if (!installed) {
      return {
        content: [{ type: "text", text: FOUNDRY_NOT_INSTALLED_ERROR, uri, mimeType: "text/plain" }],
        isError: true
      };
    }

    const resolvedRpcUrl = await resolveRpcUrl(args.rpcUrl);
    let command = `${castPath} storage ${args.address} ${args.slot}`;
    
    if (resolvedRpcUrl) {
      command += ` --rpc-url "${resolvedRpcUrl}"`;
    }
    
    if (args.blockNumber) {
      command += ` --block ${args.blockNumber}`;
    }
    
    const result = await executeCommand(command);
    
    return {
      content: [{ 
        type: "text", 
        text: result.success 
          ? `Storage at ${args.address} slot ${args.slot}: ${result.message.trim()}` 
          : `Failed to read storage: ${result.message}` ,
        uri: uri,
        mimeType: "text/plain"
      }],
      isError: !result.success
    };
  }
);

// Tool: Run a published transaction in a local environment and print the trace
server.tool(
  "cast_run",
  "Runs a published transaction in a local environment and prints the trace",
  {
    txHash: z.string().describe("Transaction hash to replay"),
    rpcUrl: z.string().describe("JSON-RPC URL"),
    quick: z.boolean().optional().describe("Execute the transaction only with the state from the previous block"),
    debug: z.boolean().optional().describe("Open the transaction in the debugger"),
    labels: z.array(z.string()).optional().describe("Label addresses in the trace (format: <address>:<label>)")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    const installed = await checkFoundryInstalled();
    const uri = "cast://run";
    if (!installed) {
      return {
        content: [{ type: "text", text: FOUNDRY_NOT_INSTALLED_ERROR, uri, mimeType: "text/plain" }],
        isError: true
      };
    }

    const resolvedRpcUrl = await resolveRpcUrl(args.rpcUrl);
    let command = `${castPath} run ${args.txHash}`;
    
    if (resolvedRpcUrl) {
      command += ` --rpc-url "${resolvedRpcUrl}"`;
    }
    
    if (args.quick) {
      command += " --quick";
    }
    
    if (args.debug) {
      command += " --debug";
    }
    
    for (const label of args.labels || []) {
      command += ` --label ${label}`;
    }
    
    const result = await executeCommand(command);
    
    return {
      content: [{ 
        type: "text", 
        text: result.success 
          ? `Trace for transaction ${args.txHash}:\n${result.message}` 
          : `Trace failed: ${result.message}` ,
        uri: uri,
        mimeType: "text/plain"
      }],
      isError: !result.success
    };
  }
);

// Tool: Get logs by signature or topic
server.tool(
  "cast_logs",
  "Get logs by signature or topic",
  {
    signature: z.string().describe("Event signature (e.g., 'Transfer(address,address,uint256)') or topic 0 hash"),
    topics: z.array(z.string()).optional().describe("Additional topics (up to 3)"),
    address: z.string().optional().describe("Contract address to filter logs from"),
    fromBlock: z.string().optional().describe("Starting block number/tag"),
    toBlock: z.string().optional().describe("Ending block number/tag"),
    rpcUrl: z.string().optional().describe("JSON-RPC URL (default: http://localhost:8545)")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    const installed = await checkFoundryInstalled();
    const uri = "cast://logs";
    if (!installed) {
      return {
        content: [{ type: "text", text: FOUNDRY_NOT_INSTALLED_ERROR, uri, mimeType: "text/plain" }],
        isError: true
      };
    }

    const resolvedRpcUrl = await resolveRpcUrl(args.rpcUrl);
    let command = `${castPath} logs "${args.signature}"`;
    
    if (args.topics?.length && args.topics.length > 0) {
      command += " " + (args.topics?.join(" ") || "");
    }
    
    if (args.address) {
      command += ` --address ${args.address}`;
    }
    
    if (args.fromBlock) {
      command += ` --from-block ${args.fromBlock}`;
    }
    
    if (args.toBlock) {
      command += ` --to-block ${args.toBlock}`;
    }
    
    if (resolvedRpcUrl) {
      command += ` --rpc-url "${resolvedRpcUrl}"`;
    }
    
    const result = await executeCommand(command);
    
    return {
      content: [{ 
        type: "text", 
        text: result.success 
          ? `Logs for signature "${args.signature}":\n${result.message}` 
          : `Failed to get logs: ${result.message}` ,
        uri: uri,
        mimeType: "text/plain"
      }],
      isError: !result.success
    };
  }
);

// Tool: Lookup function or event signatures
server.tool(
  "cast_sig",
  "Get the selector for a function or event signature",
  {
    signature: z.string().describe("Function or event signature"),
    isEvent: z.boolean().optional().describe("Whether the signature is for an event (default: false)")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    const installed = await checkFoundryInstalled();
    const uri = "cast://sig";
    if (!installed) {
      return {
        content: [{ type: "text", text: FOUNDRY_NOT_INSTALLED_ERROR, uri, mimeType: "text/plain" }],
        isError: true
      };
    }

    const command = args.isEvent 
      ? `${castPath} sig-event "${args.signature}"` 
      : `${castPath} sig "${args.signature}"`;
    
    const result = await executeCommand(command);
    
    return {
      content: [{ 
        type: "text", 
        text: result.success 
          ? `Selector for ${args.isEvent ? "event" : "function"} "${args.signature}": ${result.message.trim()}` 
          : `Selector generation failed: ${result.message}` ,
        uri: uri,
        mimeType: "text/plain"
      }],
      isError: !result.success
    };
  }
);

// Tool: Get event or function signature using 4byte directory
server.tool(
  "cast_4byte",
  "Lookup function or event signature from the 4byte directory",
  {
    selector: z.string().describe("Function selector (0x + 4 bytes) or event topic (0x + 32 bytes)"),
    isEvent: z.boolean().optional().describe("Whether to lookup an event (default: false)")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    const installed = await checkFoundryInstalled();
    const uri = "cast://4byte";
    if (!installed) {
      return {
        content: [{ type: "text", text: FOUNDRY_NOT_INSTALLED_ERROR, uri, mimeType: "text/plain" }],
        isError: true
      };
    }

    const command = args.isEvent 
      ? `${castPath} 4byte-event ${args.selector}` 
      : `${castPath} 4byte ${args.selector}`;
    
    const result = await executeCommand(command);
    
    return {
      content: [{ 
        type: "text", 
        text: result.success 
          ? `Possible ${args.isEvent ? "event" : "function"} signatures for ${args.selector}:\n${result.message}` 
          : `Lookup failed: ${result.message}` ,
        uri: uri,
        mimeType: "text/plain"
      }],
      isError: !result.success
    };
  }
);

// Tool: Get chain information
server.tool(
  "cast_chain",
  "Get information about the current chain",
  {
    rpcUrl: z.string().optional().describe("JSON-RPC URL (default: http://localhost:8545)"),
    returnId: z.boolean().optional().describe("Return the chain ID instead of the name (default: false)")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    const installed = await checkFoundryInstalled();
    const uri = "cast://chain";
    if (!installed) {
      return {
        content: [{ type: "text", text: FOUNDRY_NOT_INSTALLED_ERROR, uri, mimeType: "text/plain" }],
        isError: true
      };
    }

    const resolvedRpcUrl = await resolveRpcUrl(args.rpcUrl);
    const command = args.returnId 
      ? `${castPath} chain-id --rpc-url "${resolvedRpcUrl}"` 
      : `${castPath} chain --rpc-url "${resolvedRpcUrl}"`;
    
    const result = await executeCommand(command);
    
    return {
      content: [{ 
        type: "text", 
        text: result.success 
          ? `Chain ${args.returnId ? "ID" : "name"}: ${result.message.trim()}` 
          : `Failed to get chain information: ${result.message}` ,
        uri: uri,
        mimeType: "text/plain"
      }],
      isError: !result.success
    };
  }
);

//===================================================================================================
// ANVIL TOOLS
//===================================================================================================

// Tool: Start a new Anvil instance
server.tool(
  "anvil_start",
  "Start a new Anvil instance (local Ethereum node)",
  {
    port: z.number().optional().describe("Port to listen on (default: 8545)"),
    blockTime: z.number().optional().describe("Block time in seconds (default: 0 - mine on demand)"),
    forkUrl: z.string().optional().describe("URL of the JSON-RPC endpoint to fork from"),
    forkBlockNumber: z.number().optional().describe("Block number to fork from"),
    accounts: z.number().optional().describe("Number of accounts to generate (default: 10)"),
    mnemonic: z.string().optional().describe("BIP39 mnemonic phrase to generate accounts from"),
    silent: z.boolean().optional().describe("Suppress anvil output (default: false)")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    const installed = await checkFoundryInstalled();
    const uri = "anvil://start";
    if (!installed) {
      return {
        content: [{ type: "text", text: FOUNDRY_NOT_INSTALLED_ERROR, uri, mimeType: "text/plain" }],
        isError: true
      };
    }

    // Check if anvil is already running
    const anvilInfo = await getAnvilInfo();
    if (anvilInfo.running) {
      return {
        content: [{ 
          type: "text", 
          text: `Anvil is already running on port ${anvilInfo.port}.` ,
          uri: uri,
          mimeType: "text/plain"
        }],
        isError: true
      };
    }

    let command = `${anvilPath} --port ${args.port || 8545}`;
    
    if (args.blockTime !== undefined) {
      command += ` --block-time ${args.blockTime}`;
    }
    
    if (args.forkUrl) {
      command += ` --fork-url "${args.forkUrl}"`;
      
      if (args.forkBlockNumber !== undefined) {
        command += ` --fork-block-number ${args.forkBlockNumber}`;
      }
    }
    
    if (args.accounts !== undefined) {
      command += ` --accounts ${args.accounts}`;
    }
    
    if (args.mnemonic) {
      command += ` --mnemonic "${args.mnemonic}"`;
    }
    
    try {
      // Start anvil in the background
      const child = exec(command, (error, stdout, stderr) => {
        if (error && !args.silent) {
          console.error(`Anvil error: ${error.message}`);
        }
        if (stderr && !args.silent) {
          console.error(`Anvil stderr: ${stderr}`);
        }
        if (stdout && !args.silent) {
          console.log(`Anvil stdout: ${stdout}`);
        }
      });
      
      // Give it a moment to start
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Check if it started successfully
      const newAnvilInfo = await getAnvilInfo();
      if (newAnvilInfo.running) {
        return {
          content: [{ 
            type: "text", 
            text: `Anvil started successfully on port ${args.port || 8545}. ` +
                  `RPC URL: http://localhost:${args.port || 8545}\n` +
                  `Process ID: ${child.pid}` ,
            uri: uri,
            mimeType: "text/plain"
          }],
          isError: false
        };
      } else {
        return {
          content: [{ 
            type: "text", 
            text: `Failed to start Anvil. Check system logs for details.` ,
            uri: uri,
            mimeType: "text/plain"
          }],
          isError: true
        };
      }
    } catch (error) {
      return {
        content: [{ 
          type: "text", 
          text: `Error starting Anvil: ${error instanceof Error ? error.message : String(error)}` ,
          uri: uri,
          mimeType: "text/plain"
        }],
        isError: true
      };
    }
  }
);

// Tool: Stop an Anvil instance
server.tool(
  "anvil_stop",
  "Stop a running Anvil instance",
  {},
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    const anvilInfo = await getAnvilInfo();
    const uri = "anvil://stop";
    if (!anvilInfo.running) {
      return {
        content: [{ 
          type: "text", 
          text: "No Anvil instance is currently running." ,
          uri: uri,
          mimeType: "text/plain"
        }],
        isError: true
      };
    }

    try {
      // Kill the anvil process
      if (os.platform() === 'win32') {
        await execAsync('taskkill /F /IM anvil.exe');
      } else {
        await execAsync('pkill -f anvil');
      }
      
      // Check if it was stopped successfully
      await new Promise(resolve => setTimeout(resolve, 500));
      const newAnvilInfo = await getAnvilInfo();
      
      if (!newAnvilInfo.running) {
        return {
          content: [{ 
            type: "text", 
            text: "Anvil has been stopped successfully." ,
            uri: uri,
            mimeType: "text/plain"
          }],
          isError: false
        };
      } else {
        return {
          content: [{ 
            type: "text", 
            text: "Failed to stop Anvil. It may still be running." ,
            uri: uri,
            mimeType: "text/plain"
          }],
          isError: true
        };
      }
    } catch (error) {
      return {
        content: [{ 
          type: "text", 
          text: `Error stopping Anvil: ${error instanceof Error ? error.message : String(error)}` ,
          uri: uri,
          mimeType: "text/plain"
        }],
        isError: true
      };
    }
  }
);

// Tool: Get current Anvil status
server.tool(
  "anvil_status",
  "Check if Anvil is running and get its status",
  {},
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    const anvilInfo = await getAnvilInfo();
    const uri = "anvil://status";
    
    return {
      content: [{ 
        type: "text", 
        text: anvilInfo.running
          ? `Anvil is running on port ${anvilInfo.port}. RPC URL: ${anvilInfo.url}` 
          : "Anvil is not currently running." ,
        uri: uri,
        mimeType: "text/plain"
      }],
      isError: false
    };
  }
);

// Tool: Run Forge scripts
server.tool(
  "forge_script",
  "Run a Forge script from the workspace",
  {
    scriptPath: z.string().describe("Path to the script file (e.g., 'script/Deploy.s.sol')"),
    sig: z.string().optional().describe("Function signature to call (default: 'run()')"),
    rpcUrl: z.string().optional().describe("JSON-RPC URL (default: http://localhost:8545)"),
    broadcast: z.boolean().optional().describe("Broadcast the transactions"),
    verify: z.boolean().optional().describe("Verify the contract on Etherscan (needs API key)")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    const installed = await checkFoundryInstalled();
    const uri = "forge://script";
    if (!installed) {
      return {
        content: [{ type: "text", text: FOUNDRY_NOT_INSTALLED_ERROR, uri, mimeType: "text/plain" }],
        isError: true
      };
    }

    try {
      const workspace = await ensureWorkspaceInitialized();
      
      // Check if script exists
      const scriptFullPath = path.join(workspace, args.scriptPath);
      const scriptExists = await fs.access(scriptFullPath).then(() => true).catch(() => false);
      if (!scriptExists) {
        return {
          content: [{ 
            type: "text", 
            text: `Script does not exist at ${scriptFullPath}` ,
            uri: uri,
            mimeType: "text/plain"
          }],
          isError: true
        };
      }

      const resolvedRpcUrl = await resolveRpcUrl(args.rpcUrl);
      let command = `cd ${workspace} && ${forgePath} script ${args.scriptPath} --sig "${args.sig || 'run()'}"`;
      
      if (resolvedRpcUrl) {
        command += ` --rpc-url "${resolvedRpcUrl}"`;
      }
      
      if (args.broadcast) {
        command += ` --broadcast`;
      }
      
      if (args.verify) {
        command += ` --verify`;
      }
      
      const result = await executeCommand(command);
      
      return {
        content: [{ 
          type: "text", 
          text: result.success 
            ? `Script executed successfully:\n${result.message}` 
            : `Script execution failed: ${result.message}` ,
          uri: uri,
          mimeType: "text/plain"
        }],
        isError: !result.success
      };
    } catch (error) {
      return {
        content: [{ 
          type: "text", 
          text: `Error executing script: ${error instanceof Error ? error.message : String(error)}` ,
          uri: uri,
          mimeType: "text/plain"
        }],
        isError: true
      };
    }
  }
);
 

//===================================================================================================
// UTILITY TOOLS
//===================================================================================================

// Tool: Convert between units (wei, gwei, ether)
server.tool(
  "convert_eth_units",
  "Convert between Ethereum units (wei, gwei, ether)",
  {
    value: z.string().describe("Value to convert"),
    fromUnit: z.enum(["wei", "gwei", "ether"]).describe("Source unit"),
    toUnit: z.enum(["wei", "gwei", "ether"]).describe("Target unit")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    const installed = await checkFoundryInstalled();
    const uri = "convert://eth-units";
    if (!installed) {
      return {
        content: [{ type: "text", text: FOUNDRY_NOT_INSTALLED_ERROR, uri, mimeType: "text/plain" }],
        isError: true
      };
    }

    const command = `${castPath} to-unit ${args.value}${args.fromUnit} ${args.toUnit}`;
    const result = await executeCommand(command);
    
    return {
      content: [{ 
        type: "text", 
        text: result.success 
          ? `${args.value} ${args.fromUnit} = ${result.message.trim()} ${args.toUnit}` 
          : `Conversion failed: ${result.message}` ,
        uri: uri,
        mimeType: "text/plain"
      }],
      isError: !result.success
    };
  }
);

// Tool: Calculate contract address
server.tool(
  "compute_address",
  "Compute the address of a contract that would be deployed by a specific address",
  {
    deployerAddress: z.string().describe("Address of the deployer"),
    nonce: z.string().optional().describe("Nonce of the transaction (default: current nonce)"),
    rpcUrl: z.string().optional().describe("JSON-RPC URL (default: http://localhost:8545)")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    const installed = await checkFoundryInstalled();
    const uri = "compute://address";
    if (!installed) {
      return {
        content: [{ type: "text", text: FOUNDRY_NOT_INSTALLED_ERROR, uri, mimeType: "text/plain" }],
        isError: true
      };
    }

    const resolvedRpcUrl = await resolveRpcUrl(args.rpcUrl);
    let command = `${castPath} compute-address ${args.deployerAddress}`;
    
    if (args.nonce) {
      command += ` --nonce ${args.nonce}`;
    }
    
    if (resolvedRpcUrl) {
      command += ` --rpc-url "${resolvedRpcUrl}"`;
    }
    
    const result = await executeCommand(command);
    
    return {
      content: [{ 
        type: "text", 
        text: result.success 
          ? `Computed contract address:\n${result.message}` 
          : `Address computation failed: ${result.message}` ,
        uri: uri,
        mimeType: "text/plain"
      }],
      isError: !result.success
    };
  }
);

// Tool: Get contract bytecode size
server.tool(
  "contract_size",
  "Get the bytecode size of a deployed contract",
  {
    address: z.string().describe("Contract address"),
    rpcUrl: z.string().optional().describe("JSON-RPC URL (default: http://localhost:8545)")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    const installed = await checkFoundryInstalled();
    const uri = "contract://size";
    if (!installed) {
      return {
        content: [{ type: "text", text: FOUNDRY_NOT_INSTALLED_ERROR, uri, mimeType: "text/plain" }],
        isError: true
      };
    }

    const resolvedRpcUrl = await resolveRpcUrl(args.rpcUrl);
    let command = `${castPath} codesize ${args.address}`;
    
    if (resolvedRpcUrl) {
      command += ` --rpc-url "${resolvedRpcUrl}"`;
    }
    
    const result = await executeCommand(command);
    const bytes = parseInt(result.message);
    let sizeInfo = "";
    if (!isNaN(bytes)) {
      const kilobytes = bytes / 1024;
      const contractLimit = 24576; // 24KB limit for contracts
      const percentOfLimit = (bytes / contractLimit) * 100;
      
      sizeInfo = `\n\n${bytes} bytes (${kilobytes.toFixed(2)} KB)\n` +
                 `EVM Contract Size Limit: 24KB (24576 bytes)\n` +
                 `Current size is ${percentOfLimit.toFixed(2)}% of the maximum`;
    }
    
    return {
      content: [{ 
        type: "text", 
        text: result.success 
          ? `Contract bytecode size for ${args.address}:${sizeInfo}` 
          : `Failed to get contract size: ${result.message}` ,
        uri: uri,
        mimeType: "text/plain"
      }],
      isError: !result.success
    };
  }
);

// server.tool(
//   "estimate_gas",
//   "Estimate the gas cost of a transaction",
//   {
//     to: z.string().describe("Recipient address"),
//     functionSignature: z.string().describe("Function signature (e.g., 'transfer(address,uint256)')"),
//     args: z.array(z.string()).optional().describe("Function arguments"),
//     value: z.string().optional().describe("Ether value to send with the transaction (in wei)"),
//     rpcUrl: z.string().optional().describe("JSON-RPC URL (default: http://localhost:8545)")
//   },
//   async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
//     const installed = await checkFoundryInstalled();
//     const uri = "estimate://gas";
//     if (!installed) {
//       return {
//         content: [{ type: "text", text: FOUNDRY_NOT_INSTALLED_ERROR, uri, mimeType: "text/plain" }],
//         isError: true
//       };
//     }

//     const resolvedRpcUrl = await resolveRpcUrl(args.rpcUrl);
//     let command = `${castPath} estimate ${args.to} "${args.functionSignature}"`;
    
//     if (args.args?.length && args.args.length > 0) {
//       command += " " + (args.args?.join(" ") || "");
//     }
    
//     if (args.value) {
//       command += ` --value ${args.value}`;
//     }
    
//     if (resolvedRpcUrl) {
//       command += ` --rpc-url "${resolvedRpcUrl}"`;
//     }
    
//     const result = await executeCommand(command);
//     const gasEstimate = result.message.trim();
    
//     // Get current gas price to calculate cost in ETH
//     let gasPriceInfo = "";
//     try {
//       const gasPriceCommand = `${castPath} gas-price --rpc-url "${resolvedRpcUrl}"`;
//       const gasPriceResult = await executeCommand(gasPriceCommand);
//       if (gasPriceResult.success) {
//         const gasPrice = gasPriceResult.message.trim();
//         const cost = BigInt(gasEstimate) * BigInt(gasPrice);
        
//         // Convert wei to ETH
//         const ethCommand = `${castPath} from-wei ${cost}`;
//         const ethResult = await executeCommand(ethCommand);
//         if (ethResult.success) {
//           gasPriceInfo = `\nGas Price: ${gasPrice} wei\nEstimated Cost: ${ethResult.message.trim()} ETH`;
//         }
//       }
//     } catch (error) {
//       console.error("Error getting gas price:", error);
//     }
    
//     return {
//       content: [{ 
//         type: "text", 
//         text: result.success 
//           ? `Estimated gas for calling ${args.functionSignature} on ${args.to}: ${gasEstimate} gas units${gasPriceInfo}` 
//           : `Gas estimation failed: ${result.message}` ,
//         uri: uri,
//         mimeType: "text/plain"
//       }],
//       isError: !result.success
//     };
//   }
// );

// Tool: Create or update a Solidity file (contract, script, etc.)
server.tool(
  "create_solidity_file",
  "Create or update a Solidity file in the workspace",
  {
    filePath: z.string().describe("Path to the file (e.g., 'src/MyContract.sol' or 'script/Deploy.s.sol')"),
    content: z.string().describe("File content"),
    overwrite: z.boolean().optional().describe("Overwrite existing file (default: false)")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    try {
      const workspace = await ensureWorkspaceInitialized();
      const fullFilePath = path.join(workspace, args.filePath);
      
      const fileExists = await fs.access(fullFilePath).then(() => true).catch(() => false);
      if (fileExists && !args.overwrite) {
        return {
          content: [{ 
            type: "text", 
            text: `File already exists at ${fullFilePath}. Use overwrite=true to replace it.` ,
            uri: "create://solidity-file",
            mimeType: "text/plain"
          }],
          isError: true
        };
      }
      
      await fs.mkdir(path.dirname(fullFilePath), { recursive: true });
      
      await fs.writeFile(fullFilePath, args.content);
      
      return {
        content: [{ 
          type: "text", 
          text: `File ${fileExists ? 'updated' : 'created'} successfully at ${fullFilePath}` ,
          uri: "create://solidity-file",
          mimeType: "text/plain"
        }],
        isError: false
      };
    } catch (error) {
      return {
        content: [{ 
          type: "text", 
          text: `Error managing file: ${error instanceof Error ? error.message : String(error)}` ,
          uri: "create://solidity-file",
          mimeType: "text/plain"
        }],
        isError: true
      };
    }
  }
);

// Tool: Install dependencies for the workspace
server.tool(
  "install_dependency",
  "Install a dependency for the Forge workspace",
  {
    dependency: z.string().describe("GitHub repository to install (e.g., 'OpenZeppelin/openzeppelin-contracts')"),
    version: z.string().optional().describe("Version tag or branch to install (default: latest)")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    const installed = await checkFoundryInstalled();
    const uri = "install://dependency";
    if (!installed) {
      return {
        content: [{ type: "text", text: FOUNDRY_NOT_INSTALLED_ERROR, uri, mimeType: "text/plain" }],
        isError: true
      };
    }

    try {
       const workspace = await ensureWorkspaceInitialized();
      
       let command = `cd ${workspace} && ${forgePath} install ${args.dependency} --no-commit`;
      if (args.version) {
        command += ` --tag ${args.version}`;
      }
      
      const result = await executeCommand(command);
      
      return {
        content: [{ 
          type: "text", 
          text: result.success 
            ? `Dependency installed successfully:\n${result.message}` 
            : `Failed to install dependency: ${result.message}` ,
          uri: uri,
          mimeType: "text/plain"
        }],
        isError: !result.success
      };
    } catch (error) {
      return {
        content: [{ 
          type: "text", 
          text: `Error installing dependency: ${error instanceof Error ? error.message : String(error)}` ,
          uri: uri,
          mimeType: "text/plain"
        }],
        isError: true
      };
    }
  }
);

// Tool: List files in the workspace
server.tool(
  "list_files",
  "List files in the workspace",
  {
    directory: z.string().optional().describe("Directory to list (e.g., 'src' or 'script'), defaults to root")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    try {
       const workspace = await ensureWorkspaceInitialized();
      const dirPath = path.join(workspace, args.directory || '');
      
       const dirExists = await fs.access(dirPath).then(() => true).catch(() => false);
      if (!dirExists) {
        return {
          content: [{ 
            type: "text", 
            text: `Directory '${args.directory}' does not exist in the workspace` ,
            uri: "list://files",
            mimeType: "text/plain"
          }],
          isError: true
        };
      }
      
       async function listFiles(dir: string, baseDir: string = ""): Promise<string[]> {
        const entries = await fs.readdir(dir, { withFileTypes: true });
        let files: string[] = [];
        
        for (const entry of entries) {
          const relativePath = path.join(baseDir, entry.name);
          if (entry.isDirectory()) {
            const subFiles: string[] = await listFiles(path.join(dir, entry.name), relativePath);
            files = [...files, ...subFiles];
          } else {
            files.push(relativePath);
          }
        }
        
        return files;
      }
      
      const files = await listFiles(dirPath);
      return {
        content: [{ 
          type: "text", 
          text: files.length > 0
            ? `Files in ${args.directory || 'workspace'}:\n\n${files.join('\n')}`
            : `No files found in ${args.directory || 'workspace'}` ,
          uri: "list://files",
          mimeType: "text/plain"
        }],
        isError: false
      };
    } catch (error) {
      return {
        content: [{ 
          type: "text", 
          text: `Error listing files: ${error instanceof Error ? error.message : String(error)}` ,
          uri: "list://files",
          mimeType: "text/plain"
        }],
        isError: true
      };
    }
  }
);

// Tool: Read a file from the workspace
server.tool(
  "read_file",
  "Read the content of a file from the workspace",
  {
    filePath: z.string().describe("Path to the file (e.g., 'src/MyContract.sol')")
  },
  async (args, extra): Promise<{ content: { type: "text"; text: string; uri: string; mimeType?: string }[]; isError: boolean }> => {
    try {
      const workspace = await ensureWorkspaceInitialized();
      const fullFilePath = path.join(workspace, args.filePath);
      
       const fileExists = await fs.access(fullFilePath).then(() => true).catch(() => false);
      if (!fileExists) {
        return {
          content: [{ 
            type: "text", 
            text: `File does not exist at ${fullFilePath}` ,
            uri: "read://file",
            mimeType: "text/plain"
          }],
          isError: true
        };
      }
      
      const content = await fs.readFile(fullFilePath, 'utf8');
      
      return {
        content: [{ 
          type: "text", 
          text: `Content of ${args.filePath}:\n\n${content}` ,
          uri: "read://file",
          mimeType: "text/plain"
        }],
        isError: false
      };
    } catch (error) {
      return {
        content: [{ 
          type: "text", 
          text: `Error reading file: ${error instanceof Error ? error.message : String(error)}` ,
          uri: "read://file",
          mimeType: "text/plain"
        }],
        isError: true
      };
    }
  }
);

async function startServer(): Promise<void> {
  const foundryInstalled = await checkFoundryInstalled();
  if (!foundryInstalled) {
    console.error("Error: Foundry is not installed");
    process.exit(1);
  }

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Foundry MCP Server started on stdio");
}

startServer().catch((error) => {
  console.error("Error starting server:", error);
  process.exit(1);
});
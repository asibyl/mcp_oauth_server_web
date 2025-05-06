import express, { Request, Response } from 'express';
import cors from 'cors';
import { randomUUID } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { createServer } from './streamableHTTP_server.js'; 
import { GitHubServerAuthProvider } from './auth/GHAuthProvider.js';
import { githubAuthRouter } from './auth/GHAuthRouter.js';
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { InMemoryEventStore } from '@modelcontextprotocol/sdk/examples/shared/inMemoryEventStore.js';


// Create an MCP server with implementation details
const server = createServer();

// Initialize the GitHub server auth provider
const provider = new GitHubServerAuthProvider();

const app = express();
app.use(express.json());

app.use(cors());

app.use((req, res, next) => {
  res.header("Access-Control-Expose-Headers", "mcp-session-id");
  next();
});

const webAppTransports: Map<string, Transport> = new Map<string, Transport>(); // Transports by sessionId

// Mount the GitHub auth router (this will add registration and other OAuth endpoints)
app.use('/', githubAuthRouter({
    provider: provider,
    issuerUrl: new URL('http://localhost:3001'),
    serviceDocumentationUrl: new URL('https://example.com'),
    authorizationOptions: {},
    tokenOptions: {}
}));

// Map to store transports by session ID
const wTransports: { [sessionId: string]: StreamableHTTPServerTransport } = {};


// Modern Streamable HTTP endpoint: Handle MCP requests
app.post('/mcp', 
  requireBearerAuth({ provider, requiredScopes: ["read:user", "user:email"]}),
  async (req: Request, res: Response) => {
    try {
      const sessionId = req.headers['mcp-session-id'] as string | undefined;
      console.log("Received POST request for session ID:", sessionId)
      console.log("Request Body:", req.body)

      let transport: StreamableHTTPServerTransport;
      if(sessionId && webAppTransports[sessionId]) { transport = webAppTransports[sessionId] }
      else if (!sessionId && isInitializeRequest(req.body)) {
        const eventStore = new InMemoryEventStore()
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(), // here we generate a new session ID!!
          eventStore,
          onsessioninitialized: (sessionId) => {
            webAppTransports[sessionId] = transport
            console.log("New session initialized with session ID:", sessionId)
          }
        })
      
        // Set up onclose handler to clean up transport when closed
        transport.onclose = () => {
          const sid = transport.sessionId;
          if (sid && webAppTransports[sid]) {
            delete webAppTransports[sid];
          }
        };

        await server.connect(transport)
        await transport.handleRequest(req, res, req.body)
        return
      } else {
        // Invalid request - no session ID or not initialization request
        res.status(400).json({
          jsonrpc: '2.0',
          error: {
            code: -32000,
            message: 'Bad Request: No valid session ID provided',
          },
          id: null,
        });
        return;
      }
      await transport.handleRequest(req, res, req.body); 
      return
    } catch (error) {
        console.error('Error handling MCP request:', error);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: {
              code: -32603,
              message: 'Internal server error',
            },
            id: null,
          });
        }
    }
});

// GET requests to /mcp
app.get('/mcp', 
  requireBearerAuth({ provider, requiredScopes: ["read:user", "user:email"]}),
  async (req: Request, res: Response) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;

    try {
      if(!sessionId) {
        throw new Error("Missing session ID")
      }    
      const transport = webAppTransports[sessionId];
      if(!transport) {
        res.status(404).end("Session not found")
        return
      } else {
        transport.handleRequest(req, res)
      }
    } catch (error) {
      console.error("Error in GET /mcp route:", error);
      res.status(500).json(error);
    }
});

// Legacy SSE for older clients: Handle GET requests for SSE streams (using built-in support from StreamableHTTP)
app.get('/sse', 
  requireBearerAuth({ provider, requiredScopes: ["read:user", "user:email"]}),
  async (req: Request, res: Response) => {
  try {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;

    if(!sessionId) {
      throw new Error("Missing session ID")
    }   
    const transport = new SSEServerTransport("/message", res)
    webAppTransports.set(transport.sessionId, transport)
    console.log("Created SSE web app transport")


  } catch (error) {
    console.error("Error in GET /sse route:", error)
    res.status(500).json(error)
  }
});

app.post("/message", 
  requireBearerAuth({ provider, requiredScopes: ["read:user", "user:email"]}),
  async (req, res) => {
  try {
    const sessionId = req.query.sessionId as string | undefined;
    console.log(`Received message for sessionId ${sessionId}`);

    if(!sessionId) {
      throw new Error("Missing session ID")
    }

    const transport = webAppTransports[sessionId] as SSEServerTransport;
    if (!transport) {
      res.status(404).end("Session not found");
      return;
    }
    await transport.handlePostMessage(req, res);
  } catch (error) {
    console.error("Error in POST /message route:", error);
    res.status(500).json(error);
  }
});

// redirect destination from GitHub after user approves
app.get('/auth/callback', (req: Request, res: Response) => {
  const { code, state } = req.query;

  if (!code || !state || typeof code !== 'string' || typeof state !== 'string') {
    return res.status(400).send('Missing or invalid code or state');
  }

  provider.handleCallback(code, state)
    .then( (result) => {
      // result will include authorization code in redirect url, client must exchange this for it's own access token 
      if (result.success) { 
        console.log('Redirecting to client:', result.redirectUrl);
        res.redirect(result.redirectUrl)
      }
      else { res.status(400).send(result.error || 'Unknown error')}
    })
});

// Start the server
const PORT = 3001;
app.listen(PORT, () => {
  console.log(`MCP Streamable HTTP Server listening on port ${PORT}`);
});



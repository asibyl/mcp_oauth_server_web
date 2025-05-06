# Implementing Streamable HTTP MCP Server with Browser-based OAuth

## Overview

The purpose of this project is to support MCP Client requested authorization through the MCP Server. This requires implementing a custom OAuthProvider for GitHub. 

As such, this project provides:
1. An StreamableHTTP Server 
2. Browser-based client authorization using GitHub's OAuth
3. Handling authorized client requests
  

### High-level Execution Flow

The flow proceeds as follows:
1. The client sends POST request to /mcp endpoint. 
2. The server verifies the access token included in the Authorization header. If it's expired (or not recognized), server returns an error. If the access token is valid, the server proceeds to the next step. 
3. If the client request contains a valid sessionId, the server uses an existing transport connection. If not, it creates a transport connection with a new sessionId. The server uses the transport connection to handle the request. 

### Authorization

The server receives client requests for authorization through the `/authorize` and `/token` endpoints. These are supported through a class that implements the OAuthServerProvider.  

For requests to the `/authorize` endpoint, the server auth provider:
1. Generates the PKCE verifier and challenge
2. Redirects to the GitHub OAuth endpoint (GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET env variables must be set)
3. As part of the callback, 
    - uses the code returned in callback to fetche its access token from GitHub 
    - stores this access token along with the clientId
    - generates a new auth code and returns this to the client

When the client hits the `/token` endpoint with this auth code, the server provides the client it's own access token. 

## How to use

1. Clone this repository
2. Install the dependencies `npm install`
3. Go to your Developer Settings on GitHub (under Settings) and create an OAuth app. Note the Client ID and Client Secret.
4. Set the GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET environment variables in your local dev environment.
5. Start the MCP Server `npx tsx server/index_streamable.ts`







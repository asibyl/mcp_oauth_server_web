import { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import { AuthorizationParams, OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { OAuthClientInformationFull, OAuthTokens, OAuthTokenRevocationRequest } from "@modelcontextprotocol/sdk/shared/auth.js";
import { Response } from "express";
import fs from 'fs/promises';
import path from 'path';
import dotenv from 'dotenv';    
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';
import { tokenStore } from './TokenStore.js';
import { SessionData } from './SessionData.js';
import { ClientWithVerifier } from './ClientWithVerifier.js';
import { existsSync, mkdirSync } from 'fs';

const currentDir = path.dirname(new URL(import.meta.url).pathname);
const DEFAULT_CLIENTS_FILE = path.join(currentDir, '.auth/registered_clients.json');

export class GitHubServerAuthProvider implements OAuthServerProvider {
    private _clientsMap: Map<string, OAuthClientInformationFull> = new Map();
    private _clientsStoreImpl: OAuthRegisteredClientsStore;
    private _clientsFilePath: string;
    private _sessionStore: Map<string, SessionData> = new Map();
    private _tempAuthCodes: Map<string, { sessionToken: string, expires: number }> = new Map();

    constructor() {
        dotenv.config();

        // Check if the environment variables are set
        const requiredEnvVars = ['GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET'];
        const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
        if (missingEnvVars.length > 0) {
            throw new Error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
        }

        this._clientsFilePath = path.resolve(process.cwd(), DEFAULT_CLIENTS_FILE);

        // Ensure .auth directory exists
        const authDir = path.dirname(this._clientsFilePath);
        if (!existsSync(authDir)) {
            mkdirSync(authDir, { recursive: true });
        }

        this._clientsStoreImpl = {
            getClient: (clientId: string) => {
                return this._clientsMap.get(clientId);
            },

            registerClient: (client: OAuthClientInformationFull) => {
                this._clientsMap.set(client.client_id, client);
 
                this._saveClientsToFile().catch(err => {
                    console.error("Failed to save client registration:", err);
                });
                return client;
            }
        };

        this._loadClientsFromFile().catch(err => {
            console.error("Failed to load registered clients:", err);
        });

        setInterval(() => {
            tokenStore.cleanExpiredTokens();
        }, 60000);
    }

    private generatePkce(): { verifier: string, challenge: string } {
        const verifier = uuidv4() + uuidv4() + uuidv4();
        const challenge = crypto.createHash('sha256')
            .update(verifier)
            .digest('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');

        return { verifier, challenge };
    }

    private async _storeSessionData(state: string, data: SessionData): Promise<void> {
        if (!state) {
            throw new Error("Cannot store session data: state parameter is missing");
        }

        this._sessionStore.set(state, data);
    }

    private _getSessionData(state: string): SessionData | undefined {
        return this._sessionStore.get(state);
    }

    private _clearSessionData(state: string): void {
        this._sessionStore.delete(state);
    }

    private async _loadClientsFromFile(): Promise<void> {
        try {
            await fs.access(this._clientsFilePath)
                .catch(() => {
                    console.log("No saved clients found. Starting with empty clients list.");
                    return Promise.reject(new Error("File not found"));
                });

            const fileContent = await fs.readFile(this._clientsFilePath, { encoding: 'utf8' });
            const clientsData = JSON.parse(fileContent);

            this._clientsMap.clear();
            for (const [clientId, clientData] of Object.entries(clientsData)) {
                this._clientsMap.set(clientId, clientData as OAuthClientInformationFull);
            }

            console.log(`Loaded ${this._clientsMap.size} registered clients from file.`);
        } catch (err) {
            if ((err as Error).message !== "File not found") {
                console.error("Error loading clients from file:", err);
            }
        }
    }

    private async _saveClientsToFile(): Promise<void> {
        try {
            const clientsObject: Record<string, OAuthClientInformationFull> = {};
            for (const [clientId, clientData] of this._clientsMap.entries()) {
                clientsObject[clientId] = clientData;
            }

            await fs.writeFile(
                this._clientsFilePath,
                JSON.stringify(clientsObject, null, 2),
                { encoding: 'utf8' }
            );

            console.log(`Saved ${this._clientsMap.size} registered clients to file.`);
        } catch (err) {
            console.error("Error saving clients to file:", err);
            throw err;
        }
    }

    get clientsStore(): OAuthRegisteredClientsStore {
        return this._clientsStoreImpl;
    }

    // required method for OAuthServerProvider
    // routed through /authorize
    async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
        console.log("Authorizing client: ", client.client_id);

        try {
            const redirectUri = client.redirect_uris[0] as string;

            // Generate PKCE values
            const pkce = this.generatePkce();
            
            // Generate state parameter
            const state = crypto.randomBytes(32).toString('hex');

            // Store session data
            const sessionData: SessionData = {
                clientId: client.client_id,
                state: state,
                codeVerifier: pkce.verifier,
                redirectUri: redirectUri,
                originalState: params.state as string,
                clientCodeChallenge: params.codeChallenge as string,
                clientCodeChallengeMethod: 'S256'
            };

            await this._storeSessionData(state, sessionData);

            // Redirect to GitHub OAuth
            const githubAuthUrl = new URL('https://github.com/login/oauth/authorize');
            githubAuthUrl.searchParams.append('client_id', process.env.GITHUB_CLIENT_ID!);
            githubAuthUrl.searchParams.append('redirect_uri', 'http://localhost:3001/auth/callback');
            githubAuthUrl.searchParams.append('state', state);
            githubAuthUrl.searchParams.append('scope', 'read:user user:email');

            console.log("Redirecting to Github to authorize client")
            res.redirect(githubAuthUrl.toString());
        } catch (error) {
            console.error("Error in authorization set up:", error);
            res.status(500).send("Failed to initialize authentication: " + error);
        }
    }

    // required method for OAuthServerProvider
    async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
        try {
            const tempCodeData = this._tempAuthCodes.get(authorizationCode);
            if (!tempCodeData || tempCodeData.expires < Date.now()) {
                this._tempAuthCodes.delete(authorizationCode);
                throw new Error("Invalid or expired authorization code");
            }

            const sessionToken = tempCodeData.sessionToken;
            const storedToken = tokenStore.getToken(sessionToken);

            if (!storedToken) {
                throw new Error("Invalid session token");
            }

            return storedToken.clientCodeChallenge || '';
        } catch (error) {
            console.error("Error retrieving code challenge:", error);
            throw new Error(`Failed to get code challenge: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    // required method for OAuthServerProvider
    async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string, scopes?: string[]): Promise<OAuthTokens> {
        throw new Error("Refresh token exchange not implemented");
    }

    // required method for OAuthServerProvider
    // called when bearer token auth is required
    async verifyAccessToken(token: string): Promise<AuthInfo> {
        const storedToken = tokenStore.getToken(token);

        if (!storedToken) {
            throw new Error("Invalid or expired token");
        }

        if (storedToken.expiresAt < Date.now()) {
            tokenStore.removeToken(token);
            throw new Error("Token has expired");
        }

        return {
            token: token,
            clientId: storedToken.clientId,
            scopes: storedToken.scopes,
            expiresAt: storedToken.expiresAt
        };
    }

    // required method for OAuthServerProvider 
    async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
        throw new Error("Token revocation not implemented");
    }

    // required method for OAuthServerProvider
    // (likely) routed through /token
    // called by client to exchange its code for its own access token (in this case the session token)
    async exchangeAuthorizationCode(client: ClientWithVerifier, authorizationCode: string): Promise<OAuthTokens> {
        try {
            const tempCodeData = this._tempAuthCodes.get(authorizationCode);
            if (!tempCodeData || tempCodeData.expires < Date.now()) {
                this._tempAuthCodes.delete(authorizationCode);
                throw new Error("Invalid or expired authorization code");
            }

            this._tempAuthCodes.delete(authorizationCode);

            const sessionToken = tempCodeData.sessionToken;
            const storedToken = tokenStore.getToken(sessionToken);

            if (!storedToken) {
                throw new Error("Invalid session token");
            }

            return {
                access_token: sessionToken,
                token_type: "Bearer",
                expires_in: Math.floor((storedToken.expiresAt - Date.now()) / 1000),
                refresh_token: crypto.randomBytes(32).toString('hex'),
                scope: storedToken.scopes.join(' ')
            };
        } catch (error) {
            throw new Error(`Failed to exchange authorization code: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    // called after user approves auth (from /auth/callback), exchanges code for access token, validates the access token
    // return different auth code to client, sent back via client redirect url
    public async handleCallback(code: string, state: string): Promise<{
        redirectUrl: string;
        success: boolean;
        error?: string;
    }> {
        try {
            const sessionData = this._getSessionData(state);
            if (!sessionData) {
                return { redirectUrl: '', success: false, error: "Invalid state parameter" };
            }

            // Exchange code for GitHub token using fetch
            const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    client_id: process.env.GITHUB_CLIENT_ID,
                    client_secret: process.env.GITHUB_CLIENT_SECRET,
                    code: code,
                    redirect_uri: 'http://localhost:3001/auth/callback'
                })
            });

            if (!tokenResponse.ok) {
                throw new Error(`GitHub token exchange failed: ${tokenResponse.status} ${tokenResponse.statusText}`);
            }

            const tokenData = await tokenResponse.json();
            const accessToken = tokenData.access_token;
            
            if (!accessToken) {
                throw new Error("Failed to obtain GitHub access token");
            }

            // Get user data from GitHub using fetch
            const userResponse = await fetch('https://api.github.com/user', {
                headers: {
                    'Authorization': `token ${accessToken}`,
                    'Accept': 'application/json'
                }
            });

            if (!userResponse.ok) {
                throw new Error(`GitHub user API failed: ${userResponse.status} ${userResponse.statusText}`);
            }

            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            const userData = await userResponse.json();

            // Store token in our system
            // will be required for future requests submitted by client, client must exchange temp auth code for this token
            const sessionToken = tokenStore.storeToken( // internally, generates a fresh session token 
                accessToken,
                '',
                3600, // 1 hour expiration
                sessionData.clientId,
                ['read:user', 'user:email'],
                sessionData.clientCodeChallenge,
                sessionData.clientCodeChallengeMethod
            );

            // Create temporary authorization code (for client to exchange for it's own access token)
            const tempAuthCode = crypto.randomBytes(32).toString('hex');
            this._tempAuthCodes.set(tempAuthCode, {
                sessionToken: sessionToken,
                expires: Date.now() + 5 * 60 * 1000 // 5 minutes
            });

            // Create client redirect URL
            const clientRedirectUrl = new URL(sessionData.redirectUri);
            clientRedirectUrl.searchParams.append("code", tempAuthCode);
            clientRedirectUrl.searchParams.append("state", sessionData.originalState || "");
            // Clean up session data
            this._clearSessionData(state);

            return {
                redirectUrl: clientRedirectUrl.toString(),
                success: true
            };
        } catch (error) {
            return {
                redirectUrl: '',
                success: false,
                error: `Authentication callback failed: ${error instanceof Error ? error.message : String(error)}`
            };
        }
    }

}
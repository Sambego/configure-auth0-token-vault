# Auth0 Token Vault Setup CLI

An interactive CLI tool to configure Auth0 Token Vault for your applications. This script automates the setup process for storing and managing external identity provider tokens securely with Auth0.

## What is Token Vault?

Token Vault is an Auth0 feature that securely stores access and refresh tokens from external identity providers (like Google, GitHub, Microsoft, etc.) after users authenticate. This allows your application to:

- Store external provider tokens securely in Auth0
- Retrieve tokens on behalf of users without re-authentication
- Exchange Auth0 tokens for external provider tokens
- Manage multiple linked accounts per user

## Features

- 🚀 Interactive setup wizard
- 🔐 Automatic configuration of applications, connections, and APIs
- 📦 Support for multiple Token Vault patterns
- ✅ Idempotent - safe to run multiple times
- 🐛 Debug mode for troubleshooting
- 📝 Detailed usage instructions after setup

## Prerequisites

### 1. Node.js
- **Node.js** 18 or higher

### 2. Auth0 CLI
Install and configure the Auth0 CLI:
```bash
brew tap auth0/auth0-cli && brew install auth0
```

### 3. Auth0 Tenant
- An **Auth0 tenant** with admin access

### 4. Social or Enterprise Connection
You must configure at least one social or enterprise connection before running this script.

**To create a connection:**

1. Go to the [Auth0 Dashboard](https://manage.auth0.com/)
2. Navigate to **Authentication → Social**
3. Click **Create Connection**
4. Select your identity provider (e.g., Google, GitHub, Microsoft)
5. Configure the connection settings
6. **Important:** Set the connection purpose to one of:
   - **Connected Accounts for Token Vault** - If this connection will only be used for linking accounts
   - **Authentication and Connected Accounts for Token Vault** - If this connection will be used for both user login and account linking

**Supported providers:**
- Google, GitHub, LinkedIn, Microsoft, Facebook, Twitter
- Dropbox, Box, Salesforce, Fitbit, Slack, Spotify, Stripe
- Custom OAuth2 or OIDC connections

> **Note:** The connection must support Token Vault. Most social and enterprise OAuth2/OIDC connections are compatible.

## Installation

```bash
npm install
```

## Usage

Run the interactive setup:

```bash
npm start
```

Or with debug logging:

```bash
DEBUG=true npm start
# or
npm start -- --debug
```

## Token Vault Flavors

The script supports four Token Vault configurations:

### 1. Connected Accounts

**Use case:** Allow users to link and manage multiple external accounts through your application UI.

**What it configures:**
- My Account API activation
- Client grants for Connected Accounts scopes
- Multi-Resource Refresh Token (MRRT) policies
- Connection settings

**Example:** A social media dashboard where users link their Twitter, Facebook, and Instagram accounts.

### 2. Refresh Token Exchange

**Use case:** Backend services that need to retrieve external provider tokens using Auth0 refresh tokens, without active user sessions.

**What it configures:**
- Everything from Connected Accounts
- Usage instructions for token exchange endpoint

**Example:** A scheduled job that posts to users' social media accounts on their behalf.

**Token Exchange:**
```bash
POST https://{your-domain}/oauth/token
Content-Type: application/json

{
  "grant_type": "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
  "subject_token": "<auth0_refresh_token>",
  "subject_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
  "requested_token_type": "http://auth0.com/oauth/token-type/federated-connection-access-token",
  "connection": "google-oauth2",
  "client_id": "<your_client_id>",
  "client_secret": "<your_client_secret>"
}
```

### 3. Access Token Exchange

**Use case:** Backend APIs that exchange Auth0 access tokens for external provider tokens when handling user requests.

**What it configures:**
- Everything from Connected Accounts
- Optional Custom API Client creation
- Usage instructions for access token exchange

**Example:** An API endpoint that reads a user's Google Calendar events when they make a request.

**Token Exchange:**
```bash
POST https://{your-domain}/oauth/token
Content-Type: application/json

{
  "grant_type": "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
  "subject_token": "<auth0_access_token>",
  "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "requested_token_type": "http://auth0.com/oauth/token-type/federated-connection-access-token",
  "connection": "google-oauth2",
  "client_id": "<custom_api_client_id>",
  "client_secret": "<custom_api_client_secret>"
}
```

### 4. Privileged Worker Token Exchange

**Use case:** Machine-to-machine applications that need to retrieve external provider tokens for specific users without active sessions.

**What it configures:**
- Everything from Connected Accounts
- Private Key JWT authentication setup
- Usage instructions for JWT bearer token exchange

**Example:** A background worker that syncs data from users' Dropbox accounts to your system.

**Token Exchange:**
```bash
POST https://{your-domain}/oauth/token
Content-Type: application/json

{
  "grant_type": "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
  "subject_token": "<signed_jwt>",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "requested_token_type": "http://auth0.com/oauth/token-type/federated-connection-access-token",
  "connection": "google-oauth2",
  "client_id": "<worker_client_id>",
  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  "client_assertion": "<client_jwt>"
}
```

## What Gets Configured

The script automatically configures:

### Application Settings
- ✅ Token Vault grant type (`urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token`)
- ✅ First-party application status
- ✅ OIDC conformance
- ✅ Confidential client authentication
- ✅ Required grant types (authorization_code, refresh_token)

### Connections
- ✅ Connected Accounts activation
- ✅ Application enablement

### My Account API
- ✅ API creation/activation
- ✅ Connected Accounts scopes
- ✅ Access policy configuration (`require_client_grant`)

### Client Grants
- ✅ User-type client grant with Connected Accounts scopes:
  - `create:me:connected_accounts`
  - `read:me:connected_accounts`
  - `delete:me:connected_accounts`

### Multi-Resource Refresh Token (MRRT)
- ✅ MRRT policies for My Account API

## Supported Connections

The script works with these identity providers:

- Google (`google-oauth2`)
- GitHub (`github`)
- LinkedIn (`linkedin`)
- Microsoft (`microsoft`)
- Facebook (`facebook`)
- Twitter (`twitter`)
- Dropbox (`dropbox`)
- Box (`box`)
- Salesforce (`salesforce`)
- Fitbit (`fitbit`)
- Slack (`slack`)
- Spotify (`spotify`)
- Stripe (`stripe-connect`)
- Custom OAuth2 (`oauth2`)
- Custom OIDC (`oidc`)

## Troubleshooting

### My Account API Not Found

If the script can't create the My Account API automatically, you'll need to activate it manually:

1. Go to **Auth0 Dashboard → Applications → APIs**
2. Look for the **My Account API** banner
3. Click **Activate**
4. Run the script again

### Authentication Issues

If you see "insufficient scopes" errors:

```bash
auth0 login --scopes "read:clients,update:clients,create:clients,read:resource_servers,create:resource_servers,update:resource_servers,read:client_grants,create:client_grants,update:client_grants,read:connections,update:connections"
```

### Debug Mode

Enable debug logging to see detailed API calls:

```bash
DEBUG=true npm start
```

## Security Considerations

- **Never commit credentials:** The script displays client secrets - store them securely
- **Refresh token rotation:** The script does NOT enable refresh token rotation (as Token Vault doesn't support it)
- **MFA policy:** Token Vault requires MFA policy to NOT be "Always"
- **Confidential clients:** Token Vault only works with confidential clients (not public/SPA without backend)

## Resources

- [Token Vault Documentation](https://auth0.com/docs/secure/tokens/token-vault)
- [Connected Accounts](https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault/connected-accounts-for-token-vault)
- [Refresh Token Exchange](https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault/refresh-token-exchange-with-token-vault)
- [Access Token Exchange](https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault/access-token-exchange-with-token-vault)
- [Privileged Worker](https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault/privileged-worker-token-exchange-with-token-vault)
- [Auth0 CLI Documentation](https://github.com/auth0/auth0-cli)

## License

MIT

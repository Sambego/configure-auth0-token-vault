#!/usr/bin/env node

import * as p from "@clack/prompts";
import { execa } from "execa";
import pc from "picocolors";

const DEBUG = process.env.DEBUG === "true" || process.argv.includes("--debug");

function log(message) {
  if (DEBUG) {
    console.log(pc.dim(`[debug] ${message}`));
  }
}

async function checkScopesChanged(text) {
  if (!text) return;

  const lowerText = text.toLowerCase();
  if (
    lowerText.includes("required scopes have changed") ||
    lowerText.includes("required scopes") ||
    lowerText.includes("insufficient scopes")
  ) {
    log(`Detected scopes issue in: ${text.substring(0, 200)}`);
    p.log.error(
      "The Auth0 CLI requires additional scopes to complete this operation.",
    );
    const shouldReauth = await p.confirm({
      message: "Would you like to reauthenticate with the required scopes?",
      initialValue: true,
    });

    if (p.isCancel(shouldReauth) || !shouldReauth) {
      p.cancel("Please run 'auth0 login' manually with the required scopes.");
      process.exit(1);
    }

    p.log.info("Reauthenticating...");
    await execa("auth0", ["login"], { stdio: "inherit" });
    p.log.success("Reauthentication successful! Please run this script again.");
    process.exit(0);
  }
}

async function runAuth0Command(args, options = {}) {
  log(`Running: auth0 ${args.join(" ")}`);

  // Use reject: false to get output even on "failure" (like scope prompts)
  // Add timeout to prevent hanging
  const result = await execa("auth0", args, {
    ...options,
    reject: false,
    timeout: 30000, // 30 second timeout
  });

  log(`exitCode: ${result.exitCode}`);
  log(`stdout: ${result.stdout?.substring(0, 500)}`);
  log(`stderr: ${result.stderr?.substring(0, 500)}`);

  // Check for scopes issue in any output
  const allText = [result.stdout, result.stderr].filter(Boolean).join(" ");
  await checkScopesChanged(allText);

  // If command failed, throw error
  if (result.exitCode !== 0) {
    const error = new Error(`Command failed: auth0 ${args.join(" ")}`);
    error.stdout = result.stdout;
    error.stderr = result.stderr;
    error.exitCode = result.exitCode;
    throw error;
  }

  return result;
}

async function runAuth0Api(method, path, data = null) {
  const args = ["api", method, path, "--no-input"];
  const options = {};

  if (data) {
    const jsonData = JSON.stringify(data);
    log(
      `Running: auth0 api ${method} ${path} (with data: ${jsonData.substring(0, 100)}...)`,
    );
    options.input = jsonData;
  } else {
    log(`Running: auth0 api ${method} ${path}`);
  }

  const result = await execa("auth0", args, {
    ...options,
    reject: false,
    timeout: 30000, // 30 second timeout
  });

  log(`exitCode: ${result.exitCode}`);
  log(`stdout: ${result.stdout?.substring(0, 500)}`);
  log(`stderr: ${result.stderr?.substring(0, 500)}`);

  // Check for scopes issue in any output
  const allText = [result.stdout, result.stderr].filter(Boolean).join(" ");
  await checkScopesChanged(allText);

  // If command failed, throw error
  if (result.exitCode !== 0) {
    const error = new Error(`Command failed: auth0 api ${method} ${path}`);
    error.stdout = result.stdout;
    error.stderr = result.stderr;
    error.exitCode = result.exitCode;
    throw error;
  }

  return result;
}

const TOKEN_VAULT_GRANT_TYPE =
  "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token";

const CONNECTED_ACCOUNTS_SCOPES = [
  "create:me:connected_accounts",
  "read:me:connected_accounts",
  "delete:me:connected_accounts",
];

const MY_ACCOUNT_API_SCOPES = [
  { value: "read:me", description: "Read user profile" },
  { value: "update:me", description: "Update user profile" },
  { value: "delete:me", description: "Delete user account" },
  {
    value: "create:me:connected_accounts",
    description: "Link external accounts",
  },
  {
    value: "read:me:connected_accounts",
    description: "Read linked accounts",
  },
  {
    value: "delete:me:connected_accounts",
    description: "Unlink external accounts",
  },
];

async function main() {
  console.clear();

  p.intro(pc.bgCyan(pc.black(" Auth0 Token Vault Connected Accounts Setup ")));

  // Check Auth0 CLI installation
  const cliInstalled = await checkAuth0CLI();
  if (!cliInstalled) {
    p.log.error("Auth0 CLI is not installed.");
    p.note(
      `Install via Homebrew:\n${pc.cyan("brew tap auth0/auth0-cli && brew install auth0")}\n\nOr visit: ${pc.cyan("https://github.com/auth0/auth0-cli")}`,
      "Installation Required",
    );
    p.outro(pc.red("Setup cancelled."));
    process.exit(1);
  }

  p.log.success("Auth0 CLI detected");

  // Check if logged in
  const loggedIn = await checkAuth0Login();
  if (!loggedIn) {
    const shouldLogin = await p.confirm({
      message: "You need to log in to Auth0 CLI. Log in now?",
      initialValue: true,
    });

    if (p.isCancel(shouldLogin) || !shouldLogin) {
      p.cancel("Login required to continue.");
      process.exit(1);
    }

    await runAuth0Login();
  }

  // Get tenant info
  const tenantInfo = await getTenantInfo();
  p.log.success(`Connected to tenant: ${pc.cyan(tenantInfo.domain)}`);

  // Ask about application setup
  const appChoice = await p.select({
    message: "How would you like to configure the application?",
    options: [
      { value: "new", label: "Create a new application" },
      { value: "existing", label: "Use an existing application" },
    ],
  });

  if (p.isCancel(appChoice)) {
    p.cancel("Setup cancelled.");
    process.exit(0);
  }

  let app;

  if (appChoice === "new") {
    app = await createNewApplication();
  } else {
    app = await selectExistingApplication();
  }

  if (!app) {
    p.cancel("No application selected.");
    process.exit(1);
  }

  p.log.info(`Using application: ${pc.cyan(app.name)} (${pc.dim(app.id)})`);

  // Configure application for Token Vault
  await configureApplicationForTokenVault(app.id);

  // Enable My Account API
  await enableMyAccountAPI(tenantInfo.domain);

  // Create client grant for My Account API
  await createClientGrant(app.id, tenantInfo.domain);

  // Configure MRRT
  await configureMRRT(app.id, tenantInfo.domain);

  // Configure connections
  await configureConnections(app.id);

  // Build dashboard URL
  const domainParts = tenantInfo.domain.split(".");
  let dashboardUrl;
  if (domainParts.length === 4) {
    // Format: tenant.region.auth0.com
    const [tenant, region] = domainParts;
    dashboardUrl = `https://manage.auth0.com/dashboard/${region}/${tenant}/applications/${app.id}/settings`;
  } else {
    // Format: tenant.auth0.com (US region)
    const [tenant] = domainParts;
    dashboardUrl = `https://manage.auth0.com/dashboard/us/${tenant}/applications/${app.id}/settings`;
  }

  p.note(
    `${pc.bold("Application Details:")}\n` +
      `  Name:      ${pc.cyan(app.name)}\n` +
      `  Client ID: ${pc.dim(app.id)}\n\n` +
      `${pc.bold("Settings:")}\n` +
      `  ${pc.cyan(dashboardUrl)}\n\n` +
      `${pc.bold("Documentation:")}\n` +
      `  ${pc.cyan("https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault")}`,
    "Setup Complete",
  );

  p.outro(pc.green("All done!"));
}

async function checkAuth0CLI() {
  try {
    await runAuth0Command(["--version"]);
    return true;
  } catch {
    return false;
  }
}

async function checkAuth0Login() {
  try {
    const { stdout } = await runAuth0Command([
      "tenants",
      "list",
      "--json",
      "--no-input",
    ]);
    const tenants = JSON.parse(stdout || "[]");
    // Check if we have any tenants (logged in)
    return tenants.length > 0;
  } catch {
    return false;
  }
}

async function runAuth0Login() {
  p.log.info("Opening browser for Auth0 login...");
  try {
    await runAuth0Command(["login"], { stdio: "inherit" });
    p.log.success("Login successful!");
  } catch (error) {
    p.log.error("Login failed");
    throw error;
  }
}

async function getTenantInfo() {
  const { stdout } = await runAuth0Command([
    "tenants",
    "list",
    "--json",
    "--no-input",
  ]);
  const tenants = JSON.parse(stdout || "[]");

  if (tenants.length === 0) {
    throw new Error("No tenants found. Please log in first.");
  }

  const activeTenant = tenants.find((t) => t.active) || tenants[0];
  return { domain: activeTenant.name };
}

async function createNewApplication() {
  const details = await p.group(
    {
      name: () =>
        p.text({
          message: "Enter application name:",
          placeholder: "Token Vault App",
          defaultValue: "Token Vault App",
        }),
      type: () =>
        p.select({
          message: "Select application type:",
          options: [
            { value: "regular", label: "Regular Web Application" },
            { value: "native", label: "Native" },
            { value: "spa", label: "Single Page Application" },
            { value: "m2m", label: "Machine to Machine" },
          ],
        }),
    },
    {
      onCancel: () => {
        p.cancel("Setup cancelled.");
        process.exit(0);
      },
    },
  );

  const s = p.spinner();
  s.start("Creating application...");

  try {
    const sanitizedName = details.name.replace(/\+/g, "").trim();
    log(`Creating app: name="${sanitizedName}", type="${details.type}"`);

    const createArgs = [
      "apps",
      "create",
      "--name",
      `${sanitizedName}`,
      "--type",
      details.type,
      "--json",
      "--no-input",
    ];

    log(`Full command: auth0 ${createArgs.join(" ")}`);
    const { stdout } = await runAuth0Command(createArgs);

    log(`Response: ${stdout}`);
    const app = JSON.parse(stdout);
    s.stop(`Application created: ${pc.cyan(app.name)}`);
    return { id: app.client_id, name: app.name };
  } catch (error) {
    s.stop("Failed to create application");
    p.log.error(`Command failed: ${error.message}`);
    if (error.stdout) {
      p.log.error(`stdout: ${error.stdout}`);
    }
    if (error.stderr) {
      p.log.error(`stderr: ${error.stderr}`);
    }
    throw error;
  }
}

async function selectExistingApplication() {
  const s = p.spinner();
  s.start("Fetching applications...");

  try {
    const { stdout } = await runAuth0Command([
      "apps",
      "list",
      "--json",
      "--no-input",
    ]);
    const apps = JSON.parse(stdout);
    s.stop("Applications loaded");

    const filteredApps = apps.filter((app) => app.name !== "All Applications");

    if (filteredApps.length === 0) {
      p.log.warning("No applications found. Creating a new one.");
      return createNewApplication();
    }

    const selected = await p.select({
      message: "Select an application:",
      options: filteredApps.map((app) => ({
        value: { id: app.client_id, name: app.name },
        label: app.name,
        hint: app.client_id,
      })),
    });

    if (p.isCancel(selected)) {
      p.cancel("Setup cancelled.");
      process.exit(0);
    }

    return selected;
  } catch (error) {
    s.stop("Failed to fetch applications");
    throw error;
  }
}

async function configureApplicationForTokenVault(appId) {
  const s = p.spinner();
  s.start("Configuring application for Token Vault...");

  try {
    const { stdout } = await runAuth0Command([
      "apps",
      "show",
      appId,
      "--json",
      "--no-input",
    ]);
    const app = JSON.parse(stdout);

    let grantTypes = app.grant_types || ["authorization_code", "refresh_token"];
    if (!grantTypes.includes(TOKEN_VAULT_GRANT_TYPE)) {
      grantTypes.push(TOKEN_VAULT_GRANT_TYPE);
    }
    if (!grantTypes.includes("refresh_token")) {
      grantTypes.push("refresh_token");
    }
    if (!grantTypes.includes("authorization_code")) {
      grantTypes.push("authorization_code");
    }

    const updatePayload = {
      is_first_party: true,
      oidc_conformant: true,
      grant_types: grantTypes,
    };

    if (app.token_endpoint_auth_method === "none") {
      updatePayload.token_endpoint_auth_method = "client_secret_post";
    }

    await runAuth0Api("patch", `clients/${appId}`, updatePayload);

    s.stop("Application configured for Token Vault");
  } catch (error) {
    s.stop("Failed to configure application");
    p.log.error(error.message);
    throw error;
  }
}

async function enableMyAccountAPI(domain) {
  const s = p.spinner();
  s.start("Enabling My Account API...");

  const myAccountIdentifier = `https://${domain}/me/`;

  try {
    // First check if My Account API already exists
    const { stdout } = await runAuth0Api(
      "get",
      `resource-servers?identifier=${encodeURIComponent(myAccountIdentifier)}`,
    );
    const apis = JSON.parse(stdout);

    if (apis && apis.length > 0) {
      // API exists, check if we need to update scopes and access policy
      const existingApi = apis[0];
      const existingScopes = existingApi.scopes || [];
      const existingScopeValues = existingScopes.map((scope) => scope.value);

      // Check if connected accounts scopes are missing
      const missingScopes = MY_ACCOUNT_API_SCOPES.filter(
        (scope) => !existingScopeValues.includes(scope.value),
      );

      // Build update payload
      const updatePayload = {};

      if (missingScopes.length > 0) {
        log(`Adding missing scopes: ${missingScopes.map((sc) => sc.value).join(", ")}`);
        updatePayload.scopes = [...existingScopes, ...missingScopes];
      }

      // Configure access policy to allow user access via client grants
      // This ensures applications with a client grant can access the API
      const currentUserPolicy =
        existingApi.subject_type_authorization?.user?.policy;
      if (currentUserPolicy !== "require_client_grant") {
        log(`Setting user access policy to require_client_grant (current: ${currentUserPolicy})`);
        updatePayload.subject_type_authorization = {
          user: {
            policy: "require_client_grant",
          },
        };
      }

      if (Object.keys(updatePayload).length > 0) {
        await runAuth0Api(
          "patch",
          `resource-servers/${existingApi.id}`,
          updatePayload,
        );
        s.stop("My Account API configured with access policy and scopes");
      } else {
        s.stop("My Account API is already enabled");
      }

      return { identifier: myAccountIdentifier, id: existingApi.id };
    }

    // API doesn't exist, try to create it
    log("My Account API not found, attempting to create it");
    try {
      const { stdout: createOutput } = await runAuth0Api(
        "post",
        "resource-servers",
        {
          identifier: myAccountIdentifier,
          name: "My Account",
          scopes: MY_ACCOUNT_API_SCOPES,
          signing_alg: "RS256",
          allow_offline_access: true,
          token_lifetime: 86400,
          token_lifetime_for_web: 7200,
          skip_consent_for_verifiable_first_party_clients: true,
          subject_type_authorization: {
            user: {
              policy: "require_client_grant",
            },
          },
        },
      );
      const createdApi = JSON.parse(createOutput);
      s.stop("My Account API created and enabled");
      return { identifier: myAccountIdentifier, id: createdApi.id };
    } catch (createError) {
      // If creation fails, it might be a system API that needs special activation
      log(`Creation failed: ${createError.message}`);
      if (createError.stdout) log(`stdout: ${createError.stdout}`);
      if (createError.stderr) log(`stderr: ${createError.stderr}`);

      // Build dashboard URL for manual activation
      const domainParts = domain.split(".");
      let dashboardUrl;
      if (domainParts.length === 4) {
        const [tenant, region] = domainParts;
        dashboardUrl = `https://manage.auth0.com/dashboard/${region}/${tenant}/apis`;
      } else {
        const [tenant] = domainParts;
        dashboardUrl = `https://manage.auth0.com/dashboard/us/${tenant}/apis`;
      }

      s.stop("My Account API needs manual activation");
      p.note(
        `The My Account API requires manual activation:\n\n` +
          `1. Go to the Auth0 Dashboard:\n` +
          `   ${pc.cyan(dashboardUrl)}\n\n` +
          `2. Look for the ${pc.bold("My Account API")} banner\n\n` +
          `3. Click ${pc.bold("Activate")}\n\n` +
          `Once activated, run this script again to complete the setup.`,
        "Action Required",
      );
      return { identifier: myAccountIdentifier, id: null };
    }
  } catch (error) {
    s.stop("Could not verify My Account API status");
    log(`My Account API error: ${error.message}`);
    if (error.stdout) log(`stdout: ${error.stdout}`);
    if (error.stderr) log(`stderr: ${error.stderr}`);

    p.log.warning(
      "Please ensure My Account API is enabled in your Auth0 Dashboard.",
    );
    return { identifier: myAccountIdentifier, id: null };
  }
}

async function createClientGrant(appId, domain) {
  const s = p.spinner();
  s.start("Creating client grant for My Account API...");
  const myAccountIdentifier = `https://${domain}/me/`;

  try {
    // Check for existing client grants (both user and client types)
    const { stdout: grantsOutput } = await runAuth0Api(
      "get",
      `client-grants?client_id=${appId}&audience=${encodeURIComponent(myAccountIdentifier)}`,
    );

    const grants = JSON.parse(grantsOutput);

    // Look for a user-type grant specifically
    const userGrant = grants.find((g) => g.subject_type === "user");

    if (userGrant) {
      // Update existing user grant with scopes
      const existingScopes = userGrant.scope || [];
      const newScopes = [
        ...new Set([...existingScopes, ...CONNECTED_ACCOUNTS_SCOPES]),
      ];

      await runAuth0Api("patch", `client-grants/${userGrant.id}`, {
        scope: newScopes,
      });

      s.stop("Client grant updated with Connected Accounts scopes");
      return;
    }
  } catch {
    // Grant doesn't exist, create it
  }

  try {
    // Create a new client grant with subject_type: "user" for user-based access
    await runAuth0Api("post", "client-grants", {
      client_id: appId,
      audience: myAccountIdentifier,
      scope: CONNECTED_ACCOUNTS_SCOPES,
      subject_type: "user",
    });

    s.stop("Client grant created for My Account API (user access)");
  } catch (error) {
    if (error.message?.includes("already exists")) {
      s.stop("Client grant already exists");
    } else {
      s.stop("Could not create client grant automatically");
      log(`Client grant error: ${error.message}`);
      if (error.stdout) log(`stdout: ${error.stdout}`);
      if (error.stderr) log(`stderr: ${error.stderr}`);

      p.note(
        `Create a client grant in the Auth0 Dashboard:\n\n` +
          `1. Go to Applications → APIs → My Account\n` +
          `2. Click the "Machine to Machine Applications" tab\n` +
          `3. Find your application and authorize it\n` +
          `4. Select the Connected Accounts scopes:\n` +
          `   - create:me:connected_accounts\n` +
          `   - read:me:connected_accounts\n` +
          `   - delete:me:connected_accounts`,
        "Action Required",
      );
    }
  }
}

async function configureMRRT(appId, domain) {
  const s = p.spinner();
  s.start("Configuring Multi-Resource Refresh Token (MRRT)...");
  const myAccountIdentifier = `https://${domain}/me/`;

  try {
    // Get current app configuration
    const { stdout } = await runAuth0Command([
      "apps",
      "show",
      appId,
      "--json",
      "--no-input",
    ]);
    const app = JSON.parse(stdout);

    // Get existing refresh_token config and policies
    const refreshTokenConfig = app.refresh_token || {};
    const existingPolicies = refreshTokenConfig.policies || [];

    // Check if My Account API is already in MRRT policies
    const hasMyAccountInMRRT = existingPolicies.some(
      (policy) => policy.audience === myAccountIdentifier,
    );

    if (!hasMyAccountInMRRT) {
      // Add My Account API to policies
      const newPolicies = [
        ...existingPolicies,
        {
          audience: myAccountIdentifier,
          scope: CONNECTED_ACCOUNTS_SCOPES,
        },
      ];

      await runAuth0Api("patch", `clients/${appId}`, {
        refresh_token: {
          ...refreshTokenConfig,
          policies: newPolicies,
        },
      });

      s.stop("MRRT configured with My Account API");
    } else {
      s.stop("MRRT already includes My Account API");
    }
  } catch (error) {
    s.stop("Could not configure MRRT automatically");
    log(`MRRT error: ${error.message}`);
    if (error.stdout) log(`stdout: ${error.stdout}`);
    if (error.stderr) log(`stderr: ${error.stderr}`);

    // Build dashboard URL as fallback
    const domainParts = domain.split(".");
    let settingsUrl;
    if (domainParts.length === 4) {
      const [tenant, region] = domainParts;
      settingsUrl = `https://manage.auth0.com/dashboard/${region}/${tenant}/applications/${appId}/settings`;
    } else {
      const [tenant] = domainParts;
      settingsUrl = `https://manage.auth0.com/dashboard/us/${tenant}/applications/${appId}/settings`;
    }

    p.note(
      `Configure MRRT manually in the Auth0 Dashboard:\n\n` +
        `1. Go to your application settings:\n` +
        `   ${pc.cyan(settingsUrl)}\n\n` +
        `2. Scroll to ${pc.bold("Multi-Resource Refresh Token")}\n\n` +
        `3. Click ${pc.bold("Edit Configuration")} and enable the My Account API`,
      "Action Required: Configure MRRT",
    );
  }
}

async function configureConnections(appId) {
  const s = p.spinner();
  s.start("Fetching connections...");

  try {
    const { stdout } = await runAuth0Api("get", "connections");
    const connections = JSON.parse(stdout);

    const supportedStrategies = [
      "google-oauth2",
      "github",
      "linkedin",
      "microsoft",
      "facebook",
      "twitter",
      "dropbox",
      "box",
      "salesforce",
      "fitbit",
      "slack",
      "spotify",
      "stripe-connect",
      "oauth2",
      "oidc",
    ];

    const eligibleConnections = connections.filter(
      (conn) =>
        supportedStrategies.includes(conn.strategy) ||
        conn.strategy?.startsWith("oauth") ||
        conn.strategy?.startsWith("oidc"),
    );

    s.stop("Connections loaded");

    if (eligibleConnections.length === 0) {
      p.log.warning("No eligible social/enterprise connections found.");
      p.note(
        "Create a social connection first in the Auth0 Dashboard.",
        "No Connections",
      );
      return;
    }

    const selectedConnections = await p.multiselect({
      message: "Select connections to enable for Connected Accounts:",
      options: eligibleConnections.map((conn) => ({
        value: conn,
        label: conn.name,
        hint: conn.strategy,
      })),
      required: false,
    });

    if (p.isCancel(selectedConnections)) {
      p.cancel("Setup cancelled.");
      process.exit(0);
    }

    if (!selectedConnections || selectedConnections.length === 0) {
      p.log.warning("No connections selected.");
      return;
    }

    for (const conn of selectedConnections) {
      const connSpinner = p.spinner();
      connSpinner.start(`Configuring ${conn.name}...`);

      try {
        await runAuth0Api("patch", `connections/${conn.id}`, {
          options: {
            ...conn.options,
            connected_accounts: { active: true },
          },
        });

        await runAuth0Api("patch", `connections/${conn.id}`, {
          enabled_clients: [
            ...new Set([...(conn.enabled_clients || []), appId]),
          ],
        });

        connSpinner.stop(
          `${pc.cyan(conn.name)} configured for Connected Accounts`,
        );
      } catch {
        connSpinner.stop(`Could not fully configure ${conn.name}`);
        p.log.warning(
          `Please enable Connected Accounts manually in the Dashboard for ${conn.name}`,
        );
      }
    }
  } catch {
    s.stop("Could not fetch connections");
    p.log.warning("Please configure connections manually in the Dashboard.");
  }
}

main().catch((error) => {
  p.log.error(error.message);
  process.exit(1);
});

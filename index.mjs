// ---------------------------------------
// **DISCLAIMER: THIS CAN GET YOU BANNED**
// ---------------------------------------
// Drop this into your plugins folder and things should resume working.
// If you're on version > 1.2.27, you can also add an `anthropic-prompt.txt`
// file in the same plugins directory containing the opencode session prompt:
// https://github.com/anomalyco/opencode/blob/8e09e8c6121f03244a1f25281b506a90bcb355d7/packages/opencode/src/session/prompt/anthropic-20250930.txt

const CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const VERSION = "2.1.76";
const AGENT = `claude-code/${VERSION}`;
const SALT = "59cf53e54c78";
const ENTRY = "CLAUDE_CODE_ENTRYPOINT";
const PROMPT = new URL("./anthropic-prompt.txt", import.meta.url);
const PLATFORM_HOST = "platform.claude.com";
const LEGACY_CONSOLE_HOST = "console.anthropic.com";
const CALLBACK_URL = `https://${PLATFORM_HOST}/oauth/code/callback`;
const TOKEN_ENDPOINTS = [
  `https://${PLATFORM_HOST}/v1/oauth/token`,
  `https://${LEGACY_CONSOLE_HOST}/v1/oauth/token`,
];

async function prompt() {
  const file = Bun.file(PROMPT);
  if (!(await file.exists())) {
    return "You are Claude Code, Anthropic's official CLI for Claude.";
  }
  return file.text();
}

function base64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function random(size) {
  return base64url(crypto.getRandomValues(new Uint8Array(size)));
}

async function pkce() {
  const verifier = random(32);
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return {
    verifier,
    challenge: base64url(new Uint8Array(hash)),
  };
}

function authHeaders(extra = {}) {
  return {
    "Content-Type": "application/json",
    "User-Agent": AGENT,
    ...extra,
  };
}

async function parseError(response) {
  const text = await response.text();
  try {
    const json = JSON.parse(text);
    return json?.error_description || json?.error?.message || text;
  } catch {
    return text || response.statusText;
  }
}

async function exchangeWithEndpoint(url, payload) {
  const res = await fetch(url, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    return {
      ok: false,
      endpoint: url,
      status: res.status,
      message: await parseError(res),
    };
  }

  return {
    ok: true,
    endpoint: url,
    json: await res.json(),
  };
}

function normalizeCodeInput(input) {
  const trimmed = input.trim();
  if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
    return trimmed;
  }

  try {
    const url = new URL(trimmed);
    const code = url.searchParams.get("code");
    const state =
      url.searchParams.get("state") ||
      url.hash.replace(/^#/, "") ||
      url.searchParams.get("code_verifier");
    if (code) return `${code}#${state || ""}`;
    return trimmed;
  } catch {
    return trimmed;
  }
}

function text(input) {
  if (!Array.isArray(input)) return "";

  for (const msg of input) {
    if (!msg || typeof msg !== "object") continue;
    if (msg.role !== "user") continue;
    if (typeof msg.content === "string") return msg.content;
    if (!Array.isArray(msg.content)) return "";

    for (const block of msg.content) {
      if (!block || typeof block !== "object") continue;
      if (block.type !== "text") continue;
      if (typeof block.text === "string") return block.text;
    }

    return "";
  }

  return "";
}

function billing(body) {
  const json = JSON.parse(body);
  const sample = [4, 7, 20]
    .map((idx) => text(json.messages).charAt(idx) || "0")
    .join("");
  const hash = Bun.CryptoHasher.hash(
    "sha256",
    `${SALT}${sample}${VERSION}`,
    "hex",
  ).slice(0, 3);
  const entry = process.env[ENTRY]?.trim() || "cli";
  return `cc_version=${VERSION}.${hash}; cc_entrypoint=${entry}; cch=00000;`;
}

async function authorize(mode) {
  const code = await pkce();
  const url = new URL(
    `https://${mode === "console" ? PLATFORM_HOST : "claude.ai"}/oauth/authorize`,
  );
  url.searchParams.set("code", "true");
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("response_type", "code");
  url.searchParams.set(
    "redirect_uri",
    CALLBACK_URL,
  );
  url.searchParams.set(
    "scope",
    "org:create_api_key user:profile user:inference",
  );
  url.searchParams.set("code_challenge", code.challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", code.verifier);
  return {
    url: url.toString(),
    verifier: code.verifier,
  };
}

async function exchange(code, verifier) {
  const split = normalizeCodeInput(code).split("#");
  const payload = {
    code: split[0],
    state: split[1],
    grant_type: "authorization_code",
    client_id: CLIENT_ID,
    redirect_uri: CALLBACK_URL,
    code_verifier: verifier,
  };

  let failure = null;
  for (const endpoint of TOKEN_ENDPOINTS) {
    const res = await exchangeWithEndpoint(endpoint, payload);
    if (res.ok) {
      const json = res.json;
      return {
        type: "success",
        refresh: json.refresh_token,
        access: json.access_token,
        expires: Date.now() + json.expires_in * 1000,
      };
    }
    failure = res;
  }

  return {
    type: "failed",
    error:
      failure?.message || "Token exchange failed during Anthropic OAuth login.",
    status: failure?.status,
    endpoint: failure?.endpoint,
  };
}

export async function AnthropicAuthPlugin({ client }) {
  return {
    async "experimental.chat.system.transform"(input, output) {
      if (input.model?.providerID !== "anthropic") return;
      const prefix = await prompt();
      output.system.unshift(prefix);
      if (output.system[1])
        output.system[1] = `${prefix}\n\n${output.system[1]}`;
    },
    auth: {
      provider: "anthropic",
      async loader(getAuth, provider) {
        const auth = await getAuth();
        if (auth.type !== "oauth") return {};

        for (const model of Object.values(provider.models)) {
          model.cost = {
            input: 0,
            output: 0,
            cache: { read: 0, write: 0 },
          };
        }

        return {
          apiKey: "",
          async fetch(input, init) {
            const auth = await getAuth();
            if (auth.type !== "oauth") return fetch(input, init);

            if (!auth.access || auth.expires < Date.now()) {
              const payload = {
                grant_type: "refresh_token",
                refresh_token: auth.refresh,
                client_id: CLIENT_ID,
              };
              let refreshed = null;

              for (const endpoint of TOKEN_ENDPOINTS) {
                const res = await exchangeWithEndpoint(endpoint, payload);
                if (res.ok) {
                  refreshed = res.json;
                  break;
                }
              }

              if (!refreshed) {
                throw new Error(
                  "Token refresh failed on all known Anthropic OAuth endpoints",
                );
              }

              await client.auth.set({
                path: { id: "anthropic" },
                body: {
                  type: "oauth",
                  refresh: refreshed.refresh_token,
                  access: refreshed.access_token,
                  expires: Date.now() + refreshed.expires_in * 1000,
                },
              });
              auth.access = refreshed.access_token;
              auth.refresh = refreshed.refresh_token;
              auth.expires = Date.now() + refreshed.expires_in * 1000;
            }

            const req = init ?? {};
            const headers = new Headers(
              input instanceof Request ? input.headers : undefined,
            );
            new Headers(req.headers).forEach((value, key) => {
              headers.set(key, value);
            });

            const beta = headers.get("anthropic-beta") || "";
            const list = beta
              .split(",")
              .map((x) => x.trim())
              .filter(Boolean);
            headers.set(
              "anthropic-beta",
              [
                ...new Set([
                  "oauth-2025-04-20",
                  "interleaved-thinking-2025-05-14",
                  ...list,
                ]),
              ].join(","),
            );
            headers.set("authorization", `Bearer ${auth.access}`);
            headers.set("user-agent", AGENT);
            headers.delete("x-api-key");

            const tool = "mcp_";
            let body = req.body;
            if (typeof body === "string") {
              const json = JSON.parse(body);

              if (Array.isArray(json.system)) {
                json.system = json.system.map((item) => {
                  if (!item || typeof item !== "object") return item;
                  if (item.type !== "text" || typeof item.text !== "string")
                    return item;
                  return {
                    ...item,
                    text: item.text
                      .replace(/OpenCode/g, "Claude Code")
                      .replace(/opencode/gi, "Claude"),
                  };
                });
              }

              if (Array.isArray(json.tools)) {
                json.tools = json.tools.map((item) => {
                  if (!item || typeof item !== "object") return item;
                  if (typeof item.name !== "string") return item;
                  return { ...item, name: `${tool}${item.name}` };
                });
              }

              if (Array.isArray(json.messages)) {
                json.messages = json.messages.map((msg) => {
                  if (
                    !msg ||
                    typeof msg !== "object" ||
                    !Array.isArray(msg.content)
                  )
                    return msg;
                  return {
                    ...msg,
                    content: msg.content.map((item) => {
                      if (!item || typeof item !== "object") return item;
                      if (
                        item.type !== "tool_use" ||
                        typeof item.name !== "string"
                      )
                        return item;
                      return { ...item, name: `${tool}${item.name}` };
                    }),
                  };
                });
              }

              body = JSON.stringify(json);
            }

            let url;
            try {
              if (typeof input === "string" || input instanceof URL)
                url = new URL(input.toString());
              if (input instanceof Request) url = new URL(input.url);
            } catch {}

            if (url?.pathname === "/v1/messages" && typeof body === "string") {
              headers.set("x-anthropic-billing-header", billing(body));
            }

            if (
              url?.pathname === "/v1/messages" &&
              !url.searchParams.has("beta")
            ) {
              url.searchParams.set("beta", "true");
              input =
                input instanceof Request
                  ? new Request(url.toString(), input)
                  : url;
            }

            const res = await fetch(input, {
              ...req,
              body,
              headers,
            });

            if (!res.body) return res;

            const reader = res.body.getReader();
            const decoder = new TextDecoder();
            const encoder = new TextEncoder();
            const stream = new ReadableStream({
              async pull(ctrl) {
                const part = await reader.read();
                if (part.done) {
                  ctrl.close();
                  return;
                }

                const text = decoder
                  .decode(part.value, { stream: true })
                  .replace(/"name"\s*:\s*"mcp_([^"]+)"/g, '"name": "$1"');

                ctrl.enqueue(encoder.encode(text));
              },
            });

            return new Response(stream, {
              status: res.status,
              statusText: res.statusText,
              headers: res.headers,
            });
          },
        };
      },
      methods: [
        {
          label: "Claude Pro/Max",
          type: "oauth",
          authorize: async () => {
            const auth = await authorize("max");
            return {
              url: auth.url,
              instructions: "Paste the authorization code here: ",
              method: "code",
              callback: async (code) => exchange(code, auth.verifier),
            };
          },
        },
        {
          label: "Create an API Key",
          type: "oauth",
          authorize: async () => {
            const auth = await authorize("console");
            return {
              url: auth.url,
              instructions: "Paste the authorization code here: ",
              method: "code",
              callback: async (code) => {
                const credentials = await exchange(code, auth.verifier);
                if (credentials.type === "failed") return credentials;

                const res = await fetch(
                  "https://api.anthropic.com/api/oauth/claude_cli/create_api_key",
                  {
                    method: "POST",
                    headers: authHeaders({
                      authorization: `Bearer ${credentials.access}`,
                    }),
                  },
                );
                const json = await res.json();
                return { type: "success", key: json.raw_key };
              },
            };
          },
        },
        {
          provider: "anthropic",
          label: "Manually enter API Key",
          type: "api",
        },
      ],
    },
  };
}

export default AnthropicAuthPlugin;

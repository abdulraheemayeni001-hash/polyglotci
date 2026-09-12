import jwt from "@tsndr/cloudflare-worker-jwt";

export interface Env {
  GITHUB_WEBHOOK_SECRET: string;
  GITHUB_APP_ID: string;
  GITHUB_PRIVATE_KEY: string;
}

async function verifySignature(
  payload: string,
  signature: string | null,
  secret: string
): Promise<boolean> {
  if (!signature) return false;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signed = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
  const expectedSig =
    "sha256=" +
    Array.from(new Uint8Array(signed))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  return expectedSig === signature;
}

async function createAppJWT(appId: string, privateKey: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return await jwt.sign(
    { iat: now - 60, exp: now + 9 * 60, iss: appId },
    privateKey,
    { algorithm: "RS256" }
  );
}

async function getInstallationToken(appJwt: string, installationId: number): Promise<string> {
  const res = await fetch(
    `https://api.github.com/app/installations/${installationId}/access_tokens`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${appJwt}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "PolyglotCI",
      },
    }
  );
  const data: any = await res.json();
  if (!res.ok) throw new Error("Failed to get installation token: " + JSON.stringify(data));
  return data.token;
}

async function getChangedFiles(
  installationToken: string,
  owner: string,
  repo: string,
  prNumber: number
): Promise<any[]> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/pulls/${prNumber}/files`,
    {
      headers: {
        Authorization: `Bearer ${installationToken}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "PolyglotCI",
      },
    }
  );
  const data: any = await res.json();
  if (!res.ok) throw new Error("Failed to get PR files: " + JSON.stringify(data));
  return data;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method !== "POST") {
      return new Response("PolyglotCI is running", { status: 200 });
    }

    const payload = await request.text();
    const signature = request.headers.get("x-hub-signature-256");
    const valid = await verifySignature(payload, signature, env.GITHUB_WEBHOOK_SECRET);
    if (!valid) {
      return new Response("Invalid signature", { status: 401 });
    }

    const event = request.headers.get("x-github-event");
    const data = JSON.parse(payload);

    if (event === "pull_request" && ["opened", "synchronize", "reopened"].includes(data.action)) {
      try {
        const appJwt = await createAppJWT(env.GITHUB_APP_ID, env.GITHUB_PRIVATE_KEY);
        const installationToken = await getInstallationToken(appJwt, data.installation.id);
        const owner = data.repository.owner.login;
        const repo = data.repository.name;
        const prNumber = data.pull_request.number;

        const files = await getChangedFiles(installationToken, owner, repo, prNumber);
        console.log(
          `PR #${prNumber} in ${owner}/${repo} changed ${files.length} file(s):`,
          files.map((f) => f.filename).join(", ")
        );
      } catch (err) {
        console.log("Error fetching PR files:", err);
      }
    }

    return new Response("OK", { status: 200 });
  },
};

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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method !== "POST") {
      return new Response("PolyglotCI is running", { status: 200 });
    }

    const payload = await request.text();
    const signature = request.headers.get("x-hub-signature-256");

    const valid = await verifySignature(payload, signature, env.GITHUB_WEBHOOK_SECRET);
    if (!valid) {
      console.log("Signature verification FAILED");
      return new Response("Invalid signature", { status: 401 });
    }

    const event = request.headers.get("x-github-event");
    console.log("Verified webhook received. Event type:", event);

    if (event === "pull_request") {
      const data = JSON.parse(payload);
      console.log("PR action:", data.action, "| PR number:", data.pull_request?.number);
    }

    return new Response("OK", { status: 200 });
  },
};

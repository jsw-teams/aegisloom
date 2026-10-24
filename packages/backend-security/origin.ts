import { digest } from "../core/types.js";

/** Independent origin credential; never reuse an administrator or end-user credential. */
export async function createOriginVerifier(tokens: readonly string[]) {
  if (
    !tokens.length ||
    tokens.length > 2 ||
    new Set(tokens).size !== tokens.length ||
    tokens.some((token) => !/^[\x21-\x7e]{32,2048}$/.test(token))
  )
    throw new Error(
      "Provide one or two distinct origin secrets (32..2048 visible ASCII characters)",
    );
  const hashes = await Promise.all(tokens.map((token) => digest(token)));
  return async (request: Request): Promise<boolean> => {
    const supplied = request.headers.get("x-shield-origin-auth") ?? "";
    if (!/^[\x21-\x7e]{32,2048}$/.test(supplied)) return false;
    const hash = await digest(supplied);
    let accepted = 0;
    for (const expected of hashes) {
      let difference = 0;
      for (let i = 0; i < 64; i++) difference |= hash.charCodeAt(i) ^ expected.charCodeAt(i);
      accepted |= Number(difference === 0);
    }
    return accepted !== 0;
  };
}

// Ed25519 signing via Node's built-in crypto (OpenSSL under the hood).
// No hand-rolled cryptography.
import {
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
  createPublicKey,
  createPrivateKey,
  KeyObject,
} from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

export function generateEd25519Keypair(): { publicPem: string; privatePem: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicPem: publicKey.export({ type: "spki", format: "pem" }) as string,
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
  };
}

export async function loadPublicKey(path: string): Promise<KeyObject> {
  return createPublicKey(await readFile(path, "utf8"));
}

export async function loadPrivateKey(path: string): Promise<KeyObject> {
  return createPrivateKey(await readFile(path, "utf8"));
}

export function signBytes(key: KeyObject, data: Buffer): Buffer {
  // Ed25519: algorithm arg must be null (PureEdDSA).
  return nodeSign(null, data, key);
}

export function verifyBytes(key: KeyObject, data: Buffer, signature: Buffer): boolean {
  return nodeVerify(null, data, key, signature);
}

export async function writeKeypairFiles(dir: string): Promise<{ publicPath: string; privatePath: string }> {
  const { publicPem, privatePem } = generateEd25519Keypair();
  const publicPath = `${dir}/public_key.pem`;
  const privatePath = `${dir}/private_key.pem`;
  await writeFile(publicPath, publicPem);
  await writeFile(privatePath, privatePem, { mode: 0o600 });
  return { publicPath, privatePath };
}
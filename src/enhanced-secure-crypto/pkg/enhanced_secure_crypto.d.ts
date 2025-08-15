/* tslint:disable */
/* eslint-disable */
export function main(): void;
export function array_buffer_to_base64(buffer: Uint8Array): string;
export function base64_to_array_buffer(base64_str: string): Uint8Array;
export function hash_sha256(data: Uint8Array): Uint8Array;
export function hash_sha384(data: Uint8Array): Uint8Array;
export class EnhancedSecureCryptoUtils {
  free(): void;
  constructor();
  generate_secure_password(): string;
  generate_salt(): Uint8Array;
  encrypt_data(data: string, password: string): string;
  decrypt_data(encrypted_data: string, password: string): string;
  generate_ecdsa_keypair(): any;
  sign_data(private_key_bytes: Uint8Array, data: string): Uint8Array;
  verify_signature(public_key_bytes: Uint8Array, signature: Uint8Array, data: string): boolean;
  calculate_key_fingerprint(key_data: Uint8Array): string;
  generate_verification_code(): string;
  generate_mutual_auth_challenge(): any;
  sanitize_message(message: string): string;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly main: () => void;
  readonly __wbg_enhancedsecurecryptoutils_free: (a: number, b: number) => void;
  readonly enhancedsecurecryptoutils_new: () => number;
  readonly enhancedsecurecryptoutils_generate_secure_password: (a: number) => [number, number];
  readonly enhancedsecurecryptoutils_generate_salt: (a: number) => [number, number];
  readonly enhancedsecurecryptoutils_encrypt_data: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly enhancedsecurecryptoutils_decrypt_data: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly enhancedsecurecryptoutils_generate_ecdsa_keypair: (a: number) => [number, number, number];
  readonly enhancedsecurecryptoutils_sign_data: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly enhancedsecurecryptoutils_verify_signature: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
  readonly enhancedsecurecryptoutils_calculate_key_fingerprint: (a: number, b: number, c: number) => [number, number];
  readonly enhancedsecurecryptoutils_generate_verification_code: (a: number) => [number, number];
  readonly enhancedsecurecryptoutils_generate_mutual_auth_challenge: (a: number) => [number, number, number];
  readonly enhancedsecurecryptoutils_sanitize_message: (a: number, b: number, c: number) => [number, number, number, number];
  readonly array_buffer_to_base64: (a: number, b: number) => [number, number];
  readonly base64_to_array_buffer: (a: number, b: number) => [number, number, number, number];
  readonly hash_sha256: (a: number, b: number) => [number, number];
  readonly hash_sha384: (a: number, b: number) => [number, number];
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_2: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;

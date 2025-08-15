use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use ring::{
    aead::{self, AES_256_GCM, LessSafeKey, UnboundKey},
    digest::{SHA256, SHA384},
    rand::{SecureRandom, SystemRandom},
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1},
    pbkdf2,
};
use std::time::{SystemTime, UNIX_EPOCH};

// Включение panic hook для лучшей отладки в WASM
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}

// Основные структуры данных
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedPackage {
    pub version: String,
    pub salt: Vec<u8>,
    pub iv: Vec<u8>,
    pub data: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CryptoKeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub algorithm: String,
    pub curve: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuthChallenge {
    pub challenge: Vec<u8>,
    pub timestamp: u64,
    pub nonce: Vec<u8>,
    pub version: String,
}

// Главный класс
#[wasm_bindgen]
pub struct EnhancedSecureCryptoUtils {
    rng: SystemRandom,
}

#[wasm_bindgen]
impl EnhancedSecureCryptoUtils {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }

    // Генерация безопасного пароля
    #[wasm_bindgen]
    pub fn generate_secure_password(&self) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut password = Vec::with_capacity(16);
        
        for _ in 0..16 {
            let mut byte = [0u8; 1];
            self.rng.fill(&mut byte).unwrap();
            let index = (byte[0] as usize) % CHARS.len();
            password.push(CHARS[index]);
        }
        
        String::from_utf8(password).unwrap()
    }

    // Генерация соли (64 байта)
    #[wasm_bindgen]
    pub fn generate_salt(&self) -> Vec<u8> {
        let mut salt = vec![0u8; 64];
        self.rng.fill(&mut salt).unwrap();
        salt
    }

    // Шифрование данных с PBKDF2 и AES-GCM
    #[wasm_bindgen]
    pub fn encrypt_data(&self, data: &str, password: &str) -> Result<String, JsValue> {
        let salt = self.generate_salt();
        let iterations = 100_000;
        
        // Вывод ключа через PBKDF2
        let mut key_bytes = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(iterations).unwrap(),
            &salt,
            password.as_bytes(),
            &mut key_bytes,
        );
        
        // Создание ключа AES-GCM
        let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)
            .map_err(|e| JsValue::from_str(&format!("Key creation failed: {}", e)))?;
        let key = LessSafeKey::new(unbound_key);
        
        // Генерация IV
        let mut iv = [0u8; 12];
        self.rng.fill(&mut iv).unwrap();
        
        // Шифрование
        let mut data_bytes = data.as_bytes().to_vec();
        key.seal_in_place_append_tag(aead::Nonce::assume_unique_for_key(iv), aead::Aad::empty(), &mut data_bytes)
            .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;
        
        let package = EncryptedPackage {
            version: "1.0".to_string(),
            salt,
            iv: iv.to_vec(),
            data: data_bytes,
            timestamp: current_timestamp(),
        };
        
        let package_json = serde_json::to_string(&package)
            .map_err(|e| JsValue::from_str(&format!("Serialization failed: {}", e)))?;
        
        Ok(base64::encode(&package_json))
    }

    // Расшифровка данных
    #[wasm_bindgen]
    pub fn decrypt_data(&self, encrypted_data: &str, password: &str) -> Result<String, JsValue> {
        // Декодирование base64
        let package_json = base64::decode(encrypted_data)
            .map_err(|e| JsValue::from_str(&format!("Base64 decode failed: {}", e)))?;
        
        let package_str = String::from_utf8(package_json)
            .map_err(|e| JsValue::from_str(&format!("UTF-8 decode failed: {}", e)))?;
        
        let package: EncryptedPackage = serde_json::from_str(&package_str)
            .map_err(|e| JsValue::from_str(&format!("Deserialization failed: {}", e)))?;
        
        // Вывод ключа
        let mut key_bytes = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(100_000).unwrap(),
            &package.salt,
            password.as_bytes(),
            &mut key_bytes,
        );
        
        let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)
            .map_err(|e| JsValue::from_str(&format!("Key creation failed: {}", e)))?;
        let key = LessSafeKey::new(unbound_key);
        
        // Расшифровка
        let mut encrypted_data = package.data;
        let iv_array: [u8; 12] = package.iv.try_into()
            .map_err(|_| JsValue::from_str("Invalid IV length"))?;
        
        let decrypted = key.open_in_place(aead::Nonce::assume_unique_for_key(iv_array), aead::Aad::empty(), &mut encrypted_data)
            .map_err(|e| JsValue::from_str(&format!("Decryption failed: {}", e)))?;
        
        String::from_utf8(decrypted.to_vec())
            .map_err(|e| JsValue::from_str(&format!("UTF-8 conversion failed: {}", e)))
    }

    // Генерация ключевой пары ECDSA P-384
    #[wasm_bindgen]
    pub fn generate_ecdsa_keypair(&self) -> Result<JsValue, JsValue> {
        let rng = &self.rng;
        let key_pair_doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, rng)
            .map_err(|e| JsValue::from_str(&format!("Key generation failed: {}", e)))?;
        
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, key_pair_doc.as_ref())
            .map_err(|e| JsValue::from_str(&format!("Key pair parsing failed: {}", e)))?;
        
        let private_key = key_pair_doc.as_ref().to_vec();
        let public_key = key_pair.public_key().as_ref().to_vec();
        
        let keypair = CryptoKeyPair {
            private_key,
            public_key,
            algorithm: "ECDSA".to_string(),
            curve: "P-384".to_string(),
        };
        
        Ok(serde_wasm_bindgen::to_value(&keypair)?)
    }

    // Подпись данных
    #[wasm_bindgen]
    pub fn sign_data(&self, private_key_bytes: &[u8], data: &str) -> Result<Vec<u8>, JsValue> {
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, private_key_bytes)
            .map_err(|e| JsValue::from_str(&format!("Invalid private key: {}", e)))?;
        
        let signature = key_pair.sign(&self.rng, data.as_bytes())
            .map_err(|e| JsValue::from_str(&format!("Signing failed: {}", e)))?;
        
        Ok(signature.as_ref().to_vec())
    }

    // Проверка подписи
    #[wasm_bindgen]
    pub fn verify_signature(&self, public_key_bytes: &[u8], signature: &[u8], data: &str) -> Result<bool, JsValue> {
        let public_key = ring::signature::UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, public_key_bytes);
        
        match public_key.verify(data.as_bytes(), signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    // Вычисление отпечатка ключа
    #[wasm_bindgen]
    pub fn calculate_key_fingerprint(&self, key_data: &[u8]) -> String {
        let digest = ring::digest::digest(&SHA256, key_data);
        hex::encode(&digest.as_ref()[..12])
    }

    // Генерация кода верификации
    #[wasm_bindgen]
    pub fn generate_verification_code(&self) -> String {
        let mut bytes = [0u8; 6];
        self.rng.fill(&mut bytes).unwrap();
        
        bytes.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .chunks(2)
            .map(|chunk| chunk.join(""))
            .collect::<Vec<String>>()
            .join("-")
    }

    // Генерация вызова для взаимной аутентификации
    #[wasm_bindgen]
    pub fn generate_mutual_auth_challenge(&self) -> Result<JsValue, JsValue> {
        let mut challenge = vec![0u8; 48];
        self.rng.fill(&mut challenge).unwrap();
        
        let mut nonce = vec![0u8; 16];
        self.rng.fill(&mut nonce).unwrap();
        
        let auth_challenge = AuthChallenge {
            challenge,
            timestamp: current_timestamp(),
            nonce,
            version: "4.0".to_string(),
        };
        
        Ok(serde_wasm_bindgen::to_value(&auth_challenge)?)
    }

    // Очистка сообщения от вредоносного содержимого
    #[wasm_bindgen]
    pub fn sanitize_message(&self, message: &str) -> Result<String, JsValue> {
        if message.len() > 2000 {
            return Err(JsValue::from_str("Message too long"));
        }

        let sanitized = message
            .replace("<script", "&lt;script")
            .replace("</script>", "&lt;/script&gt;")
            .replace("javascript:", "")
            .replace("data:", "")
            .replace("vbscript:", "")
            .replace("onload=", "")
            .replace("onerror=", "")
            .replace("onclick=", "")
            .trim()
            .to_string();

        Ok(sanitized)
    }
}

// Вспомогательные функции
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// Экспорт дополнительных утилит
#[wasm_bindgen]
pub fn array_buffer_to_base64(buffer: &[u8]) -> String {
    base64::encode(buffer)
}

#[wasm_bindgen]
pub fn base64_to_array_buffer(base64_str: &str) -> Result<Vec<u8>, JsValue> {
    base64::decode(base64_str)
        .map_err(|e| JsValue::from_str(&format!("Base64 decode error: {}", e)))
}

#[wasm_bindgen]
pub fn hash_sha256(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&SHA256, data).as_ref().to_vec()
}

#[wasm_bindgen]
pub fn hash_sha384(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&SHA384, data).as_ref().to_vec()
}
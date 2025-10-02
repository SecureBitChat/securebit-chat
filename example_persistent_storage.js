// Пример использования новой системы персистентного хранения ключей
import { 
    EnhancedSecureWebRTCManager,
    SecureMasterKeyManager,
    SecureIndexedDBWrapper,
    SecurePersistentKeyStorage
} from './src/network/EnhancedSecureWebRTCManager.js';

// Создание менеджера WebRTC с персистентным хранением
const webrtcManager = new EnhancedSecureWebRTCManager(
    (message) => console.log('Received:', message),
    (status) => console.log('Status:', status),
    (keyData) => console.log('Key exchange:', keyData),
    (verificationData) => console.log('Verification required:', verificationData)
);

// Настройка callback для запроса пароля
webrtcManager.setMasterKeyPasswordCallback((isRetry, callback) => {
    const message = isRetry ? 
        'Неверный пароль. Введите мастер-пароль повторно:' : 
        'Введите мастер-пароль для разблокировки хранилища ключей:';
    
    // В реальном приложении используйте безопасный UI
    const password = prompt(message);
    callback(password);
});

// Настройка callback для истечения сессии
webrtcManager.setMasterKeySessionExpiredCallback((reason) => {
    console.warn(`Сессия мастер-ключа истекла: ${reason}`);
    alert(`Сессия заблокирована: ${reason}. Потребуется повторный ввод пароля.`);
});

// Демонстрация работы с персистентным хранением
async function demonstratePersistentStorage() {
    try {
        console.log('=== Демонстрация персистентного хранения ключей ===');
        
        // 1. Создание и сохранение extractable ключа
        console.log('\n1. Создание extractable ключа для демонстрации...');
        const testKey = await crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true, // extractable = true для персистентного хранения
            ['encrypt', 'decrypt']
        );
        
        // 2. Сохранение ключа (автоматически зашифруется и сохранится в IndexedDB)
        console.log('2. Сохранение ключа в персистентное хранилище...');
        const keyId = 'demo_persistent_key_' + Date.now();
        const stored = await webrtcManager._secureKeyStorage.storeKey(keyId, testKey, {
            purpose: 'demonstration',
            algorithm: 'AES-GCM'
        });
        
        if (stored) {
            console.log('✅ Ключ успешно сохранен в зашифрованном виде в IndexedDB');
        } else {
            console.log('❌ Ошибка сохранения ключа');
            return;
        }
        
        // 3. Получение статистики хранилища
        console.log('\n3. Статистика хранилища:');
        const stats = await webrtcManager._secureKeyStorage.getStorageStats();
        console.log('Статистика:', JSON.stringify(stats, null, 2));
        
        // 4. Список всех ключей
        console.log('\n4. Список всех ключей:');
        const allKeys = await webrtcManager._secureKeyStorage.listAllKeys();
        console.log('Ключи:', JSON.stringify(allKeys, null, 2));
        
        // 5. Симуляция перезапуска приложения (очистка памяти)
        console.log('\n5. Симуляция перезапуска приложения...');
        webrtcManager._secureKeyStorage._keyReferences.clear();
        console.log('Память очищена. Ключи остались только в IndexedDB.');
        
        // 6. Восстановление ключа из IndexedDB
        console.log('\n6. Восстановление ключа из IndexedDB...');
        const restoredKey = await webrtcManager._secureKeyStorage.retrieveKey(keyId);
        
        if (restoredKey) {
            console.log('✅ Ключ успешно восстановлен из IndexedDB как non-extractable');
            console.log('Тип ключа:', restoredKey.type);
            console.log('Алгоритм:', restoredKey.algorithm.name);
            console.log('Extractable:', restoredKey.extractable); // Должно быть false
        } else {
            console.log('❌ Ошибка восстановления ключа');
        }
        
        // 7. Тест шифрования с восстановленным ключом
        console.log('\n7. Тест шифрования с восстановленным ключом...');
        const testData = new TextEncoder().encode('Тестовые данные для шифрования');
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            restoredKey,
            testData
        );
        
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            restoredKey,
            encrypted
        );
        
        const decryptedText = new TextDecoder().decode(decrypted);
        console.log('✅ Шифрование/расшифровка успешно:', decryptedText);
        
        // 8. Очистка демонстрационных данных
        console.log('\n8. Очистка демонстрационных данных...');
        await webrtcManager._secureKeyStorage.deleteKey(keyId);
        console.log('✅ Демонстрационный ключ удален');
        
        console.log('\n=== Демонстрация завершена ===');
        
    } catch (error) {
        console.error('Ошибка демонстрации:', error);
    }
}

// Демонстрация безопасности
async function demonstrateSecurity() {
    console.log('\n=== Демонстрация безопасности ===');
    
    try {
        // Попытка прямого доступа к IndexedDB
        const request = indexedDB.open('SecureKeyStorage');
        request.onsuccess = (event) => {
            const db = event.target.result;
            const transaction = db.transaction(['encrypted_keys'], 'readonly');
            const store = transaction.objectStore('encrypted_keys');
            const getAllRequest = store.getAll();
            
            getAllRequest.onsuccess = () => {
                const keys = getAllRequest.result;
                console.log('🔍 Прямой доступ к IndexedDB:');
                
                if (keys.length > 0) {
                    const firstKey = keys[0];
                    console.log('📦 Найден зашифрованный ключ:');
                    console.log('- ID:', firstKey.keyId);
                    console.log('- Зашифрованные данные (первые 20 байт):', 
                        Array.from(firstKey.encryptedData.slice(0, 20))
                             .map(b => b.toString(16).padStart(2, '0')).join(' '));
                    console.log('- IV:', Array.from(firstKey.iv)
                                      .map(b => b.toString(16).padStart(2, '0')).join(' '));
                    console.log('✅ Данные зашифрованы - невозможно извлечь JWK без мастер-ключа!');
                } else {
                    console.log('📭 Нет сохраненных ключей в IndexedDB');
                }
            };
        };
        
    } catch (error) {
        console.error('Ошибка проверки безопасности:', error);
    }
}

// Запуск демонстрации
console.log('Запуск демонстрации персистентного хранения ключей...');
console.log('При первом запуске будет запрошен мастер-пароль.');

// Последовательный запуск демонстраций
demonstratePersistentStorage()
    .then(() => demonstrateSecurity())
    .catch(error => console.error('Ошибка:', error));

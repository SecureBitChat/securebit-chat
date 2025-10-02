// Пример использования новой системы мастер-ключей
import { EnhancedSecureWebRTCManager } from './src/network/EnhancedSecureWebRTCManager.js';

// Создание менеджера WebRTC
const webrtcManager = new EnhancedSecureWebRTCManager(
    (message) => console.log('Received:', message),
    (status) => console.log('Status:', status),
    (keyData) => console.log('Key exchange:', keyData),
    (verificationData) => console.log('Verification required:', verificationData)
);

// Настройка callback для запроса пароля
webrtcManager.setMasterKeyPasswordCallback((isRetry, callback) => {
    // В реальном приложении здесь должен быть UI для ввода пароля
    const message = isRetry ? 
        'Неверный пароль. Введите мастер-пароль повторно:' : 
        'Введите мастер-пароль для разблокировки безопасного хранилища:';
    
    // Пример с prompt (в реальном приложении используйте модальное окно)
    const password = prompt(message);
    callback(password);
});

// Настройка callback для истечения сессии
webrtcManager.setMasterKeySessionExpiredCallback((reason) => {
    console.warn(`Сессия мастер-ключа истекла: ${reason}`);
    
    // Уведомить пользователя
    if (reason === 'inactivity') {
        alert('Сессия заблокирована из-за неактивности. Потребуется повторный ввод пароля.');
    } else if (reason === 'timeout') {
        alert('Сессия истекла по таймауту. Потребуется повторный ввод пароля.');
    }
});

// Проверка статуса мастер-ключа
console.log('Мастер-ключ разблокирован:', webrtcManager.isMasterKeyUnlocked());
console.log('Статус сессии:', webrtcManager.getMasterKeySessionStatus());

// Ручная блокировка мастер-ключа
// webrtcManager.lockMasterKey();

// Пример использования в реальном приложении:
async function initializeSecureConnection() {
    try {
        // При первом обращении к зашифрованным ключам будет запрошен пароль
        const offer = await webrtcManager.createSecureOffer();
        console.log('Secure offer created:', offer);
        
        // Мастер-ключ теперь разблокирован и будет автоматически заблокирован:
        // - через 15 минут бездействия
        // - через 5 минут после потери фокуса окна
        // - при ручном вызове lockMasterKey()
        
    } catch (error) {
        console.error('Failed to create secure offer:', error);
    }
}

// Запуск примера
initializeSecureConnection();

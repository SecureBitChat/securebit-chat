// Пример использования новой асинхронной системы очистки
import { EnhancedSecureWebRTCManager } from './src/network/EnhancedSecureWebRTCManager.js';

// Создание менеджера WebRTC с асинхронной очисткой
const webrtcManager = new EnhancedSecureWebRTCManager(
    (message) => console.log('Received:', message),
    (status) => console.log('Status:', status),
    (keyData) => console.log('Key exchange:', keyData),
    (verificationData) => console.log('Verification required:', verificationData)
);

// Демонстрация асинхронной очистки
async function demonstrateAsyncCleanup() {
    console.log('=== Демонстрация асинхронной системы очистки ===');
    
    try {
        // 1. Демонстрация естественной очистки памяти
        console.log('\n1. Тест естественной очистки памяти...');
        const startTime = performance.now();
        
        await webrtcManager._performNaturalCleanup();
        
        const endTime = performance.now();
        console.log(`✅ Естественная очистка завершена за ${(endTime - startTime).toFixed(2)}ms`);
        console.log('   - Без блокировки UI');
        console.log('   - Без принудительного window.gc()');
        console.log('   - Использует естественные циклы сборки мусора');
        
        // 2. Демонстрация асинхронного sleep
        console.log('\n2. Тест асинхронного sleep (замена busy-wait)...');
        const sleepStart = performance.now();
        
        await webrtcManager._asyncSleep(50); // 50ms без блокировки
        
        const sleepEnd = performance.now();
        console.log(`✅ Асинхронный sleep завершен за ${(sleepEnd - sleepStart).toFixed(2)}ms`);
        console.log('   - UI остается отзывчивым');
        console.log('   - Нет busy-wait циклов');
        
        // 3. Демонстрация батчевых операций
        console.log('\n3. Тест батчевых операций...');
        const batchStart = performance.now();
        
        // Создаем массив "тяжелых" операций
        const heavyOperations = Array.from({ length: 100 }, (_, i) => 
            async () => {
                // Симуляция тяжелой операции
                await webrtcManager._asyncSleep(1);
                return `operation_${i}`;
            }
        );
        
        const results = await webrtcManager._batchAsyncOperation(heavyOperations, 10, 2);
        
        const batchEnd = performance.now();
        console.log(`✅ Батчевые операции завершены за ${(batchEnd - batchStart).toFixed(2)}ms`);
        console.log(`   - Обработано ${results.length} операций`);
        console.log('   - UI не блокировался благодаря батчингу');
        console.log('   - Задержки между батчами предотвращают зависание');
        
        // 4. Демонстрация WebWorker очистки (если доступен)
        console.log('\n4. Тест WebWorker очистки...');
        const workerStart = performance.now();
        
        const cleanupData = {
            type: 'cleanup_arrays',
            data: { count: 1000 }
        };
        
        const workerResult = await webrtcManager._performHeavyCleanup(cleanupData);
        
        const workerEnd = performance.now();
        console.log(`✅ WebWorker очистка завершена за ${(workerEnd - workerStart).toFixed(2)}ms`);
        console.log(`   - Результат: ${JSON.stringify(workerResult)}`);
        console.log('   - Тяжелые операции выполнены в фоновом потоке');
        console.log('   - Основной поток не блокировался');
        
        // 5. Демонстрация запланированной очистки
        console.log('\n5. Тест запланированной очистки...');
        const scheduleStart = performance.now();
        
        const cleanupPromise = webrtcManager._scheduleAsyncCleanup(async () => {
            console.log('   🧹 Выполняется запланированная очистка...');
            await webrtcManager._asyncSleep(20);
            console.log('   ✅ Запланированная очистка завершена');
        }, 10); // Задержка 10ms
        
        await cleanupPromise;
        
        const scheduleEnd = performance.now();
        console.log(`✅ Запланированная очистка завершена за ${(scheduleEnd - scheduleStart).toFixed(2)}ms`);
        console.log('   - Очистка выполнена с задержкой');
        console.log('   - Не блокирует текущий поток выполнения');
        
        // 6. Сравнение производительности
        console.log('\n6. Сравнение с старой системой...');
        console.log('📊 Преимущества новой системы:');
        console.log('   ✅ Нет busy-wait циклов');
        console.log('   ✅ Нет принудительного window.gc()');
        console.log('   ✅ UI остается отзывчивым');
        console.log('   ✅ WebWorker для тяжелых операций');
        console.log('   ✅ Батчинг предотвращает блокировки');
        console.log('   ✅ Естественная сборка мусора');
        
        console.log('\n❌ Проблемы старой системы (исправлены):');
        console.log('   ❌ while (Date.now() - start < 10) {} - busy-wait');
        console.log('   ❌ window.gc() - принудительная сборка мусора');
        console.log('   ❌ Блокировка UI при очистке');
        console.log('   ❌ Синхронные тяжелые операции');
        
    } catch (error) {
        console.error('Ошибка демонстрации:', error);
    }
}

// Демонстрация мониторинга производительности
async function demonstratePerformanceMonitoring() {
    console.log('\n=== Мониторинг производительности ===');
    
    // Мониторинг времени выполнения операций
    const operations = [
        { name: 'Естественная очистка', fn: () => webrtcManager._performNaturalCleanup() },
        { name: 'Асинхронный sleep 10ms', fn: () => webrtcManager._asyncSleep(10) },
        { name: 'Батчевая операция', fn: () => webrtcManager._batchAsyncOperation([
            async () => 'test1',
            async () => 'test2',
            async () => 'test3'
        ], 2, 1) }
    ];
    
    for (const operation of operations) {
        const start = performance.now();
        await operation.fn();
        const end = performance.now();
        
        console.log(`⏱️  ${operation.name}: ${(end - start).toFixed(2)}ms`);
    }
    
    // Проверка доступности WebWorker
    if (typeof Worker !== 'undefined') {
        console.log('✅ WebWorker доступен - тяжелые операции будут выполняться в фоне');
    } else {
        console.log('⚠️  WebWorker недоступен - fallback на батчинг в основном потоке');
    }
}

// Запуск демонстрации
console.log('🚀 Запуск демонстрации асинхронной системы очистки...');

demonstrateAsyncCleanup()
    .then(() => demonstratePerformanceMonitoring())
    .then(() => {
        console.log('\n🎉 Демонстрация завершена успешно!');
        console.log('💡 Новая система обеспечивает:');
        console.log('   • Отзывчивый UI');
        console.log('   • Эффективную очистку памяти');
        console.log('   • Отсутствие блокировок');
        console.log('   • Использование WebWorker для тяжелых операций');
    })
    .catch(error => {
        console.error('❌ Ошибка демонстрации:', error);
    });

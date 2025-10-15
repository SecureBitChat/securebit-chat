/**
 * Web Bluetooth API Examples
 * 
 * This file contains examples of how to use the Web Bluetooth API
 * for device discovery and connection.
 */

// Example 1: Basic device discovery
async function discoverBluetoothDevices() {
    try {
        console.log('Requesting Bluetooth device...');
        
        const device = await navigator.bluetooth.requestDevice({
            filters: [
                { services: ['battery_service'] },
                { services: ['device_information'] },
                { name: 'MyDevice' },
                { namePrefix: 'My' }
            ],
            optionalServices: ['battery_service', 'device_information']
        });
        
        console.log('Device selected:', device.name);
        console.log('Device ID:', device.id);
        
        return device;
    } catch (error) {
        console.error('Error discovering device:', error);
        throw error;
    }
}

// Example 2: Connect to device and read characteristics
async function connectAndReadData(device) {
    try {
        console.log('Connecting to device...');
        const server = await device.gatt.connect();
        
        console.log('Getting primary service...');
        const service = await server.getPrimaryService('battery_service');
        
        console.log('Getting characteristic...');
        const characteristic = await service.getCharacteristic('battery_level');
        
        console.log('Reading value...');
        const value = await characteristic.readValue();
        const batteryLevel = value.getUint8(0);
        
        console.log('Battery level:', batteryLevel + '%');
        
        return batteryLevel;
    } catch (error) {
        console.error('Error connecting to device:', error);
        throw error;
    }
}

// Example 3: Listen for characteristic changes
async function listenForChanges(device) {
    try {
        const server = await device.gatt.connect();
        const service = await server.getPrimaryService('battery_service');
        const characteristic = await service.getCharacteristic('battery_level');
        
        // Start notifications
        await characteristic.startNotifications();
        
        // Listen for changes
        characteristic.addEventListener('characteristicvaluechanged', (event) => {
            const value = event.target.value;
            const batteryLevel = value.getUint8(0);
            console.log('Battery level changed:', batteryLevel + '%');
        });
        
        console.log('Listening for battery level changes...');
    } catch (error) {
        console.error('Error setting up notifications:', error);
        throw error;
    }
}

// Example 4: Write data to characteristic
async function writeData(device, data) {
    try {
        const server = await device.gatt.connect();
        const service = await server.getPrimaryService('custom_service');
        const characteristic = await service.getCharacteristic('custom_characteristic');
        
        // Convert data to ArrayBuffer
        const buffer = new TextEncoder().encode(data);
        
        // Write data
        await characteristic.writeValue(buffer);
        console.log('Data written successfully');
    } catch (error) {
        console.error('Error writing data:', error);
        throw error;
    }
}

// Example 5: Complete workflow
async function completeBluetoothWorkflow() {
    try {
        // Step 1: Discover device
        const device = await discoverBluetoothDevices();
        
        // Step 2: Connect and read data
        const batteryLevel = await connectAndReadData(device);
        
        // Step 3: Listen for changes
        await listenForChanges(device);
        
        // Step 4: Write data (if needed)
        // await writeData(device, 'Hello Bluetooth!');
        
        console.log('Bluetooth workflow completed successfully');
        return { device, batteryLevel };
    } catch (error) {
        console.error('Bluetooth workflow failed:', error);
        throw error;
    }
}

// Export functions for use in other modules
export {
    discoverBluetoothDevices,
    connectAndReadData,
    listenForChanges,
    writeData,
    completeBluetoothWorkflow
};

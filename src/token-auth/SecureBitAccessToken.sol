// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title SecureBit Access Token
 * @dev ERC-721 токен для доступа к SecureBit сервису
 * Поддерживает месячные и годовые подписки
 */
contract SecureBitAccessToken is ERC721, Ownable, ReentrancyGuard, Pausable {
    using Counters for Counters.Counter;
    
    Counters.Counter private _tokenIds;
    
    // Структура для хранения информации о токене
    struct TokenInfo {
        uint256 tokenId;
        address owner;
        uint256 expiryDate;
        TokenType tokenType;
        bool isActive;
        uint256 createdAt;
        string metadata;
    }
    
    // Типы токенов
    enum TokenType { MONTHLY, YEARLY }
    
    // Маппинг токенов
    mapping(uint256 => TokenInfo) public tokens;
    mapping(address => uint256[]) public userTokens;
    
    // Цены токенов (в wei)
    uint256 public monthlyPrice = 0.01 ether;  // 0.01 ETH
    uint256 public yearlyPrice = 0.1 ether;    // 0.1 ETH
    
    // События
    event TokenMinted(uint256 indexed tokenId, address indexed owner, TokenType tokenType, uint256 expiryDate);
    event TokenExpired(uint256 indexed tokenId, address indexed owner);
    event TokenRenewed(uint256 indexed tokenId, uint256 newExpiryDate);
    event PriceUpdated(TokenType tokenType, uint256 oldPrice, uint256 newPrice);
    event TokenDeactivated(uint256 indexed tokenId, address indexed owner);
    event TokenTransferred(uint256 indexed tokenId, address indexed from, address indexed to);
    
    // Модификаторы
    modifier tokenExists(uint256 tokenId) {
        require(_exists(tokenId), "Token does not exist");
        _;
    }
    
    modifier tokenActive(uint256 tokenId) {
        require(tokens[tokenId].isActive, "Token is not active");
        _;
    }
    
    modifier onlyTokenOwner(uint256 tokenId) {
        require(ownerOf(tokenId) == msg.sender, "Not token owner");
        _;
    }
    
    constructor() ERC721("SecureBit Access Token", "SBAT") Ownable(msg.sender) {
        // Конструктор автоматически устанавливает владельца
    }
    
    /**
     * @dev Покупка месячного токена
     */
    function purchaseMonthlyToken() external payable nonReentrant whenNotPaused {
        require(msg.value >= monthlyPrice, "Insufficient payment for monthly token");
        
        uint256 newTokenId = _mintToken(msg.sender, TokenType.MONTHLY);
        
        // Возвращаем излишки
        if (msg.value > monthlyPrice) {
            payable(msg.sender).transfer(msg.value - monthlyPrice);
        }
        
        emit TokenMinted(newTokenId, msg.sender, TokenType.MONTHLY, tokens[newTokenId].expiryDate);
    }
    
    /**
     * @dev Покупка годового токена
     */
    function purchaseYearlyToken() external payable nonReentrant whenNotPaused {
        require(msg.value >= yearlyPrice, "Insufficient payment for yearly token");
        
        uint256 newTokenId = _mintToken(msg.sender, TokenType.YEARLY);
        
        // Возвращаем излишки
        if (msg.value > yearlyPrice) {
            payable(msg.sender).transfer(msg.value - yearlyPrice);
        }
        
        emit TokenMinted(newTokenId, msg.sender, TokenType.YEARLY, tokens[newTokenId].expiryDate);
    }
    
    /**
     * @dev Покупка нескольких токенов одного типа
     */
    function purchaseMultipleTokens(TokenType tokenType, uint256 quantity) external payable nonReentrant whenNotPaused {
        require(quantity > 0 && quantity <= 10, "Invalid quantity (1-10)");
        
        uint256 totalPrice = tokenType == TokenType.MONTHLY ? monthlyPrice * quantity : yearlyPrice * quantity;
        require(msg.value >= totalPrice, "Insufficient payment");
        
        uint256[] memory newTokenIds = new uint256[](quantity);
        
        for (uint256 i = 0; i < quantity; i++) {
            newTokenIds[i] = _mintToken(msg.sender, tokenType);
            emit TokenMinted(newTokenIds[i], msg.sender, tokenType, tokens[newTokenIds[i]].expiryDate);
        }
        
        // Возвращаем излишки
        if (msg.value > totalPrice) {
            payable(msg.sender).transfer(msg.value - totalPrice);
        }
    }
    
    /**
     * @dev Внутренняя функция создания токена
     */
    function _mintToken(address owner, TokenType tokenType) internal returns (uint256) {
        _tokenIds.increment();
        uint256 newTokenId = _tokenIds.current();
        
        uint256 expiryDate;
        if (tokenType == TokenType.MONTHLY) {
            expiryDate = block.timestamp + 30 days;
        } else {
            expiryDate = block.timestamp + 365 days;
        }
        
        TokenInfo memory newToken = TokenInfo({
            tokenId: newTokenId,
            owner: owner,
            expiryDate: expiryDate,
            tokenType: tokenType,
            isActive: true,
            createdAt: block.timestamp,
            metadata: ""
        });
        
        tokens[newTokenId] = newToken;
        userTokens[owner].push(newTokenId);
        
        _safeMint(owner, newTokenId);
        
        return newTokenId;
    }
    
    /**
     * @dev Проверка валидности токена
     */
    function isTokenValid(uint256 tokenId) external view returns (bool) {
        if (!_exists(tokenId)) return false;
        
        TokenInfo memory token = tokens[tokenId];
        return token.isActive && block.timestamp < token.expiryDate;
    }
    
    /**
     * @dev Получение информации о токене
     */
    function getTokenInfo(uint256 tokenId) external view tokenExists(tokenId) returns (TokenInfo memory) {
        return tokens[tokenId];
    }
    
    /**
     * @dev Получение всех токенов пользователя
     */
    function getUserTokens(address user) external view returns (uint256[] memory) {
        return userTokens[user];
    }
    
    /**
     * @dev Получение активных токенов пользователя
     */
    function getActiveUserTokens(address user) external view returns (uint256[] memory) {
        uint256[] memory allTokens = userTokens[user];
        uint256 activeCount = 0;
        
        // Подсчитываем активные токены
        for (uint256 i = 0; i < allTokens.length; i++) {
            if (tokens[allTokens[i]].isActive && block.timestamp < tokens[allTokens[i]].expiryDate) {
                activeCount++;
            }
        }
        
        // Создаем массив активных токенов
        uint256[] memory activeTokens = new uint256[](activeCount);
        uint256 currentIndex = 0;
        
        for (uint256 i = 0; i < allTokens.length; i++) {
            if (tokens[allTokens[i]].isActive && block.timestamp < tokens[allTokens[i]].expiryDate) {
                activeTokens[currentIndex] = allTokens[i];
                currentIndex++;
            }
        }
        
        return activeTokens;
    }
    
    /**
     * @dev Проверка, есть ли у пользователя активный токен
     */
    function hasActiveToken(address user) external view returns (bool) {
        uint256[] memory userTokenList = userTokens[user];
        
        for (uint256 i = 0; i < userTokenList.length; i++) {
            if (tokens[userTokenList[i]].isActive && block.timestamp < tokens[userTokenList[i]].expiryDate) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * @dev Деактивация токена (только владельцем)
     */
    function deactivateToken(uint256 tokenId) external onlyTokenOwner(tokenId) tokenActive(tokenId) {
        tokens[tokenId].isActive = false;
        emit TokenDeactivated(tokenId, msg.sender);
    }
    
    /**
     * @dev Продление токена
     */
    function renewToken(uint256 tokenId) external payable nonReentrant onlyTokenOwner(tokenId) whenNotPaused {
        TokenInfo memory token = tokens[tokenId];
        require(token.isActive, "Token is not active");
        
        uint256 renewalPrice;
        uint256 additionalTime;
        
        if (token.tokenType == TokenType.MONTHLY) {
            renewalPrice = monthlyPrice;
            additionalTime = 30 days;
        } else {
            renewalPrice = yearlyPrice;
            additionalTime = 365 days;
        }
        
        require(msg.value >= renewalPrice, "Insufficient payment for renewal");
        
        // Обновляем дату истечения
        tokens[tokenId].expiryDate += additionalTime;
        
        // Возвращаем излишки
        if (msg.value > renewalPrice) {
            payable(msg.sender).transfer(msg.value - renewalPrice);
        }
        
        emit TokenRenewed(tokenId, tokens[tokenId].expiryDate);
    }
    
    /**
     * @dev Обновление цен (только владельцем)
     */
    function updatePrices(uint256 newMonthlyPrice, uint256 newYearlyPrice) external onlyOwner {
        require(newMonthlyPrice > 0 && newYearlyPrice > 0, "Prices must be greater than 0");
        
        uint256 oldMonthlyPrice = monthlyPrice;
        uint256 oldYearlyPrice = yearlyPrice;
        
        monthlyPrice = newMonthlyPrice;
        yearlyPrice = newYearlyPrice;
        
        emit PriceUpdated(TokenType.MONTHLY, oldMonthlyPrice, newMonthlyPrice);
        emit PriceUpdated(TokenType.YEARLY, oldYearlyPrice, newYearlyPrice);
    }
    
    /**
     * @dev Вывод средств (только владельцем)
     */
    function withdrawFunds() external onlyOwner {
        uint256 balance = address(this).balance;
        require(balance > 0, "No funds to withdraw");
        
        payable(owner()).transfer(balance);
    }
    
    /**
     * @dev Экстренная пауза контракта
     */
    function pause() external onlyOwner {
        _pause();
    }
    
    /**
     * @dev Снятие паузы
     */
    function unpause() external onlyOwner {
        _unpause();
    }
    
    /**
     * @dev Получение баланса контракта
     */
    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    /**
     * @dev Получение статистики
     */
    function getStats() external view returns (uint256 totalTokens, uint256 activeTokens, uint256 monthlyTokens, uint256 yearlyTokens) {
        totalTokens = _tokenIds.current();
        
        for (uint256 i = 1; i <= totalTokens; i++) {
            if (tokens[i].isActive && block.timestamp < tokens[i].expiryDate) {
                activeTokens++;
                
                if (tokens[i].tokenType == TokenType.MONTHLY) {
                    monthlyTokens++;
                } else {
                    yearlyTokens++;
                }
            }
        }
    }
    
    /**
     * @dev Удаление токена из массива пользователя
     */
    function _removeTokenFromUser(address user, uint256 tokenId) internal {
        uint256[] storage tokenList = userTokens[user];
        for (uint256 i = 0; i < tokenList.length; i++) {
            if (tokenList[i] == tokenId) {
                tokenList[i] = tokenList[tokenList.length - 1];
                tokenList.pop();
                break;
            }
        }
    }
    
    /**
     * @dev Переопределение функции _beforeTokenTransfer для обновления userTokens
     */
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 firstTokenId,
        uint256 batchSize
    ) internal virtual override {
        super._beforeTokenTransfer(from, to, firstTokenId, batchSize);
        
        // При трансфере обновляем userTokens и владельца токена
        if (from != address(0) && to != address(0)) {
            _removeTokenFromUser(from, firstTokenId);
            userTokens[to].push(firstTokenId);
            tokens[firstTokenId].owner = to;
            
            emit TokenTransferred(firstTokenId, from, to);
        }
    }
    
    /**
     * @dev Получение URI токена
     */
    function tokenURI(uint256 tokenId) public view virtual override tokenExists(tokenId) returns (string memory) {
        TokenInfo memory token = tokens[tokenId];
        
        // Создаем JSON метаданные
        string memory json = string(abi.encodePacked(
            '{"name": "SecureBit Access Token #', _toString(tokenId), '",',
            '"description": "Access token for SecureBit service",',
            '"attributes": [',
            '{"trait_type": "Type", "value": "', _tokenTypeToString(token.tokenType), '"},',
            '{"trait_type": "Expiry Date", "value": "', _toString(token.expiryDate), '"},',
            '{"trait_type": "Status", "value": "', token.isActive ? "Active" : "Inactive", '"},',
            '{"trait_type": "Created At", "value": "', _toString(token.createdAt), '"}',
            ']}'
        ));
        
        return string(abi.encodePacked('data:application/json;base64,', _base64Encode(bytes(json))));
    }
    
    /**
     * @dev Конвертация числа в строку
     */
    function _toString(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0";
        
        uint256 temp = value;
        uint256 digits;
        
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        
        bytes memory buffer = new bytes(digits);
        
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        
        return string(buffer);
    }
    
    /**
     * @dev Конвертация типа токена в строку
     */
    function _tokenTypeToString(TokenType tokenType) internal pure returns (string memory) {
        if (tokenType == TokenType.MONTHLY) return "Monthly";
        if (tokenType == TokenType.YEARLY) return "Yearly";
        return "Unknown";
    }
    
    /**
     * @dev Base64 кодирование (исправленная версия)
     */
    function _base64Encode(bytes memory data) internal pure returns (string memory) {
        if (data.length == 0) return "";
        
        string memory table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        uint256 len = data.length;
        uint256 encodedLen = 4 * ((len + 2) / 3);
        
        bytes memory result = new bytes(encodedLen);
        
        uint256 i = 0;
        uint256 j = 0;
        
        while (i < len) {
            uint256 a = i < len ? uint8(data[i++]) : 0;
            uint256 b = i < len ? uint8(data[i++]) : 0;
            uint256 c = i < len ? uint8(data[i++]) : 0;
            
            uint256 triple = (a << 16) + (b << 8) + c;
            
            result[j++] = bytes1(uint8(bytes(table)[(triple >> 18) & 63]));
            result[j++] = bytes1(uint8(bytes(table)[(triple >> 12) & 63]));
            result[j++] = bytes1(uint8(bytes(table)[(triple >> 6) & 63]));
            result[j++] = bytes1(uint8(bytes(table)[triple & 63]));
        }
        
        // Обработка padding
        uint256 paddingCount = (3 - (len % 3)) % 3;
        if (paddingCount > 0) {
            for (uint256 k = encodedLen - paddingCount; k < encodedLen; k++) {
                result[k] = "=";
            }
        }
        
        return string(result);
    }
}
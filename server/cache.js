const logger = require('./logger');

class Cache {
  constructor() {
    this.store = new Map();
    this.defaultTTL = 60 * 60 * 1000; // 1 час в миллисекундах
  }

  // Генерация ключа для кэша
  generateKey(prefix, params) {
    const sortedParams = Object.keys(params)
      .sort()
      .map(key => `${key}=${params[key]}`)
      .join('&');
    return `${prefix}:${sortedParams}`;
  }

  // Получение значения из кэша
  get(key) {
    const item = this.store.get(key);
    if (!item) return null;

    // Проверка TTL
    if (Date.now() > item.expiresAt) {
      this.store.delete(key);
      logger.debug(`Cache expired for key: ${key}`);
      return null;
    }

    logger.debug(`Cache hit for key: ${key}`);
    return item.value;
  }

  // Сохранение значения в кэш
  set(key, value, ttl = this.defaultTTL) {
    const expiresAt = Date.now() + ttl;
    this.store.set(key, { value, expiresAt });
    logger.debug(`Cache set for key: ${key}, TTL: ${ttl}ms`);
  }

  // Удаление значения из кэша
  delete(key) {
    this.store.delete(key);
    logger.debug(`Cache deleted for key: ${key}`);
  }

  // Очистка просроченных записей
  cleanup() {
    const now = Date.now();
    let cleaned = 0;
    
    for (const [key, item] of this.store.entries()) {
      if (now > item.expiresAt) {
        this.store.delete(key);
        cleaned++;
      }
    }
    
    if (cleaned > 0) {
      logger.debug(`Cache cleanup: removed ${cleaned} expired entries`);
    }
  }

  // Получение статистики кэша
  getStats() {
    const now = Date.now();
    let valid = 0;
    let expired = 0;
    
    for (const item of this.store.values()) {
      if (now > item.expiresAt) {
        expired++;
      } else {
        valid++;
      }
    }
    
    return {
      total: this.store.size,
      valid,
      expired,
      hitRate: 0 // Можно добавить логику подсчета hit/miss
    };
  }
}

// Создаем глобальный экземпляр кэша
const cache = new Cache();

// Периодическая очистка просроченных записей (каждые 5 минут)
setInterval(() => cache.cleanup(), 5 * 60 * 1000);

module.exports = cache;
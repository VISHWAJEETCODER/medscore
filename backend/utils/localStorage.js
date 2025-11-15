const fs = require('fs');
const path = require('path');

// Local storage utility for file-based storage
class LocalStorageUtils {
  constructor() {
    this.storageDir = path.join(__dirname, '../data');
    this.ensureStorageDir();
  }

  ensureStorageDir() {
    if (!fs.existsSync(this.storageDir)) {
      fs.mkdirSync(this.storageDir, { recursive: true });
    }
  }

  // Get data from local storage
  get(key) {
    try {
      const filePath = path.join(this.storageDir, `${key}.json`);
      if (fs.existsSync(filePath)) {
        const data = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(data);
      }
      return null;
    } catch (error) {
      console.error(`Error reading ${key} from localStorage:`, error);
      return null;
    }
  }

  // Set data in local storage
  set(key, value) {
    try {
      const filePath = path.join(this.storageDir, `${key}.json`);
      fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
      return true;
    } catch (error) {
      console.error(`Error writing ${key} to localStorage:`, error);
      return false;
    }
  }

  // Remove data from local storage
  remove(key) {
    try {
      const filePath = path.join(this.storageDir, `${key}.json`);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        return true;
      }
      return false;
    } catch (error) {
      console.error(`Error removing ${key} from localStorage:`, error);
      return false;
    }
  }

  // Check if key exists
  has(key) {
    const filePath = path.join(this.storageDir, `${key}.json`);
    return fs.existsSync(filePath);
  }

  // Get all keys
  keys() {
    try {
      const files = fs.readdirSync(this.storageDir);
      return files
        .filter(file => file.endsWith('.json'))
        .map(file => file.replace('.json', ''));
    } catch (error) {
      console.error('Error getting localStorage keys:', error);
      return [];
    }
  }

  // Clear all data
  clear() {
    try {
      const files = fs.readdirSync(this.storageDir);
      files.forEach(file => {
        if (file.endsWith('.json')) {
          fs.unlinkSync(path.join(this.storageDir, file));
        }
      });
      return true;
    } catch (error) {
      console.error('Error clearing localStorage:', error);
      return false;
    }
  }
}

// Create singleton instance
const localStorageUtils = new LocalStorageUtils();

module.exports = {
  localStorageUtils
};

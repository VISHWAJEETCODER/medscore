const fs = require('fs');
const path = require('path');

// Data directory path
const dataDir = path.join(__dirname, '../data');

// Ensure data directory exists
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// JSON Storage utility class
class JSONStorage {
  constructor(filename) {
    this.filePath = path.join(dataDir, `${filename}.json`);
    this.data = [];
    this.load();
  }

  // Load data from JSON file
  load() {
    try {
      if (fs.existsSync(this.filePath)) {
        const fileContent = fs.readFileSync(this.filePath, 'utf8');
        this.data = JSON.parse(fileContent);
      } else {
        this.data = [];
        this.save();
      }
    } catch (error) {
      console.error(`Error loading ${this.filePath}:`, error);
      this.data = [];
    }
  }

  // Save data to JSON file
  save() {
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2));
      return true;
    } catch (error) {
      console.error(`Error saving ${this.filePath}:`, error);
      return false;
    }
  }

  // Create new record
  create(record) {
    try {
      const newRecord = {
        id: this.generateId(),
        ...record,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      this.data.push(newRecord);
      this.save();
      return { success: true, data: newRecord };
    } catch (error) {
      console.error('Error creating record:', error);
      return { success: false, error: error.message };
    }
  }

  // Find all records with optional filter
  find(filter = {}) {
    try {
      let results = [...this.data];
      
      // Apply filters
      Object.keys(filter).forEach(key => {
        if (filter[key] !== undefined) {
          results = results.filter(item => {
            if (typeof filter[key] === 'string') {
              return item[key] && item[key].toLowerCase().includes(filter[key].toLowerCase());
            }
            return item[key] === filter[key];
          });
        }
      });
      
      return { success: true, data: results };
    } catch (error) {
      console.error('Error finding records:', error);
      return { success: false, error: error.message };
    }
  }

  // Find one record by ID
  findById(id) {
    try {
      const record = this.data.find(item => item.id === id);
      return { success: true, data: record || null };
    } catch (error) {
      console.error('Error finding record by ID:', error);
      return { success: false, error: error.message };
    }
  }

  // Find one record by field
  findOne(filter) {
    try {
      const record = this.data.find(item => {
        return Object.keys(filter).every(key => item[key] === filter[key]);
      });
      return { success: true, data: record || null };
    } catch (error) {
      console.error('Error finding record:', error);
      return { success: false, error: error.message };
    }
  }

  // Update record by ID
  update(id, updates) {
    try {
      const index = this.data.findIndex(item => item.id === id);
      if (index === -1) {
        return { success: false, error: 'Record not found' };
      }
      
      this.data[index] = {
        ...this.data[index],
        ...updates,
        updatedAt: new Date().toISOString()
      };
      
      this.save();
      return { success: true, data: this.data[index] };
    } catch (error) {
      console.error('Error updating record:', error);
      return { success: false, error: error.message };
    }
  }

  // Delete record by ID
  delete(id) {
    try {
      const index = this.data.findIndex(item => item.id === id);
      if (index === -1) {
        return { success: false, error: 'Record not found' };
      }
      
      const deletedRecord = this.data.splice(index, 1)[0];
      this.save();
      return { success: true, data: deletedRecord };
    } catch (error) {
      console.error('Error deleting record:', error);
      return { success: false, error: error.message };
    }
  }

  // Get count of records
  count(filter = {}) {
    try {
      let results = [...this.data];
      
      // Apply filters
      Object.keys(filter).forEach(key => {
        if (filter[key] !== undefined) {
          results = results.filter(item => {
            if (typeof filter[key] === 'string') {
              return item[key] && item[key].toLowerCase().includes(filter[key].toLowerCase());
            }
            return item[key] === filter[key];
          });
        }
      });
      
      return { success: true, data: results.length };
    } catch (error) {
      console.error('Error counting records:', error);
      return { success: false, error: error.message };
    }
  }

  // Paginate results
  paginate(page = 1, limit = 10, filter = {}) {
    try {
      const { data } = this.find(filter);
      const startIndex = (page - 1) * limit;
      const endIndex = startIndex + limit;
      
      const paginatedData = data.slice(startIndex, endIndex);
      
      return {
        success: true,
        data: {
          records: paginatedData,
          pagination: {
            currentPage: page,
            totalPages: Math.ceil(data.length / limit),
            totalRecords: data.length,
            hasNext: endIndex < data.length,
            hasPrev: page > 1
          }
        }
      };
    } catch (error) {
      console.error('Error paginating records:', error);
      return { success: false, error: error.message };
    }
  }

  // Generate unique ID
  generateId() {
    const maxId = this.data.reduce((max, item) => Math.max(max, item.id || 0), 0);
    return maxId + 1;
  }

  // Clear all data
  clear() {
    try {
      this.data = [];
      this.save();
      return { success: true, message: 'All data cleared' };
    } catch (error) {
      console.error('Error clearing data:', error);
      return { success: false, error: error.message };
    }
  }

  // Get all data
  getAll() {
    return { success: true, data: [...this.data] };
  }

  // Search records
  search(query, fields = []) {
    try {
      if (!query || query.trim() === '') {
        return { success: true, data: this.data };
      }
      
      const searchTerm = query.toLowerCase();
      const results = this.data.filter(item => {
        // If specific fields are provided, search only in those
        const fieldsToSearch = fields.length > 0 ? fields : Object.keys(item);
        
        return fieldsToSearch.some(field => {
          const value = item[field];
          if (typeof value === 'string') {
            return value.toLowerCase().includes(searchTerm);
          } else if (typeof value === 'number') {
            return value.toString().includes(searchTerm);
          }
          return false;
        });
      });
      
      return { success: true, data: results };
    } catch (error) {
      console.error('Error searching records:', error);
      return { success: false, error: error.message };
    }
  }
}

// Export storage instances for different data types
const usersStorage = new JSONStorage('users');
const collegesStorage = new JSONStorage('colleges');
const mentorsStorage = new JSONStorage('mentors');
const bookingsStorage = new JSONStorage('bookings');
const materialsStorage = new JSONStorage('materials');
const plannersStorage = new JSONStorage('planners');
const mentorApplicationsStorage = new JSONStorage('mentorApplications');
const purchasesStorage = new JSONStorage('purchases');

// Export the class and instances
module.exports = {
  JSONStorage,
  usersStorage,
  collegesStorage,
  mentorsStorage,
  bookingsStorage,
  materialsStorage,
  plannersStorage,
  mentorApplicationsStorage,
  purchasesStorage
};

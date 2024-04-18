const { Pool } = require('pg');
const dbConfig = require('./db-config.json');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

class CloudCustomers {
    constructor() {
        this.pool = new Pool(dbConfig);
    }

    async getUserById(id) {
        const query = {
            text: 'SELECT * FROM cloud_customers WHERE id = $1',
            values: [id],
        };

        try {
            const result = await this.pool.query(query);
            return result;
        } catch (err) {
            console.error('Error getting user by ID:', err);
            throw err;
        }
    }

    async getUserByEmail(email) {
        const query = {
            text: 'SELECT * FROM cloud_customers WHERE email = $1',
            values: [email],
        };

        try {
            const result = await this.pool.query(query);
            return result.rows[0];
        } catch (error) {
            console.error('Error getting user by email:', error);
            throw error;
        }
    }

    async editUser(id, newData) {
        const fields = Object.keys(newData);
        const values = Object.values(newData);
        const placeholders = fields.map((_, i) => `$${i + 2}`).join(', ');

        const query = {
            text: `UPDATE cloud_customers SET (${fields.join(', ')}) = (${placeholders}) WHERE id = $1`,
            values: [id, ...values],
        };

        try {
            await this.pool.query(query);
            return true;
        } catch (err) {
            console.error('Error editing user:', err);
            throw err;
        }
    }

    async createUser(user) {
        // Генерируем новый уникальный id
        const id = uuidv4();
        user.id = id;

        const fields = Object.keys(user);
        const values = Object.values(user);
        const placeholders = fields.map((_, i) => `$${i + 1}`).join(', ');

        const query = {
            text: `INSERT INTO cloud_customers (${fields.join(', ')}) VALUES (${placeholders})`,
            values,
        };

        try {
            await this.pool.query(query);
            return true;
        } catch (err) {
            console.error('Error creating user:', err);
            throw err;
        }
    }

    async changePassword(id, newPassword) {
        const query = {
            text: 'UPDATE cloud_customers SET password = $1 WHERE id = $2',
            values: [newPassword, id],
        };

        try {
            await this.pool.query(query);
            return true;
        } catch (err) {
            console.error('Error changing user password:', err);
            throw err;
        }
    }

    async hashPassword(password) {
        try {
            const saltRounds = 10; // количество "соли", используемое при хэшировании пароля
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            return hashedPassword;
        } catch (error) {
            console.error('Error hashing password:', error);
            throw error;
        }
    }

    async comparePassword(plainPassword, hashedPassword) {
        try {
            const match = await bcrypt.compare(plainPassword, hashedPassword);
            return match;
        } catch (error) {
            console.error('Error comparing password:', error);
            throw error;
        }
    }

}

module.exports = CloudCustomers;

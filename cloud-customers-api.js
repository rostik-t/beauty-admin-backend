const express = require('express');
const jwt = require('jsonwebtoken');
const CloudCustomers = require('./cloud-customers-db');

class CloudCustomersAPI {
    constructor() {
        this.router = express.Router();
        this.cloudCustomers = new CloudCustomers();
        this.initializeRoutes();
    }

    initializeRoutes() {
        this.router.post('/login', this.login.bind(this));
        this.router.get('/users/:id', this.authenticateToken, this.getUserById.bind(this));
        this.router.put('/users/:id', this.authenticateToken, this.editUser.bind(this));
        this.router.post('/users', this.createUser.bind(this));
        this.router.put('/users/:id/password', this.authenticateToken, this.changePassword.bind(this));
    }

    async login(req, res) {
        const { email, password } = req.body;
        try {
            // Получаем пользователя по email из базы данных
            const user = await this.cloudCustomers.getUserByEmail(email);

            if (!user) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            // Проверяем соответствие пароля
            const passwordMatch = await this.cloudCustomers.comparePassword(password, user.password);

            if (!passwordMatch) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            // Генерируем JWT-токен
            const accessToken = jwt.sign({ email: user.email }, process.env.ACCESS_TOKEN_SECRET);

            res.json({ accessToken });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    }

    authenticateToken(req, res, next) {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        if (token == null) return res.sendStatus(401);

        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
            if (err) return res.sendStatus(403);
            req.user = user;
            next();
        });
    }

    async getUserById(req, res) {
        // Здесь вы можете получить req.user, который содержит информацию о пользователе из токена
        const userId = parseInt(req.params.id);
        try {
            const user = await this.cloudCustomers.getUserById(userId);
            res.json(user);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    }

    async editUser(req, res) {
        // Здесь также доступен req.user для получения информации о пользователе
        const userId = parseInt(req.params.id);
        const userData = req.body;
        try {
            await this.cloudCustomers.editUser(userId, userData);
            res.json({ message: 'User edited successfully' });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    }

    async createUser(req, res) {
        const userData = req.body;
        try {
            const hashedPassword = await this.cloudCustomers.hashPassword(userData.password);
            // Замените пароль в объекте userData на его хэшированную версию
            userData.password = hashedPassword;
            await this.cloudCustomers.createUser(userData);
            res.json({ message: 'User created successfully' });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    }

    async changePassword(req, res) {
        const userId = parseInt(req.params.id);
        const { newPassword } = req.body;
        try {
            const hashedPassword = await this.cloudCustomers.hashPassword(newPassword);
            await this.cloudCustomers.changePassword(userId, hashedPassword);
            res.json({ message: 'Password changed successfully' });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    }

    getRouter() {
        return this.router;
    }
}

module.exports = CloudCustomersAPI;

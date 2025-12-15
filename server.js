// server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serve static files from public folder

// MongoDB Connection - Railway Database
mongoose.connect('mongodb://mongo:SjcxnbuuQYROeBiUAQlroSzNjTxnmptj@caboose.proxy.rlwy.net:14659', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB Connected to Railway'))
  .catch(err => console.error('❌ MongoDB Error:', err));

// User Schema
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    username: { type: String, required: true },
    coins: { type: Number, default: 100 },
    isAdmin: { type: Boolean, default: false },
    purchasedTools: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Tool' }],
    adsWatched: { type: Number, default: 0 },
    lastAdWatch: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Tool Schema
const toolSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String, required: true },
    price: { type: Number, required: true },
    category: { type: String, required: true },
    icon: { type: String, default: '🛠️' },
    features: [String],
    downloadLink: String,
    isActive: { type: Boolean, default: true },
    purchaseCount: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

const Tool = mongoose.model('Tool', toolSchema);

// Ad Watch Log Schema
const adWatchSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    coinsEarned: { type: Number, default: 10 },
    timestamp: { type: Date, default: Date.now }
});

const AdWatch = mongoose.model('AdWatch', adWatchSchema);

// JWT Secret
const JWT_SECRET = 'your-secret-key-change-this-in-production';

// Auth Middleware
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access denied' });
    }
    
    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ error: 'Invalid token' });
    }
};

// Admin Middleware
const isAdmin = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user.isAdmin) {
            return res.status(403).json({ error: 'Admin access required' });
        }
        next();
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
};

// ============ AUTH ROUTES ============

// Signup
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { email, password, username } = req.body;
        
        // Validation
        if (!email || !password || !username) {
            return res.status(400).json({ error: 'All fields required' });
        }
        
        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }
        
        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // Create user
        const user = new User({
            email,
            password: hashedPassword,
            username,
            coins: 100 // Starting coins
        });
        
        await user.save();
        
        // Create token
        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                email: user.email,
                username: user.username,
                coins: user.coins,
                isAdmin: user.isAdmin
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Validation
        if (!email || !password) {
            return res.status(400).json({ error: 'All fields required' });
        }
        
        // Check user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        // Create token
        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                email: user.email,
                username: user.username,
                coins: user.coins,
                isAdmin: user.isAdmin
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json({ success: true, user });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ============ COIN ROUTES ============

// Watch ad and earn coins
app.post('/api/coins/watch-ad', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        
        // Check if user watched ad recently (1 minute cooldown)
        if (user.lastAdWatch) {
            const timeDiff = Date.now() - user.lastAdWatch.getTime();
            if (timeDiff < 60000) {
                return res.status(400).json({ 
                    error: 'Please wait before watching another ad',
                    cooldown: Math.ceil((60000 - timeDiff) / 1000)
                });
            }
        }
        
        // Add coins
        const coinsEarned = 10;
        user.coins += coinsEarned;
        user.adsWatched += 1;
        user.lastAdWatch = new Date();
        await user.save();
        
        // Log ad watch
        const adWatch = new AdWatch({
            userId: user._id,
            coinsEarned
        });
        await adWatch.save();
        
        res.json({
            success: true,
            coinsEarned,
            totalCoins: user.coins,
            message: 'Coins added successfully!'
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get coin balance
app.get('/api/coins/balance', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        res.json({ 
            success: true, 
            coins: user.coins,
            adsWatched: user.adsWatched
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ============ SHOP ROUTES ============

// Get all tools
app.get('/api/shop/tools', authenticateToken, async (req, res) => {
    try {
        const tools = await Tool.find({ isActive: true });
        const user = await User.findById(req.user.id);
        
        const toolsWithOwnership = tools.map(tool => ({
            ...tool.toObject(),
            owned: user.purchasedTools.includes(tool._id)
        }));
        
        res.json({ success: true, tools: toolsWithOwnership });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Purchase tool
app.post('/api/shop/purchase/:toolId', authenticateToken, async (req, res) => {
    try {
        const tool = await Tool.findById(req.params.toolId);
        const user = await User.findById(req.user.id);
        
        if (!tool) {
            return res.status(404).json({ error: 'Tool not found' });
        }
        
        // Check if already purchased
        if (user.purchasedTools.includes(tool._id)) {
            return res.status(400).json({ error: 'Tool already purchased' });
        }
        
        // Check if enough coins
        if (user.coins < tool.price) {
            return res.status(400).json({ error: 'Insufficient coins' });
        }
        
        // Process purchase
        user.coins -= tool.price;
        user.purchasedTools.push(tool._id);
        await user.save();
        
        tool.purchaseCount += 1;
        await tool.save();
        
        res.json({
            success: true,
            message: 'Purchase successful!',
            remainingCoins: user.coins,
            tool: tool
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get purchased tools
app.get('/api/shop/my-tools', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).populate('purchasedTools');
        res.json({ success: true, tools: user.purchasedTools });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ============ ADMIN ROUTES ============

// Get all users
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const users = await User.find().select('-password');
        const totalUsers = await User.countDocuments();
        const totalCoins = await User.aggregate([
            { $group: { _id: null, total: { $sum: '$coins' } } }
        ]);
        
        res.json({ 
            success: true, 
            users,
            stats: {
                totalUsers,
                totalCoins: totalCoins[0]?.total || 0
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Create tool
app.post('/api/admin/tools', authenticateToken, isAdmin, async (req, res) => {
    try {
        const tool = new Tool(req.body);
        await tool.save();
        res.json({ success: true, tool });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Update tool
app.put('/api/admin/tools/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const tool = await Tool.findByIdAndUpdate(
            req.params.id, 
            req.body, 
            { new: true }
        );
        res.json({ success: true, tool });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete tool
app.delete('/api/admin/tools/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        await Tool.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: 'Tool deleted' });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get admin stats
app.get('/api/admin/stats', authenticateToken, isAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const totalTools = await Tool.countDocuments();
        const totalPurchases = await Tool.aggregate([
            { $group: { _id: null, total: { $sum: '$purchaseCount' } } }
        ]);
        const totalAdsWatched = await AdWatch.countDocuments();
        
        res.json({
            success: true,
            stats: {
                totalUsers,
                totalTools,
                totalPurchases: totalPurchases[0]?.total || 0,
                totalAdsWatched
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Give coins to user (admin)
app.post('/api/admin/give-coins', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { userId, amount } = req.body;
        const user = await User.findById(userId);
        
        user.coins += amount;
        await user.save();
        
        res.json({ success: true, message: 'Coins added', newBalance: user.coins });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Start server
const PORT = process.env.PORT || 3000;

// Root route - Serve index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API status route
app.get('/api', (req, res) => {
    res.json({
        message: '🚀 Suzuku V3 Backend API',
        status: 'Running',
        version: '1.0.0',
        port: PORT,
        endpoints: {
            auth: {
                signup: 'POST /api/auth/signup',
                login: 'POST /api/auth/login',
                me: 'GET /api/auth/me'
            },
            coins: {
                watchAd: 'POST /api/coins/watch-ad',
                balance: 'GET /api/coins/balance'
            },
            shop: {
                tools: 'GET /api/shop/tools',
                purchase: 'POST /api/shop/purchase/:toolId',
                myTools: 'GET /api/shop/my-tools'
            },
            admin: {
                users: 'GET /api/admin/users',
                stats: 'GET /api/admin/stats',
                createTool: 'POST /api/admin/tools',
                updateTool: 'PUT /api/admin/tools/:id',
                deleteTool: 'DELETE /api/admin/tools/:id',
                giveCoins: 'POST /api/admin/give-coins'
            }
        }
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📡 Frontend: http://localhost:${PORT}`);
    console.log(`📡 API: http://localhost:${PORT}/api`);
});

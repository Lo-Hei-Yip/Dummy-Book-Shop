const express = require('express');
const mysql = require('mysql2');
const multer = require('multer');
const sharp = require('sharp');
const path = require('path');
const methodOverride = require('method-override');
const fs = require('fs');
const { body, validationResult, param } = require('express-validator');
const session = require('express-session');
const csrf = require('csurf');
const bcrypt = require('bcrypt');
const sanitizeHtml = require('sanitize-html');
const crypto = require('crypto');
require('dotenv').config();

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY); //to use env variable

const app = express();
const port = 3000;

// Database connection
const pool = mysql.createPool({
    host: process.env.DB_HOST, 
    user: process.env.DB_USER, 
    password: process.env.DB_PASSWORD, 
    database: process.env.DB_NAME, 
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(methodOverride('_method'));

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET, 
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 2 * 24 * 60 * 60 * 1000,
        sameSite: 'Strict'
    }
}));

// CSRF middleware
const csrfProtection = csrf();

// Webhook route which is defined BEFORE express.json() for avoiding turning into JS object
app.post('/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    let event;
    try {
        console.log('Received webhook payload type:', typeof req.body);
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
        console.log(`Received webhook event: ${event.type}, session ID: ${event.data.object.id}`);
    } catch (err) {
        console.error('Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
        if (event.type === 'checkout.session.completed' || event.type === 'checkout.session.async_payment_succeeded') {
            const session = event.data.object;
            console.log(`Processing session: ${session.id}, payment_status: ${session.payment_status}`);
            console.log(`Session metadata:`, session.metadata);
            if (session.payment_status === 'paid') {
                await fulfillCheckout(session.id);
            } else {
                console.log(`Session ${session.id} not paid, status: ${session.payment_status}`);
            }
        } else if (event.type === 'checkout.session.expired') {
            const session = event.data.object;
            console.log(`Processing expired session: ${session.id}`);
            console.log(`Session metadata:`, session.metadata);
            const orderId = session.metadata?.orderId;
            if (!orderId) {
                console.error(`No orderId found in session metadata for session ${session.id}`);
                return res.status(200).end();
            }
            console.log(`Retrieved orderId: ${orderId}`);

            const [orders] = await pool.promise().query(
                'SELECT status FROM orders WHERE orderID = ? AND status = ?',
                [orderId, 'pending']
            );

            if (orders.length === 0) {
                console.log(`Order ${orderId} not pending or not found`);
                return res.status(200).end();
            }

            await pool.promise().query(
                'UPDATE orders SET status = ? WHERE orderID = ?',
                ['failed', orderId]
            );
            console.log(`Marked order ${orderId} as failed for session ${session.id}`);
        } else {
            console.log(`Ignored event type: ${event.type}`);
        }
    } catch (err) {
        console.error(`Error processing webhook event ${event.type}:`, err);
        return res.status(500).end();
    }

    res.status(200).end();
});

// JSON parsing middleware
app.use(express.json());

// Sanitization Helper Function
const sanitizeOutput = (data) => {
    if (typeof data === 'string') {
        return sanitizeHtml(data, { allowedTags: [], allowedAttributes: {} });
    } else if (Array.isArray(data)) {
        return data.map(item => sanitizeOutput(item));
    } else if (typeof data === 'object' && data !== null) {
        const sanitized = {};
        for (const [key, value] of Object.entries(data)) {
            sanitized[key] = sanitizeOutput(value);
        }
        return sanitized;
    }
    return data;
};

// Check if user is authenticated
const isAuthenticated = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
};

// Check if user is admin
const isAdmin = (req, res, next) => {
    if (req.session.userId && req.session.isAdmin) {
        return next();
    }
    res.status(403).send('Access denied');
};

// File upload setup
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, 'public/images'));
    },
    filename: (req, file, cb) => {
        if (!file) {
            return cb(new Error('No file provided'));
        }
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, 'temp_' + uniqueSuffix + ext);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        if (!file) {
            return cb(new Error('No file uploaded'));
        }
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'));
        }
    }
});

// CSRF token route
app.get('/api/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Function to fulfill the checkout
async function fulfillCheckout(sessionId) {
    try {
        console.log(`Fulfilling checkout for session ${sessionId}`);
        const checkoutSession = await stripe.checkout.sessions.retrieve(sessionId, {
            expand: ['line_items'],
        });

        const orderId = checkoutSession.metadata?.orderId;
        if (!orderId) {
            console.error(`No orderId found in session metadata for session ${sessionId}`);
            return;
        }
        console.log(`Retrieved orderId: ${orderId}`);

        const [orders] = await pool.promise().query(
            'SELECT digest, salt, total, currency FROM orders WHERE orderID = ? AND status != ?',
            [orderId, 'confirmed']
        );

        if (orders.length === 0) {
            console.log(`Order ${orderId} already fulfilled or not found`);
            return;
        }
        console.log(`Found order ${orderId}, status: ${orders[0].status}`);

        const order = orders[0];

        const [orderItems] = await pool.promise().query(
            'SELECT pid, quantity, price FROM order_items WHERE orderID = ?',
            [orderId]
        );
        console.log(`Order items for ${orderId}:`, orderItems);

        const merchantEmail = '1155195182@link.cuhk.edu.hk';
        const itemsString = orderItems
            .map(item => `${item.pid}${item.quantity}${item.price}${(item.price * item.quantity).toFixed(2)}`)
            .join('');
        const digestString = `${order.currency}${merchantEmail}${order.salt}${itemsString}${order.total}`;
        const regeneratedDigest = crypto.createHash('sha256').update(digestString).digest('hex');

        console.log(`Regenerated digest: ${regeneratedDigest}, stored digest: ${order.digest}`);
        if (regeneratedDigest !== order.digest) {
            console.error(`Digest mismatch for order ${orderId}`);
            return;
        }

        await pool.promise().query(
            'UPDATE orders SET status = ? WHERE orderID = ?',
            ['confirmed', orderId]
        );

        console.log(`Fulfilled Checkout Session ${sessionId} for Order ${orderId}`);
    } catch (err) {
        console.error(`Error fulfilling checkout ${sessionId}:`, err);
    }
}

// Checkout route
app.post('/create-checkout-session', csrfProtection, [
    body('items').isArray({ min: 1 }).withMessage('Cart must contain at least one item'),
    body('items.*.pid').isInt({ gt: 0 }).withMessage('Invalid product ID'),
    body('items.*.quantity').isInt({ min: 1, max: 10 }).withMessage('Quantity must be between 1 and 10')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { items } = req.body;
    const merchantEmail = '1155195182@link.cuhk.edu.hk';
    const currency = 'USD';
    let total = 0;
    const salt = crypto.randomBytes(16).toString('hex');

    try {
        const validatedItems = [];
        for (const item of items) {
            const [products] = await pool.promise().query(
                'SELECT pid, price, name FROM products WHERE pid = ?',
                [item.pid]
            );
            if (products.length === 0) {
                return res.status(400).json({ error: `Product ID ${item.pid} not found` });
            }
            const product = products[0];
            validatedItems.push({
                pid: product.pid,
                quantity: item.quantity,
                price: product.price,
                name: product.name,
                subtotal: product.price * item.quantity
            });
            total += product.price * item.quantity;
        }

        const [orderResult] = await pool.promise().query(
            'INSERT INTO orders (userID, total, digest, salt, currency, status) VALUES (?, ?, ?, ?, ?, ?)',
            [req.session.userId || null, total.toFixed(2), 'temp', salt, currency, 'pending']
        );
        const orderId = orderResult.insertId;
        console.log(`Created order with orderId: ${orderId}`);

        for (const item of validatedItems) {
            await pool.promise().query(
                'INSERT INTO order_items (orderID, pid, quantity, price) VALUES (?, ?, ?, ?)',
                [orderId, item.pid, item.quantity, item.price]
            );
        }

        const itemsString = validatedItems
            .map(item => `${item.pid}${item.quantity}${item.price}${item.subtotal.toFixed(2)}`)
            .join('');
        const digestString = `${currency}${merchantEmail}${salt}${itemsString}${total.toFixed(2)}`;
        const digest = crypto.createHash('sha256').update(digestString).digest('hex');

        await pool.promise().query(
            'UPDATE orders SET digest = ? WHERE orderID = ?',
            [digest, orderId]
        );

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: validatedItems.map(item => ({
                price_data: {
                    currency: 'usd',
                    product_data: {
                        name: item.name,
                    },
                    unit_amount: Math.round(item.price * 100),
                },
                quantity: item.quantity,
            })),
            mode: 'payment',
            success_url: `https://s22.ierg4210.ie.cuhk.edu.hk/index.html`,
            cancel_url: `https://s22.ierg4210.ie.cuhk.edu.hk/index.html`,
            metadata: {
                orderId: orderId.toString(),
            },
        });
        console.log(`Created Stripe session ${session.id} with metadata.orderId: ${orderId}`);

        // Return session ID, orderId, and digest
        res.json({ id: session.id, orderId: orderId, digest: digest });
    } catch (err) {
        console.error('Error creating checkout session:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Routes
app.get('/login', csrfProtection, (req, res) => {
    if (req.session.userId) {
        return req.session.isAdmin ? res.redirect('/admin') : res.redirect('/account');
    }
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post('/login', csrfProtection, [
    body('email').isEmail().normalizeEmail().withMessage('Invalid email format'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).send(`<p>Validation errors: ${errors.array().map(e => e.msg).join(', ')}. <a href="/login">Try again</a></p>`);
    }
    const { email, password } = req.body;
    try {
        const [users] = await pool.promise().query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) return res.status(401).send('<p>Invalid email or password. <a href="/login">Try again</a></p>');
        const user = users[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).send('<p>Invalid email or password. <a href="/login">Try again</a></p>');
        req.session.regenerate((err) => {
            if (err) return res.status(500).send('Internal server error');
            req.session.userId = user.userid;
            req.session.isAdmin = user.isAdmin;
            if (user.isAdmin) res.redirect('/admin');
            else res.redirect('/');
        });
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).send('Internal server error');
    }
});

app.get('/admin', isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

app.get('/account', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'account.html'));
});


app.post('/change-password', csrfProtection, isAuthenticated, [
    body('currentPassword').isLength({ min: 8 }).withMessage('Current password must be at least 8 characters'),
    body('newPassword')
        .isLength({ min: 8 }).withMessage('New password must be at least 8 characters')
        .matches(/[A-Z]/).withMessage('New password must contain at least one uppercase letter')
        .matches(/[a-z]/).withMessage('New password must contain at least one lowercase letter')
        .matches(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/).withMessage('New password must contain at least one special character'),
    body('confirmPassword').custom((value, { req }) => {
        if (value !== req.body.newPassword) {
            throw new Error('Password confirmation does not match new password');
        }
        return true;
    })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).send(`<p>Validation errors: ${errors.array().map(e => e.msg).join(', ')}. <a href="/account">Try again</a></p>`);
    }
    
    const { currentPassword, newPassword } = req.body;
    
    try {
        const [users] = await pool.promise().query('SELECT password FROM users WHERE userid = ?', [req.session.userId]);
        if (users.length === 0) return res.status(404).send('User not found');
        
        const match = await bcrypt.compare(currentPassword, users[0].password);
        if (!match) return res.status(401).send('<p>Incorrect current password. <a href="/account">Try again</a></p>');
        
        const samePassword = await bcrypt.compare(newPassword, users[0].password);
        if (samePassword) {
            return res.status(400).send('<p>New password must be different from current password. <a href="/account">Try again</a></p>');
        }
        
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        await pool.promise().query('UPDATE users SET password = ? WHERE userid = ?', [hashedNewPassword, req.session.userId]);
        
        req.session.destroy((err) => {
            if (err) return res.status(500).send('Internal server error');
            res.send('<p>Password changed successfully. <a href="/login">Login again</a></p>');
        });
    } catch (err) {
        console.error('Error changing password:', err);
        res.status(500).send('Internal server error');
    }
});


app.post('/logout', csrfProtection, (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).send('Internal server error');
        res.redirect('/index.html');
    });
});

app.get('/api/user', (req, res) => {
    if (req.session.userId) {
        pool.query('SELECT email, isAdmin FROM users WHERE userid = ?', [req.session.userId], (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            if (results.length > 0) res.json(sanitizeOutput({ email: results[0].email, isAdmin: results[0].isAdmin }));
            else res.json(null);
        });
    } else {
        res.json(null);
    }
});

app.get('/api/categories', (req, res) => {
    pool.query('SELECT * FROM categories', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(sanitizeOutput(results));
    });
});

app.get('/api/products', (req, res) => {
    const { catid } = req.query;
    const query = catid ? 'SELECT * FROM products WHERE catid = ?' : 'SELECT * FROM products';
    const params = catid ? [catid] : [];
    pool.query(query, params, (err, products) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(sanitizeOutput(products));
    });
});

app.get('/api/products/:pid', [
    param('pid').isInt({ gt: 0 }).withMessage('Invalid product ID')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { pid } = req.params;
    pool.query('SELECT * FROM products WHERE pid = ?', [pid], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: 'Product not found' });
        res.json(sanitizeOutput(results[0]));
    });
});

app.post('/api/categories', csrfProtection, isAdmin, [
    body('name').trim().isLength({ min: 1 }).withMessage('Category name is required')
        .customSanitizer(value => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} }))
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { name } = req.body;
    pool.query('INSERT INTO categories (name) VALUES (?)', [name], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(sanitizeOutput({ message: 'Category added successfully', categoryId: result.insertId }));
    });
});

app.put('/api/categories', csrfProtection, isAdmin, [
    body('catid').isInt({ gt: 0 }).withMessage('Invalid category ID'),
    body('name').trim().isLength({ min: 1 }).withMessage('Category name is required')
        .customSanitizer(value => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} }))
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { catid, name } = req.body;
    pool.query('UPDATE categories SET name = ? WHERE catid = ?', [name, catid], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(sanitizeOutput({ message: 'Category updated successfully' }));
    });
});

app.delete('/api/categories', csrfProtection, isAdmin, [
    body('catid').isInt({ gt: 0 }).withMessage('Invalid category ID')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { catid } = req.body;
    pool.query('DELETE FROM categories WHERE catid = ?', [catid], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(sanitizeOutput({ message: 'Category deleted successfully' }));
    });
});

app.post('/api/products', csrfProtection, isAdmin, upload.single('image'), [
    body('catid').isInt({ gt: 0 }).withMessage('Invalid category ID'),
    body('name').trim().isLength({ min: 1 }).withMessage('Product name is required'),
    body('price').isFloat({ gt: 0 }).withMessage('Price must be a positive number'),
    body('description').trim().isLength({ min: 1 }).withMessage('Description is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    if (!req.file) {
        return res.status(400).json({ error: 'Image file is required' });
    }

    try {
        let { catid, name, price, description } = req.body;
        catid = Array.isArray(catid) ? catid[0] : catid;

        const [result] = await pool.promise().query(
            'INSERT INTO products (catid, name, price, description, image) VALUES (?, ?, ?, ?, ?)',
            [catid, name, price, description, null]
        );

        const productId = result.insertId;
        const imageExt = '.jpg'; // Force JPG extension
        const imageName = `${productId}${imageExt}`;
        const newPath = path.join(__dirname, 'public/images', imageName);

        await sharp(req.file.path)
            .toFormat('jpeg')
            .toFile(newPath);

        await fs.promises.unlink(req.file.path);

        await Promise.all([
            sharp(newPath)
                .resize(800, 800, { fit: 'inside', withoutEnlargement: true })
                .toFile(path.join(__dirname, 'public/images', `${productId}_large.jpg`)),
            sharp(newPath)
                .resize(150, 150, { fit: 'inside', withoutEnlargement: true })
                .toFile(path.join(__dirname, 'public/images', `${productId}_thumb.jpg`))
        ]);

        await pool.promise().query(
            'UPDATE products SET image = ? WHERE pid = ?',
            [imageName, productId]
        );

        res.json({ message: 'Product added successfully', productId });
    } catch (err) {
        console.error('Error adding product:', err);
        if (req.file) {
            try {
                await fs.promises.unlink(req.file.path);
            } catch (cleanupErr) {
                console.warn('Could not delete uploaded file:', cleanupErr);
            }
        }
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/products', csrfProtection, isAdmin, upload.single('image'), [
    body('pid').isInt({ gt: 0 }).withMessage('Invalid product ID'),
    body('catid').optional({ checkFalsy: true }).isInt({ gt: 0 }).withMessage('Invalid category ID'),
    body('name').optional({ checkFalsy: true }).trim().isLength({ min: 1 }).withMessage('Product name is required'),
    body('price').optional({ checkFalsy: true }).isFloat({ gt: 0 }).withMessage('Price must be a positive number'),
    body('description').optional({ checkFalsy: true }).trim().isLength({ min: 1 }).withMessage('Description is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { pid, catid, name, price, description } = req.body;
        let updateFields = [];
        let queryParams = [];

        if (catid) {
            updateFields.push('catid = ?');
            queryParams.push(catid);
        }
        if (name) {
            updateFields.push('name = ?');
            queryParams.push(name);
        }
        if (price) {
            updateFields.push('price = ?');
            queryParams.push(price);
        }
        if (description) {
            updateFields.push('description = ?');
            queryParams.push(description);
        }

        if (req.file) {
            const imageExt = '.jpg'; // Force JPG extension
            const imageName = `${pid}${imageExt}`;
            const newPath = path.join(__dirname, 'public/images', imageName);

            try {
                const [product] = await pool.promise().query('SELECT image FROM products WHERE pid = ?', [pid]);
                if (product[0]?.image) {
                    const oldImageBase = path.basename(product[0].image, path.extname(product[0].image));
                    
                    await Promise.all([
                        fs.promises.unlink(path.join(__dirname, 'public/images', product[0].image)).catch(() => {}),
                        fs.promises.unlink(path.join(__dirname, 'public/images', `${oldImageBase}_large.jpg`)).catch(() => {}),
                        fs.promises.unlink(path.join(__dirname, 'public/images', `${oldImageBase}_thumb.jpg`)).catch(() => {})
                    ]);
                }
            } catch (err) {
                console.error('Error deleting old images:', err);
            }

            await sharp(req.file.path)
                .toFormat('jpeg')
                .toFile(newPath);

            await fs.promises.unlink(req.file.path);

            await Promise.all([
                sharp(newPath)
                    .resize(800, 800, { fit: 'inside', withoutEnlargement: true })
                    .toFile(path.join(__dirname, 'public/images', `${pid}_large.jpg`)),
                sharp(newPath)
                    .resize(150, 150, { fit: 'inside', withoutEnlargement: true })
                    .toFile(path.join(__dirname, 'public/images', `${pid}_thumb.jpg`))
            ]);

            updateFields.push('image = ?');
            queryParams.push(imageName);
        }

        if (updateFields.length === 0) {
            return res.status(400).json({ error: 'No fields to update' });
        }

        queryParams.push(pid);
        const query = `UPDATE products SET ${updateFields.join(', ')} WHERE pid = ?`;

        await pool.promise().query(query, queryParams);
        res.json({ message: 'Product updated successfully' });

    } catch (err) {
        console.error('Error updating product:', err);
        if (req.file) {
            try {
                await fs.promises.unlink(req.file.path);
            } catch (cleanupErr) {
                console.warn('Could not delete uploaded file:', cleanupErr);
            }
        }
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/products', csrfProtection, isAdmin, [
    body('pid').isInt({ gt: 0 }).withMessage('Invalid product ID')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    
    const { pid } = req.body;
    
    try {
        const [products] = await pool.promise().query('SELECT image FROM products WHERE pid = ?', [pid]);
        
        if (products.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        
        const product = products[0];
        
        if (product.image) {
            const imageBase = path.basename(product.image, path.extname(product.image));
            
            await Promise.all([
                fs.promises.unlink(path.join(__dirname, 'public/images', product.image)).catch(() => {}),
                fs.promises.unlink(path.join(__dirname, 'public/images', `${imageBase}_large.jpg`)).catch(() => {}),
                fs.promises.unlink(path.join(__dirname, 'public/images', `${imageBase}_thumb.jpg`)).catch(() => {})
            ]);
        }
        
        await pool.promise().query('DELETE FROM products WHERE pid = ?', [pid]);
        
        res.json(sanitizeOutput({ message: 'Product deleted successfully' }));
        
    } catch (err) {
        console.error('Error deleting product:', err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/categories/:catid', [
    param('catid').isInt({ gt: 0 }).withMessage('Invalid category ID')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { catid } = req.params;
    pool.query('SELECT * FROM categories WHERE catid = ?', [catid], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: 'Category not found' });
        res.json(sanitizeOutput(results[0]));
    });
});


//For the display order table function for admin
app.get('/api/orders', isAdmin, async (req, res) => {
    try {
        const [orders] = await pool.promise().query(
            'SELECT orderID, userID, total, currency, status, ' +
            'DATE_FORMAT(createdAt, "%Y-%m-%dT%H:%i:%s.000Z") AS createdAt ' +
            'FROM orders ORDER BY createdAt DESC'
        );
        console.log('Fetched orders:', orders.length);

        const orderIds = orders.map(order => order.orderID);
        let orderItems = [];
        if (orderIds.length > 0) {
            const [items] = await pool.promise().query(
                'SELECT oi.orderID, oi.pid, oi.quantity, oi.price, p.name AS productName ' +
                'FROM order_items oi LEFT JOIN products p ON oi.pid = p.pid ' +
                'WHERE oi.orderID IN (?)',
                [orderIds]
            );
            orderItems = items;
            console.log('Fetched order items:', orderItems.length);
        }

        const result = orders.map(order => ({
            ...order,
            items: orderItems
                .filter(item => item.orderID === order.orderID)
                .map(item => ({
                    pid: item.pid,
                    productName: item.productName || `Product ID ${item.pid} (Deleted)`,
                    quantity: item.quantity,
                    price: item.price
                }))
        }));

        res.json(sanitizeOutput(result));
    } catch (err) {
        console.error('Error fetching orders:', err);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});


//For the display the 5 order function for normal user
app.get('/api/user/orders', isAuthenticated, async (req, res) => {
    try {
        const [orders] = await pool.promise().query(
            'SELECT orderID, userID, total, currency, status, ' +
            'DATE_FORMAT(createdAt, "%Y-%m-%dT%H:%i:%s.000Z") AS createdAt ' +
            'FROM orders WHERE userID = ? ORDER BY createdAt DESC LIMIT 5',
            [req.session.userId]
        );
        console.log(`Fetched ${orders.length} orders for userID ${req.session.userId}`);

        const orderIds = orders.map(order => order.orderID);
        let orderItems = [];
        if (orderIds.length > 0) {
            const [items] = await pool.promise().query(
                'SELECT oi.orderID, oi.pid, oi.quantity, oi.price, p.name AS productName ' +
                'FROM order_items oi LEFT JOIN products p ON oi.pid = p.pid ' +
                'WHERE oi.orderID IN (?)',
                [orderIds]
            );
            orderItems = items;
            console.log(`Fetched ${orderItems.length} order items for userID ${req.session.userId}`);
        }

        const result = orders.map(order => ({
            ...order,
            items: orderItems
                .filter(item => item.orderID === order.orderID)
                .map(item => ({
                    pid: item.pid,
                    productName: item.productName || `Product ID ${item.pid} (Deleted)`,
                    quantity: item.quantity,
                    price: item.price
                }))
        }));

        res.json(sanitizeOutput(result));
    } catch (err) {
        console.error(`Error fetching orders for userID ${req.session.userId}:`, err);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

app.post('/signup', csrfProtection, [
    body('email').isEmail().normalizeEmail().withMessage('Invalid email format'),
    body('password')
        .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
        .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
        .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
        .matches(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/).withMessage('Password must contain at least one special character'),
    body('confirmPassword').custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('Password confirmation does not match password');
        }
        return true;
    })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).send(`<p>Validation errors: ${errors.array().map(e => e.msg).join(', ')}. <a href="/login">Try again</a></p>`);
    }

    const { email, password } = req.body;
    
    try {
        // Check if email already exists
        const [users] = await pool.promise().query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length > 0) {
            return res.status(400).send('<p>Email already registered. <a href="/login">Try again</a></p>');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Insert new user (isAdmin defaults to 0/false)
        await pool.promise().query(
            'INSERT INTO users (email, password) VALUES (?, ?)',
            [email, hashedPassword]
        );

        res.send('<p>Registration successful! <a href="/login">Login now</a></p>');
    } catch (err) {
        console.error('Error during signup:', err);
        res.status(500).send('Internal server error');
    }
});

// sign up 
app.post('/signup', csrfProtection, [
    body('email').isEmail().normalizeEmail().withMessage('Invalid email format'),
    body('password')
        .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
        .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
        .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
        .matches(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/).withMessage('Password must contain at least one special character'),
    body('confirmPassword').custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('Password confirmation does not match password');
        }
        return true;
    })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).send(`<p>Validation errors: ${errors.array().map(e => e.msg).join(', ')}. <a href="/login">Try again</a></p>`);
    }

    const { email, password } = req.body;
    
    try {
        // Check if email already exists
        const [users] = await pool.promise().query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length > 0) {
            return res.status(400).send('<p>Email already registered. <a href="/login">Try again</a></p>');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Insert new user (isAdmin defaults to 0/false)
        await pool.promise().query(
            'INSERT INTO users (email, password) VALUES (?, ?)',
            [email, hashedPassword]
        );

        res.send('<p>Registration successful! <a href="/login">Login now</a></p>');
    } catch (err) {
        console.error('Error during signup:', err);
        res.status(500).send('Internal server error');
    }
});


//for public key
app.get('/api/stripe-public-key', (req, res) => {
    res.json({ publicKey: process.env.STRIPE_PUBLIC_KEY });
});


app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        console.error('Invalid CSRF token:', err.message);
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    console.error('Unexpected error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(port, () => console.log(`Server running on port ${port}`));
// Import required modules
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
require("dotenv").config();

// Initialize the app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Database connection using Mongoose
mongoose
    .connect(process.env.MONGO_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => console.log("Connected to MongoDB"))
    .catch((err) => console.error("Database connection error:", err));

// Models
const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ["buyer", "seller", "admin"], default: "buyer" },
});
const User = mongoose.model("User", UserSchema);

const ProductSchema = new mongoose.Schema({
    name: { type: String, required: true },
    price: { type: Number, required: true },
    category: { type: String, required: true },
    brand: String,
    description: String,
    sellerId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
});
const Product = mongoose.model("Product", ProductSchema);

// JWT Middleware
const authenticateJWT = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "Forbidden" });
        req.user = user;
        next();
    });
};

// Role Middleware
const authorizeRoles = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: "Access Denied" });
        }
        next();
    };
};

// Routes
// User Registration
app.post("/api/register", async (req, res) => {
    const { name, email, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword, role });
        await user.save();
        res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
        res.status(400).json({ error: "Email already exists or invalid data" });
    }
});

// User Login
app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ message: "User not found" });

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid)
            return res.status(401).json({ message: "Invalid password" });

        const token = jwt.sign(
            { id: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "1d" }
        );
        res.status(200).json({ token, role: user.role });
    } catch (err) {
        res.status(500).json({ error: "Something went wrong" });
    }
});

// Get Products
app.get("/api/products", async (req, res) => {
    try {
        const products = await Product.find();
        res.status(200).json(products);
    } catch (err) {
        res.status(500).json({ error: "Something went wrong" });
    }
});

// Add Product (Seller Only)
app.post(
    "/api/products",
    authenticateJWT,
    authorizeRoles("seller"),
    async (req, res) => {
        const { name, price, category, brand, description } = req.body;
        try {
            const product = new Product({
                name,
                price,
                category,
                brand,
                description,
                sellerId: req.user.id,
            });
            await product.save();
            res.status(201).json(product);
        } catch (err) {
            res.status(400).json({ error: "Invalid product data" });
        }
    }
);

// Delete Product (Seller Only)
app.delete(
    "/api/products/:id",
    authenticateJWT,
    authorizeRoles("seller"),
    async (req, res) => {
        try {
            const product = await Product.findOne({
                _id: req.params.id,
                sellerId: req.user.id,
            });
            if (!product)
                return res.status(404).json({ message: "Product not found" });

            await product.deleteOne();
            res.status(200).json({ message: "Product deleted successfully" });
        } catch (err) {
            res.status(500).json({ error: "Something went wrong" });
        }
    }
);

// Manage Users (Admin Only)
app.get(
    "/api/users",
    authenticateJWT,
    authorizeRoles("admin"),
    async (req, res) => {
        try {
            const users = await User.find();
            res.status(200).json(users);
        } catch (err) {
            res.status(500).json({ error: "Something went wrong" });
        }
    }
);

app.put(
    "/api/users/:id",
    authenticateJWT,
    authorizeRoles("admin"),
    async (req, res) => {
        const { role } = req.body;
        try {
            const user = await User.findById(req.params.id);
            if (!user) return res.status(404).json({ message: "User not found" });

            user.role = role;
            await user.save();
            res.status(200).json({ message: "User role updated successfully" });
        } catch (err) {
            res.status(500).json({ error: "Something went wrong" });
        }
    }
);

// Start Server
app.get("/", (req, res) => {
    res.send("Stride Phase 02: Full-Stack Assignment");
});
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
    console.log(`Server running on port http://localhost:${PORT}`)
);

const express = require("express");
const cors = require("cors");
require("dotenv").config();
const jwt = require("jsonwebtoken");

const app = express();
const port = process.env.PORT || 4000;

// Middleware

app.use(express.json());
app.use(cors());

// jwt

app.post("/api/authentication", async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.send({ message: "Email is required" });
    }
    const token = jwt.sign({ email }, process.env.JWT_SECRET, {
        expiresIn: `${process.env.TOKEN_EXP}`,
    });
    res.send({ token });
});

// jwt verify

const verifyJWT = (req, res, next) => {
    const authorization = req.headers.authorization;
    if (!authorization || !authorization.startsWith("Bearer ")) {
        return res.send({ message: "Invalid authorization" });
    }

    const token = authorization.split(" ")[1];
    jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.send({ message: "Invalid token" });
        }
        req.decoded = decoded;
        next();
    });
};

// mongodb

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const uri = `${process.env.MONGODB_URL}`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});

const dbConnect = async () => {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();

        // collection
        const usersCollection = await client
            .db("strideAssignmentCollection")
            .collection("users");
        const productsCollection = await client
            .db("strideAssignmentCollection")
            .collection("products");

        // verify buyer
        const verifyBuyer = async (req, res, next) => {
            try {
                const email = req.decoded?.email;
                if (!email) {
                    return res.status(400).send({ message: "Email not found in token." });
                }

                const findBuyer = await usersCollection.findOne({ email });
                if (!findBuyer) {
                    return res.status(404).send({ message: "User not found." });
                }

                if (findBuyer.role === "buyer") {
                    return next();
                }

                return res.status(403).send({ message: "The user is not a buyer." });
            } catch (error) {
                console.error("Error in verifyBuyer middleware:", error);
                return res.status(500).send({ message: "Internal server error." });
            }
        };

        // verify seller
        const verifySeller = async (req, res, next) => {
            try {
                const email = req.decoded?.email;
                if (!email) {
                    return res.status(400).send({ message: "Email not found in token." });
                }

                const findBuyer = await usersCollection.findOne({ email });
                if (!findBuyer) {
                    return res.status(404).send({ message: "User not found." });
                }

                if (findBuyer.role === "seller") {
                    return next();
                }

                return res.status(403).send({ message: "The user is not a seller." });
            } catch (error) {
                console.error("Error in verifyBuyer middleware:", error);
                return res.status(500).send({ message: "Internal server error." });
            }
        };

        // verify Admin
        const verifyAdmin = async (req, res, next) => {
            try {
                const email = req.decoded?.email;
                if (!email) {
                    return res.status(400).send({ message: "Email not found in token." });
                }

                const findBuyer = await usersCollection.findOne({ email });
                if (!findBuyer) {
                    return res.status(404).send({ message: "User not found." });
                }

                if (findBuyer.role === "admin") {
                    return next();
                }

                return res.status(403).send({ message: "The user is not a admin." });
            } catch (error) {
                console.error("Error in verifyBuyer middleware:", error);
                return res.status(500).send({ message: "Internal server error." });
            }
        };

        const verifyUnbannedUser = async (req, res, next) => {
            try {
                const email = req.decoded?.email;
                if (!email) {
                    return res.status(400).send({ message: "Email not found in token." });
                }

                const user = await usersCollection.findOne({ email });
                if (!user) {
                    return res.status(404).send({ message: "User not found." });
                }

                if (user.userStatus === "banned") {
                    return res.status(403).send({
                        message: "User is banned and cannot access this resource.",
                    });
                }

                next();
            } catch (error) {
                console.error("Error in verifyUnbannedUser middleware:", error);
                return res.status(500).send({ message: "Internal server error." });
            }
        };

        // crud

        // default admin
        const ensureAdminExists = async () => {
            const adminEmail = "sabab54874@rabitex.com";
            const existingAdmin = await usersCollection.findOne({
                email: adminEmail,
            });

            if (!existingAdmin) {
                const defaultAdmin = {
                    email: adminEmail,
                    name: "Default Admin",
                    image: "https://images.pexels.com/photos/614810/pexels-photo-614810.jpeg",
                    role: "admin",
                    userStatus: "unbanned",
                    createdAt: new Date(),
                    updatedAt: new Date(),
                };

                await usersCollection.insertOne(defaultAdmin);
                console.log("Default admin user created.");
            } else {
                console.log("Admin user already exists.");
            }
        };

        await ensureAdminExists();

        // View all unbanned users
        app.get("/api/all-users", verifyJWT, verifyAdmin, async (req, res) => {
            const users = await usersCollection
                .find({ userStatus: "unbanned" })
                .toArray();
            res.send(users);
        });

        // get single user
        app.get(
            "/api/get-user/:email",
            verifyJWT,
            verifyUnbannedUser,
            async (req, res) => {
                const { email } = req.params;
                const user = await usersCollection.findOne({ email });
                if (!user) {
                    return res.send({ message: "User not found" });
                }
                res.send(user);
            }
        );

        // Change user role
        app.patch(
            "/api/change-role/:id",
            verifyJWT,
            verifyAdmin,
            async (req, res) => {
                const { id } = req.params;
                const { role } = req.body;

                // Check if the new role is valid
                if (!["buyer", "seller", "admin"].includes(role)) {
                    return res.send({ message: "Invalid role" });
                }

                const user = await usersCollection.findOne({ _id: new ObjectId(id) });
                if (!user) {
                    return res.send({ message: "User not found" });
                }

                if (user.userStatus === "banned") {
                    return res.status(403).send({
                        message: "User is banned and cannot access this resource.",
                    });
                }

                // Update the user's role
                const result = await usersCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { role, updatedAt: new Date() } }
                );

                res.send(result);
            }
        );

        // user create
        app.post("/api/create-user", async (req, res) => {
            const { email, name, image, role } = req.body;

            if (!email || !name || !role) {
                return res
                    .status(400)
                    .send({ message: "Email, name, and role are required" });
            }

            if (email === "sabab54874@rabitex.com") {
                return res.send({ acknowledge: true });
            }

            const existingUser = await usersCollection.findOne({ email });
            if (existingUser) {
                return res.status(400).send("User already exists.");
            }

            const user = {
                email,
                name,
                image,
                role,
                userStatus: "unbanned",
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            if (role === "buyer") {
                (user.wishlist = []), (user.cart = []);
            }

            const result = await usersCollection.insertOne(user);
            res.send(result);
        });

        // delete user by Ban
        app.patch("/api/ban-user/:id", verifyJWT, verifyAdmin, async (req, res) => {
            const { id } = req.params;

            // Update user status to 'banned'
            const result = await usersCollection.updateOne(
                { _id: new ObjectId(id) },
                { $set: { userStatus: "banned", updatedAt: new Date() } }
            );

            if (result.modifiedCount === 0) {
                return res.status(404).send({ message: "User not found" });
            }

            res.send({ message: "User banned successfully" });
        });

        // get  single  product

        app.get("/api/get-single-product/:productId", async (req, res) => {
            const { productId } = req.params;
            const product = await productsCollection.findOne({
                _id: new ObjectId(productId),
            });
            if (!product) {
                return res.send({ message: "Product not found" });
            }
            res.send(product);
        });

        // get product
        app.get("/api/get-products", async (req, res) => {
            const { name, category, brand, limit = 6, page, sort } = req.query;
            const query = {};

            // Add filters to the query
            if (name) query.name = { $regex: name, $options: "i" }; // Case-insensitive partial match
            if (category) query.category = category;
            if (brand) query.brand = brand;

            let sortOption = {};
            if (sort === "asc") {
                sortOption.price = 1; 
            } else if (sort === "desc") {
                sortOption.price = -1; 
            }

            const products = await productsCollection
                .find(query)
                .sort(sortOption)
                .skip((page - 1) * Number(limit)) 
                .limit(Number(limit))
                .toArray();

            const totalProducts = await productsCollection.countDocuments(query);

            const categories = [
                ...new Set(products.map((product) => product.category)),
            ];
            const brands = [...new Set(products.map((product) => product.brand))];

            res.send({ products, categories, brands, totalProducts });
        });




        // seller View all their listed products

        app.get(
            "/api/seller-products",
            verifyJWT,
            verifySeller,
            async (req, res) => {
                const sellerEmail = req.decoded.email;
                const products = await productsCollection
                    .find({ sellerEmail })
                    .toArray();
                res.send(products);
            }
        );

        // add product
        app.post("/api/add-product", verifyJWT, verifySeller, async (req, res) => {
            const { name, price, category, brand, details, stock, image } = req.body;

            // Construct product object
            const product = {
                name,
                price: parseFloat(price), // Ensure price is a number
                category,
                brand,
                details,
                stock: parseInt(stock), // Ensure stock is a number
                image,
                sellerEmail: req.decoded.email, // Use the seller's email from the token
                ratings: [],
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            const result = await productsCollection.insertOne(product);
            res.send(result);
        });

        // seller can delete their product

        app.delete(
            "/api/delete-product/:id",
            verifyJWT,
            verifySeller,
            async (req, res) => {
                const { id } = req.params;
                const sellerEmail = req.decoded.email;

                // Check if the product exists and belongs to the seller
                const product = await productsCollection.findOne({
                    _id: new ObjectId(id),
                    sellerEmail,
                });
                if (!product) {
                    return res.send({
                        message: "Product not found or you are not the seller",
                    });
                }

                // Delete the product
                const result = await productsCollection.deleteOne({
                    _id: new ObjectId(id),
                });
                res.send(result);
            }
        );

        // Update product
        app.patch(
            "/api/update-product/:id",
            verifyJWT,
            verifySeller,
            async (req, res) => {
                const { id } = req.params;
                const { name, price, category, brand, details, stock, image } =
                    req.body;
                const sellerEmail = req.decoded.email;

                // Check if the product exists and belongs to the seller
                const product = await productsCollection.findOne({
                    _id: new ObjectId(id),
                    sellerEmail,
                });
                if (!product) {
                    return res
                        .status(404)
                        .send({ message: "Product not found or you are not the seller" });
                }

                // Update only the provided fields
                const updatedProduct = {};
                if (name) updatedProduct.name = name;
                if (price) updatedProduct.price = parseFloat(price);
                if (category) updatedProduct.category = category;
                if (brand) updatedProduct.brand = brand;
                if (details) updatedProduct.details = details;
                if (stock) updatedProduct.stock = parseInt(stock);
                if (image) updatedProduct.image = image;
                updatedProduct.updatedAt = new Date();

                const result = await productsCollection.updateOne(
                    { _id: new ObjectId(product._id) },
                    { $set: updatedProduct }
                );
                res.send(result);
            }
        );

        // get user's wishlist
        app.get("/api/get-wishlist", verifyJWT, verifyBuyer, async (req, res) => {
            const email = req.decoded.email;

            // Get user and their wishlist
            const user = await usersCollection.findOne(
                { email },
                { projection: { wishlist: 1, _id: 0 } }
            );
            if (!user) {
                return res.send({ message: "User not found" });
            }
            if (user.userStatus === "banned") {
                return res
                    .status(403)
                    .send({ message: "User is banned and cannot access this resource." });
            }

            // Fetch product details for each product in the wishlist
            const wishlistProducts = await productsCollection
                .find({
                    _id: { $in: user.wishlist.map((id) => new ObjectId(String(id))) },
                })
                .toArray();

            res.send(wishlistProducts);
        });

        // remove product from wishlist
        app.patch(
            "/api/remove-from-wishlist",
            verifyJWT,
            verifyBuyer,
            async (req, res) => {
                const { productId } = req.body;
                if (!productId) {
                    return res.send({ message: "Product ID is required" });
                }

                const user = await usersCollection.findOne({
                    email: req.decoded.email,
                });
                if (!user) {
                    return res.status(404).send({ message: "User not found" });
                }
                if (user.userStatus === "banned") {
                    return res.status(403).send({
                        message: "User is banned and cannot access this resource.",
                    });
                }

                const result = await usersCollection.updateOne(
                    { email: req.decoded.email },
                    { $pull: { wishlist: productId } }
                );

                res.send(result);
            }
        );

        // add product on wishlist
        app.patch(
            "/api/add-to-wishlist",
            verifyJWT,
            verifyBuyer,
            async (req, res) => {
                const { productId } = req.body;
                if (!productId) {
                    return res.send({ message: "Product ID is required" });
                }
                const user = await usersCollection.findOne({
                    email: req.decoded.email,
                });
                if (!user) {
                    return res.status(404).send({ message: "User not found" });
                }
                if (user.userStatus === "banned") {
                    return res.status(403).send({
                        message: "User is banned and cannot access this resource.",
                    });
                }
                if (user.wishlist && user.wishlist.includes(productId)) {
                    return res.send({ message: "Product already in wishlist" });
                }
                const result = await usersCollection.updateOne(
                    { email: req.decoded.email },
                    { $addToSet: { wishlist: productId } }
                );
                res.send(result);
            }
        );

        // get user's cart
        app.get("/api/get-cart", verifyJWT, verifyBuyer, async (req, res) => {
            const email = req.decoded.email;

            // Get user and their cart
            const user = await usersCollection.findOne(
                { email },
                { projection: { cart: 1, _id: 0 } }
            );
            if (!user) {
                return res.send({ message: "User not found" });
            }
            if (user.userStatus === "banned") {
                return res
                    .status(403)
                    .send({ message: "User is banned and cannot access this resource." });
            }

            // Fetch product details for each product in the cart
            const cartProducts = await productsCollection
                .find({ _id: { $in: user.cart.map((id) => new ObjectId(id)) } })
                .toArray();

            res.send(cartProducts);
        });

        // remove product from cart
        app.patch(
            "/api/remove-from-cart",
            verifyJWT,
            verifyBuyer,
            async (req, res) => {
                const { productId } = req.body;
                if (!productId) {
                    return res.send({ message: "Product ID is required" });
                }
                const user = await usersCollection.findOne({
                    email: req.decoded.email,
                });
                if (!user) {
                    return res.status(404).send({ message: "User not found" });
                }
                if (user.userStatus === "banned") {
                    return res.status(403).send({
                        message: "User is banned and cannot access this resource.",
                    });
                }

                const result = await usersCollection.updateOne(
                    { email: req.decoded.email },
                    { $pull: { cart: productId } }
                );

                res.send(result);
            }
        );

        // add cart
        app.patch("/api/add-cart", verifyJWT, verifyBuyer, async (req, res) => {
            const { productId } = req.body;

            const email = req.decoded.email;

            // Fetch product details to ensure it's valid
            const product = await productsCollection.findOne({
                _id: new ObjectId(String(productId)),
            });
            if (!product) {
                return res.send({ message: "Product not found" });
            }

            // Get user and update cart
            const user = await usersCollection.findOne({ email });
            if (!user) {
                return res.send({ message: "User not found" });
            }
            if (user.userStatus === "banned") {
                return res
                    .status(403)
                    .send({ message: "User is banned and cannot access this resource." });
            }

            if (user.cart && user.cart.includes(productId)) {
                return res.send({ message: "Product already in cart" });
            }

            const result = await usersCollection.updateOne(
                { email: req.decoded.email },
                { $addToSet: { cart: productId } }
            );

            res.send(result);
        });

        // Send a ping to confirm a successful connection
        // await client.db("admin").command({ ping: 1 });
        console.log(
            "Pinged your deployment. You successfully connected to MongoDB!"
        );
    } catch (error) {
        console.log({ error });
    }
};

dbConnect();

//api

app.get("/", (req, res) => {
    res.send("Stride Phase 02: Full-Stack Assignment");
});

app.listen(port, () => {
    console.log(`Server is running on port: http://localhost:${port}`);
});

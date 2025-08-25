require('dotenv').config();
const express = require("express");
const cors = require("cors");
const { query } = require("./helpers/db");
const { hashPassword, comparePassword } = require("./helpers/password");
const { signToken, verifyToken } = require("./helpers/jwt");
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
    origin: "http://127.0.0.1:4000", // hanya allow dari sini
    methods: ["GET", "POST", "PUT", "DELETE"], // opsional, default semua method
    credentials: true // kalau mau kirim cookie / authorization
}));

app.use(express.json());

app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await query("SELECT * FROM users WHERE username=$1", [username]);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            const match = await comparePassword(password, user.password);
            if (!match) return res.status(401).json({ message: "Username atau password salah!" });
            const token = signToken({ id: user.id, username: user.username });
            return res.status(200).json({ message: "Login berhasil!", token, status: 200, data: result.rows[0] });
        } else {
            return res.status(401).json({ message: "Username atau password salah!", status: 200 });
        }
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Terjadi error di server" });
    }
});

app.post("/api/register", async (req, res) => {
    const { firstname, lastname, username, password } = req.body;
    try {
        const checkUser = await query("SELECT id FROM users WHERE username=$1", [username]);
        if(checkUser.rows.length > 0){
            return res.status(202).json({ message: "Username sudah terdaftar!", status: 202 });
        }else{
            const hashed = await hashPassword(password);
            await query("INSERT INTO users (firstname, lastname, username, password) VALUES ($1, $2, $3, $4)", [firstname, lastname, username, hashed]);
            return res.status(200).json({ message: "User berhasil dibuat!", status: 200 });
        }

    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Terjadi error di server" });
    }
});

app.get("/api/users", async (req, res) => {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).json({ message: "Unauthorized" });

    const token = authHeader.split(" ")[1];
    const decoded = verifyToken(token);

    if (!decoded) return res.status(401).json({ message: "Invalid token" });

    try {
        const result = await query("SELECT * FROM users WHERE status='1'");
        res.json({ users: result.rows, loginUser: decoded });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Terjadi error di server" });
    }
});

app.delete("/api/users", async (req, res) => {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).json({ message: "Unauthorized" });

    const token = authHeader.split(" ")[1];
    const decoded = verifyToken(token);
    if (!decoded) return res.status(401).json({ message: "Invalid token" });

    const { username } = req.body; // ambil username dari body
    if (!username) return res.status(400).json({ message: "Username required" });

    try {
        const result = await query(
            "DELETE FROM users WHERE username=$1",
            [username]
        );

        res.json({
            message: `User '${username}' deleted`,
            deletedCount: result.rowCount,
            loginUser: decoded
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Terjadi error di server" });
    }
});

app.put("/api/users", async (req, res) => {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).json({ message: "Unauthorized" });

    const token = authHeader.split(" ")[1];
    const decoded = verifyToken(token);
    if (!decoded) return res.status(401).json({ message: "Invalid token" });

    const { firstname, lastname, username, password, updatedUser } = req.body; 
    let updateData = {};
    if (firstname && firstname.trim() !== "") updateData.firstname = firstname.trim();
    if (lastname && lastname.trim() !== "") updateData.lastname = lastname.trim();
    if (username && username.trim() !== "") updateData.username = username.trim();
    if (password && password.trim() !== "") updateData.password = await hashPassword(password);

    try {
        const result = await query(
            `UPDATE users 
            SET firstname=COALESCE($1, firstname), 
                lastname=COALESCE($2, lastname), 
                username=COALESCE($3, username), 
                password=COALESCE(NULLIF($4, '')::text, password)
            WHERE username=$5`,
            [updateData.firstname, updateData.lastname, updateData.username, updateData.password, updatedUser]
        );

        res.status(200).json({
            message: `User '${username}' deleted`,
            deletedCount: result.rowCount,
            loginUser: decoded
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Terjadi error di server" });
    }
});

// START SERVER
app.listen(PORT, () => console.log(`Server running di http://localhost:${PORT}`));

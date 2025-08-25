const { verifyToken } = require('./jwt');

const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: "Token tidak ditemukan" });

    const token = authHeader.split(" ")[1];
    const decoded = verifyToken(token);

    if (!decoded) return res.status(401).json({ message: "Token tidak valid" });

    req.user = decoded; // simpan info user di req
    next();
};

module.exports = { authenticate };

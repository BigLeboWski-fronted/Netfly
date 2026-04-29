const jwt = require("jsonwebtoken");

const SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  throw new Error("JWT_SECRET is required");
}

function signToken(userId) {
  return jwt.sign({ sub: userId }, SECRET, { expiresIn: "30d" });
}

function requireAuth(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    const payload = jwt.verify(token, SECRET);
    req.userId = Number(payload.sub);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

module.exports = { signToken, requireAuth };

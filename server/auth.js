const jwt = require("jsonwebtoken");

const SECRET = process.env.JWT_SECRET || "change_me_in_production";

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

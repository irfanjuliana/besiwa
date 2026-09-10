import jwt from 'jsonwebtoken';
const JWT_SECRET = process.env.JWT_SECRET || 'siwa_secret_key_change_this';
export function signToken(payload) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
}
export function requireAuth(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    }
    catch {
        res.status(401).json({ error: 'Unauthorized' });
    }
}
export function requireAdmin(req, res, next) {
    if (!req.user || req.user.role !== 'admin') {
        res.status(403).json({ error: 'Forbidden: admin only' });
        return;
    }
    next();
}

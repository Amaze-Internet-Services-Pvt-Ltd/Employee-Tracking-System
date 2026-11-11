const express = require("express");
const pool = require("../config/db");
const tunnel = require("../utils/tunnel");

const router = express.Router();

/**
 * Which sites the app should send through the office tunnel. Any signed-in
 * account may read it: the app needs the list to build the browser's proxy
 * configuration, and the names are not a secret — the protection is that the
 * tunnel itself only opens for a live session.
 */
router.get("/config", async (req, res) => {
    try {
        const domains = await tunnel.getDomains(pool);
        return res.json({ success: true, domains });
    } catch (err) {
        console.error("[500]", req.method, req.originalUrl, err.message);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
});

module.exports = router;

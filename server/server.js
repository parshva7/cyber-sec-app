const express = require("express");
const cors = require("cors");

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());

app.post("/check-url", (req, res) => {
    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ error: "URL is required" });
    }
    // For now just send back that it's safe
    res.json({ status: "safe", checkedUrl: url });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

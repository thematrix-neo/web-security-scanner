import express from "express";
import cors from "cors";
import { handleScan } from "./api/scan.js";

const app = express();
app.use(cors());
app.use(express.json({ limit: "10kb" }));

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

app.post("/api/scan", handleScan);

app.listen(3001, () => console.log("Server on http://localhost:3001"));

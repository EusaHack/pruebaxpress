const express = require("express");
const app = express();
const CryptoJS = require("crypto-js");
const axios = require("axios");
require("dotenv").config();
const PORT = process.env.PORT || 3000;

app.use(express.json());
// Si también quieres soportar x-www-form-urlencoded
app.use(express.urlencoded({ extended: true }));

// Token que aceptaremos (puedes ponerlo en variables de entorno)
const TOKEN = process.env.TOKEN;
const key = process.env.AES_KEY;
const key_qa = process.env.AES_KEY_QA;
const key_data = process.env.AES_KEY_DATA;
const link_qa = process.env.LINK_QA || "https://qa5.mitec.com.mx/p/gen";

// Middleware para validar token
function validarToken(req, res, next) {
  const token = req.headers["authorization"]; // Espera 'Authorization: Bearer TOKEN'

  if (!token) {
    return res.status(401).json({ error: "Token requerido" });
  }

  // Verifica si viene en formato Bearer
  const parts = token.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer" || parts[1] !== TOKEN) {
    return res.status(403).json({ error: "Token inválido" });
  }

  next(); // Continua a la ruta si el token es válido
}

// Ruta protegida
app.get("/", validarToken, (req, res) => {
  res.send("✅ Accediste con token válido 🚀");
});

app.post("/cifrar",validarToken, async (req, res) => {
  try {
    const { xml } = req.body; // <-- XML enviado desde el front

    if (!xml) {
      return res.status(400).json({ success: false, error: "Falta el campo xml" });
    }

    // 🔐 Encriptar XML recibido
    const ciphertext = CryptoJS.AES.encrypt(xml, key).toString();

    // Construir data
    const originalString1 = `xml=<pgs><data0>SNDBX123</data0><data>${ciphertext}</data></pgs>`;
    const data = encodeURIComponent(originalString1);

    // 🚀 Enviar al endpoint real
    const response = await axios.post("https://sandboxpo.mit.com.mx/gen", data, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    // Respuesta para el frontend
    res.json({
      success: true,
      ciphertext,
      data,
      mitResponse: response.data,
    });

  } catch (error) {
    console.error("Error en /cifrar:", error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});


app.post("/cifrar-qa",validarToken, async (req, res) => {
  try {
    const { xml } = req.body; // <-- XML enviado desde el front

    if (!xml) {
      return res.status(400).json({ success: false, error: "Falta el campo xml" });
    }

    // 🔐 Encriptar XML recibido
    const ciphertext = CryptoJS.AES.encrypt(xml, key_qa).toString();

    // Construir data
    const originalString1 = `xml=<pgs><data0>${key_data}</data0><data>${ciphertext}</data></pgs>`;
    const data = encodeURIComponent(originalString1);

    // 🚀 Enviar al endpoint real
    const response = await axios.post(`${link_qa}`, data, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    // Respuesta para el frontend
    res.json({
      success: true,
      ciphertext,
      data,
      mitResponse: response.data,
    });

  } catch (error) {
    console.error("Error en /cifrar:", error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});


app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
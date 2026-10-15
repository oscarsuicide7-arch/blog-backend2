const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Usuario = require('../models/Usuario');
const router = express.Router();

router.post('/registro', async (req, res) => {
  try {
    const { correo, contrasena } = req.body;
    const existe = await Usuario.findOne({ correo });
    if (existe) return res.status(400).json({ error: 'El correo ya está registrado' });

    const usuario = new Usuario({ correo, contrasena });
    await usuario.save();

    const token = jwt.sign({ id: usuario._id }, process.env.JWT_SECRET, { expiresIn: '2h' });
    res.status(201).json({ token, usuario: { id: usuario._id, correo } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { correo, contrasena } = req.body;
    const usuario = await Usuario.findOne({ correo });
    if (!usuario) return res.status(400).json({ error: 'Credenciales incorrectas' });

    const valida = await bcrypt.compare(contrasena, usuario.contrasena);
    if (!valida) return res.status(400).json({ error: 'Credenciales incorrectas' });

    const token = jwt.sign({ id: usuario._id }, process.env.JWT_SECRET, { expiresIn: '2h' });
    res.json({ token, usuario: { id: usuario._id, correo } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Alias en ingles para que Flutter no se quede cargando
router.post('/register', async (req, res) => {
  req.body.correo = req.body.correo || req.body.email;
  req.body.contrasena = req.body.contrasena || req.body.password;
  // re-envia a la logica de /registro
  const { correo, contrasena } = req.body;
  try {
    const existe = await Usuario.findOne({ correo });
    if (existe) return res.status(400).json({ error: 'El correo ya está registrado' });
    const usuario = new Usuario({ correo, contrasena });
    await usuario.save();
    const token = jwt.sign({ id: usuario._id }, process.env.JWT_SECRET, { expiresIn: '2h' });
    res.status(201).json({ token, usuario: { id: usuario._id, correo } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;

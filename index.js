const express = require('express');
const bodyParser = require('body-parser');
const { MongoClient } = require('mongodb');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');

const secret = "supersecret"; // VULNÉRABLE : secret faible/hardcodé
const app = express();
const port = 3000;
const uri = 'mongodb://localhost:27017';
const dbName = 'testdb';

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.get('/', (req, res) => {
  res.send(`
    <h2>Connexion vulnérable</h2>
    <form method="POST" action="/login">
      <input name="username" placeholder="Username" />
      <input name="password" placeholder="Password" type="password" />
      <button type="submit">Login vulnérable</button>
    </form>

    <h2>Connexion sécurisée</h2>
    <form method="POST" action="/login-secure">
      <input name="username" placeholder="Username" />
      <input name="password" placeholder="Password" type="password" />
      <button type="submit">Login sécurisé</button>
    </form>

    <h2>Test LFI (vulnérable)</h2>
    <form method="GET" action="/read-file">
       <input name="file" placeholder="Fichier à lire (ex: index.js)" />
       <button type="submit">Lire fichier</button>
    </form>

   <h2>Test LFI (sécurisé)</h2>
   <form method="GET" action="/read-file-secure">
   <select name="file">
     <option value="index.js">index.js</option>
     <option value="README.md">README.md</option>
   </select>
   <button type="submit">Lire fichier</button>
   </form>

    <h2>Connexion JWT (vulnérable)</h2>
    <form method="POST" action="/jwt-login">
      <input name="username" placeholder="Nom d’utilisateur" />
      <button type="submit">Obtenir un token</button>
    </form>

    <h3>Accès profil JWT</h3>
    <p>Fais une requête GET vers <code>/jwt-profile</code> avec le header <code>Authorization: Bearer [TOKEN]</code></p>

  `);
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    username = JSON.parse(username);
    password = JSON.parse(password);
  } catch (e) {
    // on laisse tel quel
  }
  try{
  const client = new MongoClient(uri);
  await client.connect();
  const db = client.db(dbName);
  const users = db.collection('users');
  // VULNÉRABLE : les données ne sont pas filtrées
  const user = await users.findOne({ username: JSON.parse(username), password: JSON.parse(password) });
    if (user) {
      res.send('Bienvenue !');
    } else {
      res.send('Identifiants incorrects');
    }
  }
   catch(error){
   res.send('Identifiants incorrects');
  }
});

app.post('/login-secure', async (req, res) => {
  const { username, password } = req.body;

  // Remédiation simple : forcer le typage en string
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).send('Données invalides');
  }

  const client = new MongoClient(uri);
  await client.connect();
  const db = client.db(dbName);
  const users = db.collection('users');

  // Requête filtrée
  const user = await users.findOne({ username, password });

  if (user) {
    res.send('Bienvenue (sécurisé) !');
  } else {
    res.send('Identifiants incorrects (sécurisé)');
  }
});

app.get('/read-file', (req, res) => {
  const file = req.query.file;

  fs.readFile(file, 'utf8', (err, data) => {
    if (err) {
     console.log(err)
      return res.status(500).send('Erreur lors de la lecture du fichier.');
    }
    res.send(`<pre>${data}</pre>`);
  });
});

app.get('/read-file-secure', (req, res) => {
  const allowedFiles = ['index.js', 'README.md'];
  const file = req.query.file;

  if (!allowedFiles.includes(file)) {
    return res.status(400).send('Fichier non autorisé.');
  }

  const filePath = path.join(__dirname, file);
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).send('Erreur lors de la lecture du fichier.');
    }
    res.send(`<pre>${data}</pre>`);
  });
});

app.post('/jwt-login', (req, res) => {
  const { username } = req.body;

  // VULNÉRABLE : aucun contrôle d'identité réel
  const token = jwt.sign({ username, role: "user" }, secret, { algorithm: "HS256" });
  res.send(`Votre token : <pre>${token}</pre>`);
});

app.get('/jwt-profile', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  try {
    const payload = jwt.verify(token, secret);
    res.send(`<h3>Bienvenue ${payload.username} (role: ${payload.role})</h3>`);
  } catch (e) {
    res.status(401).send('Token invalide');
  }
});

app.get('/jwt-profile-secure', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  try {
    const payload = jwt.verify(token, secret);

    if (payload.role !== 'admin') {
      return res.status(403).send('Accès interdit');
    }

    res.send(`<h3>Bienvenue ADMIN ${payload.username}</h3>`);
  } catch (e) {
    res.status(401).send('Token invalide');
  }
});

app.listen(port, () => {
  console.log(`App en écoute sur http://localhost:${port}`);
});

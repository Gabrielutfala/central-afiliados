import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "troque-esta-chave-em-producao";
const db = new Database(path.join(__dirname, "data.db"));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS products (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 name TEXT NOT NULL,
 category TEXT NOT NULL DEFAULT 'Outros',
 status TEXT NOT NULL DEFAULT 'NOVO',
 price REAL DEFAULT 0,
 commission REAL DEFAULT 0,
 original_link TEXT DEFAULT '',
 affiliate_link TEXT DEFAULT '',
 notes TEXT DEFAULT '',
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS history (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 product_id INTEGER NOT NULL,
 event TEXT NOT NULL,
 created_at TEXT NOT NULL
);
`);

const email = "admin@local";
if (!db.prepare("SELECT id FROM users WHERE email=?").get(email)) {
  const hash = bcrypt.hashSync("1234", 10);
  db.prepare("INSERT INTO users(email,password_hash,created_at) VALUES(?,?,?)")
    .run(email, hash, new Date().toISOString());
}

app.use(express.json({limit:"2mb"}));
app.use(express.static(path.join(__dirname, "public")));

function auth(req,res,next){
  const token=(req.headers.authorization||"").replace("Bearer ","");
  try { req.user=jwt.verify(token,JWT_SECRET); next(); }
  catch { res.status(401).json({error:"Não autenticado"}); }
}

app.post("/api/login",(req,res)=>{
  const {email,password}=req.body||{};
  const u=db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if(!u || !bcrypt.compareSync(password,u.password_hash)) return res.status(401).json({error:"E-mail ou senha inválidos"});
  const token=jwt.sign({id:u.id,email:u.email},JWT_SECRET,{expiresIn:"7d"});
  res.json({token,user:{id:u.id,email:u.email}});
});

app.get("/api/me",auth,(req,res)=>res.json({email:req.user.email}));

app.get("/api/products",auth,(req,res)=>{
  const rows=db.prepare("SELECT * FROM products WHERE user_id=? ORDER BY id DESC").all(req.user.id);
  res.json(rows);
});

app.post("/api/products",auth,(req,res)=>{
  const p=req.body||{};
  if(!p.name?.trim()) return res.status(400).json({error:"Nome do produto é obrigatório"});
  const now=new Date().toISOString();
  const info=db.prepare(`INSERT INTO products
    (user_id,name,category,status,price,commission,original_link,affiliate_link,notes,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(
      req.user.id,p.name.trim(),p.category||"Outros",p.status||"NOVO",
      Number(p.price)||0,Number(p.commission)||0,p.original_link||"",p.affiliate_link||"",p.notes||"",now,now);
  db.prepare("INSERT INTO history(product_id,event,created_at) VALUES(?,?,?)")
    .run(info.lastInsertRowid,"Produto cadastrado",now);
  res.status(201).json(db.prepare("SELECT * FROM products WHERE id=?").get(info.lastInsertRowid));
});

app.patch("/api/products/:id",auth,(req,res)=>{
  const id=Number(req.params.id);
  const old=db.prepare("SELECT * FROM products WHERE id=? AND user_id=?").get(id,req.user.id);
  if(!old) return res.status(404).json({error:"Produto não encontrado"});
  const p=req.body||{}, now=new Date().toISOString();
  const allowed=["name","category","status","price","commission","original_link","affiliate_link","notes"];
  const next={...old,...Object.fromEntries(allowed.filter(k=>k in p).map(k=>[k,p[k]]))};
  db.prepare(`UPDATE products SET name=?,category=?,status=?,price=?,commission=?,original_link=?,affiliate_link=?,notes=?,updated_at=? WHERE id=? AND user_id=?`)
    .run(next.name,next.category,next.status,Number(next.price)||0,Number(next.commission)||0,next.original_link||"",next.affiliate_link||"",next.notes||"",now,id,req.user.id);
  if(old.status!==next.status) db.prepare("INSERT INTO history(product_id,event,created_at) VALUES(?,?,?)").run(id,`Status: ${old.status} → ${next.status}`,now);
  res.json(db.prepare("SELECT * FROM products WHERE id=?").get(id));
});

app.get("/api/products/:id/history",auth,(req,res)=>{
  const id=Number(req.params.id);
  const owner=db.prepare("SELECT id FROM products WHERE id=? AND user_id=?").get(id,req.user.id);
  if(!owner) return res.status(404).json({error:"Produto não encontrado"});
  res.json(db.prepare("SELECT * FROM history WHERE product_id=? ORDER BY id DESC").all(id));
});

app.delete("/api/products/:id",auth,(req,res)=>{
  const id=Number(req.params.id);
  const r=db.prepare("DELETE FROM products WHERE id=? AND user_id=?").run(id,req.user.id);
  res.json({ok:r.changes>0});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`Central de Afiliados rodando em http://localhost:${PORT}`));

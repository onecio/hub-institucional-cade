import { getDb } from './src/db/connection.js';
import argon2 from 'argon2';

const db = getDb();
const password = 'Admin@12345678';
const hashedPassword = await argon2.hash(password, {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
});

// Obter role de admin
const adminRole = db.prepare('SELECT id FROM roles WHERE name = ?').get('admin');

// Criar usuário
const insert = db.prepare(`
  INSERT INTO users (email, name, password_hash, registration, status)
  VALUES (?, ?, ?, ?, ?)
`);

const result = insert.run('admin@cade.gov.br', 'Administrador', hashedPassword, '0001', 'active');

// Atribuir role
db.prepare('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)').run(result.lastInsertRowid, adminRole.id);

console.log('✅ Usuário criado com sucesso!');
console.log('📧 Email: admin@cade.gov.br');
console.log('🔐 Senha: Admin@12345678');

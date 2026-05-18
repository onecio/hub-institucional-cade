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
console.log('Admin role:', adminRole);

// Criar usuário
const result = db.prepare(`
  INSERT INTO users (email, name, password_hash, registration, status)
  VALUES (?, ?, ?, ?, ?)
`).run('admin@cade.gov.br', 'Administrador', hashedPassword, '0001', 'active');

console.log('User inserted:', result);

// Verificar usuário criado
const user = db.prepare('SELECT id, email FROM users WHERE email = ?').get('admin@cade.gov.br');
console.log('User created:', user);

// Atribuir role
if (user && adminRole) {
  db.prepare('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)').run(user.id, adminRole.id);
  console.log('✅ Usuário criado com sucesso!');
  console.log('📧 Email: admin@cade.gov.br');
  console.log('🔐 Senha: Admin@12345678');
}

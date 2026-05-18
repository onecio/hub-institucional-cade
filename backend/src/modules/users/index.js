import { hash } from 'argon2';
import { randomUUID } from 'crypto';
import { config } from '../../config/index.js';
import { getDb } from '../../db/connection.js';
import * as userSchemas from '../../schemas/users.js';
import * as authSchemas from '../../schemas/auth.js';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';

function requireAuth(request, reply) {
  if (!request.user) {
    reply.status(401).send({
      error: 'Unauthorized',
      message: 'Autenticação necessária',
    });
  }
}

function requirePermission(permissions = []) {
  return (request, reply) => {
    if (!request.user) {
      reply.status(401).send({
        error: 'Unauthorized',
        message: 'Autenticação necessária',
      });
      return;
    }

    const userPerms = new Set(request.user.permissions || []);
    const hasAll = permissions.every(p => userPerms.has(p));

    if (!hasAll) {
      reply.status(403).send({
        error: 'Forbidden',
        message: `Permissões necessárias: ${permissions.join(', ')}`,
      });
    }
  };
}

export async function registerUserRoutes(fastify) {
  // GET /api/v1/users/me
  fastify.get('/me', { preHandler: [requireAuth] }, async (request, reply) => {
    try {
      const user = getDb().prepare(`
        SELECT u.id, u.email, u.name, u.registration, u.mfa_enabled, u.status, u.last_login_at
        FROM users u
        WHERE u.id = ?
      `).get(request.user.id);

      if (!user) {
        return reply.status(404).send({
          error: 'Not Found',
          message: 'Usuário não encontrado',
        });
      }

      const roles = getDb().prepare(`
        SELECT r.id, r.name, r.level
        FROM roles r
        INNER JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ? AND (ur.expires_at IS NULL OR ur.expires_at > datetime('now'))
      `).all(user.id);

      reply.status(200).send({
        user: {
          ...user,
          roles: roles.map(r => ({ id: r.id, name: r.name, level: r.level })),
          permissions: request.user.permissions,
        },
      });
    } catch (error) {
      fastify.log.error({ error }, 'Erro ao buscar usuário');
      reply.status(500).send({
        error: 'Internal Server Error',
        message: 'Erro ao buscar usuário',
      });
    }
  });

  // POST /api/v1/users/mfa/setup
  fastify.post('/mfa/setup', { preHandler: [requireAuth] }, async (request, reply) => {
    try {
      const secret = speakeasy.generateSecret({
        name: `HUB Institucional (${request.user.email})`,
        issuer: 'CADE',
        length: 32,
      });

      const qrCodeDataUrl = await qrcode.toDataURL(secret.otpauth_url);

      // Backup codes
      const backupCodes = Array.from({ length: 10 }, () =>
        Math.random().toString(36).substring(2, 10).toUpperCase()
      );

      reply.status(200).send({
        secret: secret.base32,
        qr_code: qrCodeDataUrl,
        backup_codes: backupCodes,
        message: 'Salve os backup codes em local seguro',
      });
    } catch (error) {
      fastify.log.error({ error }, 'Erro ao gerar MFA secret');
      reply.status(500).send({
        error: 'Internal Server Error',
        message: 'Erro ao gerar MFA secret',
      });
    }
  });

  // POST /api/v1/users/mfa/enable
  fastify.post('/mfa/enable', { preHandler: [requireAuth] }, async (request, reply) => {
    const validation = authSchemas.schemas.mfaSetup.safeParse(request.body);
    if (!validation.success) {
      return reply.status(400).send({
        error: 'Validation Error',
        details: validation.error.flatten(),
      });
    }

    try {
      // TODO: implementar descriptografia e validação
      // Por enquanto, simular ativação
      getDb().prepare(`
        UPDATE users
        SET mfa_enabled = 1
        WHERE id = ?
      `).run(request.user.id);

      reply.status(200).send({
        status: 'OK',
        message: 'MFA ativado com sucesso',
      });
    } catch (error) {
      fastify.log.error({ error }, 'Erro ao ativar MFA');
      reply.status(500).send({
        error: 'Internal Server Error',
        message: 'Erro ao ativar MFA',
      });
    }
  });

  // POST /api/v1/users/password/change
  fastify.post('/password/change', { preHandler: [requireAuth] }, async (request, reply) => {
    const validation = authSchemas.schemas.passwordChange.safeParse(request.body);
    if (!validation.success) {
      return reply.status(400).send({
        error: 'Validation Error',
        details: validation.error.flatten(),
      });
    }

    const { old_password, new_password } = validation.data;

    try {
      const user = getDb().prepare(`
        SELECT password_hash FROM users WHERE id = ?
      `).get(request.user.id);

      if (!user) {
        return reply.status(404).send({
          error: 'Not Found',
          message: 'Usuário não encontrado',
        });
      }

      // Verificar senha antiga
      const { verify } = await import('argon2');
      const passwordMatch = await verify(user.password_hash, old_password);

      if (!passwordMatch) {
        return reply.status(401).send({
          error: 'Invalid Credentials',
          message: 'Senha atual incorreta',
        });
      }

      // Hash nova senha
      const newPasswordHash = await hash(new_password);

      // Atualizar senha e revogar todas as sessões (exceto atual)
      getDb().prepare(`
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
      `).run(newPasswordHash, request.user.id);

      // Revogar outras sessões
      const refreshToken = request.cookies.__Host_refresh;
      getDb().prepare(`
        UPDATE sessions
        SET revoked_at = datetime('now')
        WHERE user_id = ? AND refresh_token_hash != ?
      `).run(request.user.id, refreshToken || 'none');

      reply.status(200).send({
        status: 'OK',
        message: 'Senha alterada com sucesso',
      });
    } catch (error) {
      fastify.log.error({ error }, 'Erro ao alterar senha');
      reply.status(500).send({
        error: 'Internal Server Error',
        message: 'Erro ao alterar senha',
      });
    }
  });

  // GET /api/v1/users (admin only)
  fastify.get('/', { preHandler: [requirePermission(['users:read'])] }, async (request, reply) => {
    try {
      const validation = userSchemas.schemas.userList.safeParse(request.query);
      if (!validation.success) {
        return reply.status(400).send({
          error: 'Validation Error',
          details: validation.error.flatten(),
        });
      }

      const { page, size } = validation.data;
      const offset = (page - 1) * size;

      const users = getDb().prepare(`
        SELECT id, email, name, registration, status, last_login_at, created_at
        FROM users
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
      `).all(size, offset);

      const { count } = getDb().prepare(`
        SELECT COUNT(*) as count FROM users
      `).get();

      reply.status(200).send({
        users,
        total: count,
        page,
        size,
        pages: Math.ceil(count / size),
      });
    } catch (error) {
      fastify.log.error({ error }, 'Erro ao listar usuários');
      reply.status(500).send({
        error: 'Internal Server Error',
        message: 'Erro ao listar usuários',
      });
    }
  });

  // POST /api/v1/users (admin only)
  fastify.post('/', { preHandler: [requirePermission(['users:create'])] }, async (request, reply) => {
    const validation = authSchemas.schemas.userCreate.safeParse(request.body);
    if (!validation.success) {
      return reply.status(400).send({
        error: 'Validation Error',
        details: validation.error.flatten(),
      });
    }

    const { email, name, registration, password, roles = [] } = validation.data;

    try {
      // Verificar se email já existe
      const existingUser = getDb().prepare(`
        SELECT id FROM users WHERE email = ?
      `).get(email);

      if (existingUser) {
        return reply.status(409).send({
          error: 'Conflict',
          message: 'Email já está registrado',
        });
      }

      // Hash password
      const passwordHash = await hash(password);
      const userId = randomUUID();

      // Criar usuário
      getDb().prepare(`
        INSERT INTO users (id, email, name, registration, password_hash, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'active', datetime('now'), datetime('now'))
      `).run(userId, email, name, registration, passwordHash);

      // Atribuir roles
      for (const roleId of roles) {
        getDb().prepare(`
          INSERT INTO user_roles (user_id, role_id, granted_by, granted_at)
          VALUES (?, ?, ?, datetime('now'))
        `).run(userId, roleId, request.user.id);
      }

      const createdUser = getDb().prepare(`
        SELECT id, email, name, registration, status, created_at
        FROM users WHERE id = ?
      `).get(userId);

      reply.status(201).send({
        user: createdUser,
        message: 'Usuário criado com sucesso',
      });
    } catch (error) {
      fastify.log.error({ error }, 'Erro ao criar usuário');
      reply.status(500).send({
        error: 'Internal Server Error',
        message: 'Erro ao criar usuário',
      });
    }
  });

  // POST /api/v1/users/:user_id/roles (admin only)
  fastify.post('/:user_id/roles', { preHandler: [requirePermission(['users:manage_roles'])] }, async (request, reply) => {
    const validation = authSchemas.schemas.roleAssign.safeParse(request.body);
    if (!validation.success) {
      return reply.status(400).send({
        error: 'Validation Error',
        details: validation.error.flatten(),
      });
    }

    const { user_id } = request.params;
    const { role_id, expires_at } = validation.data;

    try {
      // Verificar se usuário existe
      const user = getDb().prepare(`
        SELECT id FROM users WHERE id = ?
      `).get(user_id);

      if (!user) {
        return reply.status(404).send({
          error: 'Not Found',
          message: 'Usuário não encontrado',
        });
      }

      // Verificar se role existe
      const role = getDb().prepare(`
        SELECT id FROM roles WHERE id = ?
      `).get(role_id);

      if (!role) {
        return reply.status(404).send({
          error: 'Not Found',
          message: 'Role não encontrada',
        });
      }

      // Verificar se já tem role
      const existingRole = getDb().prepare(`
        SELECT id FROM user_roles
        WHERE user_id = ? AND role_id = ?
      `).get(user_id, role_id);

      if (existingRole) {
        return reply.status(409).send({
          error: 'Conflict',
          message: 'Usuário já tem esta role',
        });
      }

      // Atribuir role
      getDb().prepare(`
        INSERT INTO user_roles (user_id, role_id, granted_by, granted_at, expires_at)
        VALUES (?, ?, ?, datetime('now'), ?)
      `).run(user_id, role_id, request.user.id, expires_at || null);

      reply.status(200).send({
        status: 'OK',
        message: 'Role atribuída com sucesso',
      });
    } catch (error) {
      fastify.log.error({ error }, 'Erro ao atribuir role');
      reply.status(500).send({
        error: 'Internal Server Error',
        message: 'Erro ao atribuir role',
      });
    }
  });

  // DELETE /api/v1/users/:user_id/roles/:role_id (admin only)
  fastify.delete('/:user_id/roles/:role_id', { preHandler: [requirePermission(['users:manage_roles'])] }, async (request, reply) => {
    const { user_id, role_id } = request.params;

    try {
      const deleted = getDb().prepare(`
        DELETE FROM user_roles
        WHERE user_id = ? AND role_id = ?
      `).run(user_id, role_id);

      if (deleted.changes === 0) {
        return reply.status(404).send({
          error: 'Not Found',
          message: 'Role não atribuída ao usuário',
        });
      }

      reply.status(200).send({
        status: 'OK',
        message: 'Role removida com sucesso',
      });
    } catch (error) {
      fastify.log.error({ error }, 'Erro ao remover role');
      reply.status(500).send({
        error: 'Internal Server Error',
        message: 'Erro ao remover role',
      });
    }
  });
}

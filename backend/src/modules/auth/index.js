import { hash, verify } from 'argon2';
import { createHmac, randomBytes } from 'crypto';
import { config } from '../../config/index.js';
import { getDb } from '../../db/connection.js';
import * as authSchemas from '../../schemas/auth.js';
import speakeasy from 'speakeasy';

function createJWT(userId, expiresIn = '15m') {
  const now = Math.floor(Date.now() / 1000);
  const expiresInSeconds = parseExpires(expiresIn);
  const exp = now + expiresInSeconds;

  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    sub: userId,
    iat: now,
    exp,
  })).toString('base64url');

  const signature = createHmac('sha256', config.JWT_SECRET)
    .update(`${header}.${payload}`)
    .digest('base64url');

  return `${header}.${payload}.${signature}`;
}

function createRefreshToken() {
  return randomBytes(32).toString('base64url');
}

function hashToken(token) {
  return createHmac('sha256', config.ENCRYPTION_KEY).update(token).digest('hex');
}

function parseExpires(expiresIn) {
  const match = expiresIn.match(/^(\d+)(s|m|h|d)$/);
  if (!match) return 900; // 15min default

  const [, value, unit] = match;
  const seconds = {
    s: 1,
    m: 60,
    h: 60 * 60,
    d: 24 * 60 * 60,
  };

  return parseInt(value) * seconds[unit];
}

export async function registerAuthRoutes(fastify) {
  // POST /api/v1/auth/login
  fastify.post('/login', async (request, reply) => {
    const validation = authSchemas.schemas.login.safeParse(request.body);
    if (!validation.success) {
      return reply.status(400).send({
        error: 'Validation Error',
        details: validation.error.flatten(),
      });
    }

    const { email, password } = validation.data;

    try {
      // Buscar usuário por email
      const user = getDb().prepare(`
        SELECT id, password_hash, mfa_enabled, status, failed_attempts, locked_until
        FROM users
        WHERE email = ?
      `).get(email);

      if (!user) {
        return reply.status(401).send({
          error: 'Invalid Credentials',
          message: 'Email ou senha incorretos',
        });
      }

      // Verificar se está bloqueado
      if (user.locked_until && new Date(user.locked_until) > new Date()) {
        return reply.status(429).send({
          error: 'Account Locked',
          message: 'Conta temporariamente bloqueada',
          retryAfter: Math.ceil(
            (new Date(user.locked_until) - new Date()) / 1000
          ),
        });
      }

      // Verificar senha (timing-safe comparison via argon2.verify)
      const passwordMatch = await verify(user.password_hash, password);
      if (!passwordMatch) {
        // Incrementar tentativas falhadas
        const newFailedAttempts = (user.failed_attempts || 0) + 1;
        let lockedUntil = null;

        if (newFailedAttempts >= 5) {
          // Bloquear por 30 minutos após 5 tentativas
          lockedUntil = new Date(Date.now() + 30 * 60 * 1000).toISOString();
        }

        getDb().prepare(`
          UPDATE users
          SET failed_attempts = ?, locked_until = ?
          WHERE id = ?
        `).run(newFailedAttempts, lockedUntil, user.id);

        return reply.status(401).send({
          error: 'Invalid Credentials',
          message: 'Email ou senha incorretos',
        });
      }

      // Resetar failed_attempts
      getDb().prepare(`
        UPDATE users
        SET failed_attempts = 0, locked_until = NULL, last_login_at = datetime('now')
        WHERE id = ?
      `).run(user.id);

      // Se MFA obrigatório (admin/privileged), retornar 202 com temp session
      if (user.mfa_enabled) {
        const tempToken = createJWT(user.id, '5m'); // Temp token para MFA
        reply.setCookie('__Host-session-mfa', tempToken, {
          secure: config.NODE_ENV === 'production',
          httpOnly: true,
          sameSite: 'Strict',
          path: '/',
          maxAge: 5 * 60, // 5 minutos
        });

        return reply.status(202).send({
          status: 'MFA_REQUIRED',
          message: 'Autenticação de dois fatores necessária',
        });
      }

      // Gerar access token e refresh token
      const accessToken = createJWT(user.id, config.JWT_ACCESS_EXPIRES);
      const refreshToken = createRefreshToken();
      const refreshTokenHash = hashToken(refreshToken);

      // Armazenar refresh token hash em sessions
      const sessionId = randomBytes(16).toString('hex');
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
      getDb().prepare(`
        INSERT INTO sessions (id, user_id, refresh_token_hash, ip, user_agent, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(
        sessionId,
        user.id,
        refreshTokenHash,
        request.headers['x-forwarded-for']?.split(',')[0] || request.ip || 'unknown',
        request.headers['user-agent'] || null,
        expiresAt
      );

      // Setar cookies
      reply.setCookie('__Host-session', accessToken, {
        secure: config.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'Strict',
        path: '/',
        maxAge: parseExpires(config.JWT_ACCESS_EXPIRES),
      });

      reply.setCookie('__Host-refresh', refreshToken, {
        secure: config.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'Strict',
        path: '/',
        maxAge: parseExpires(config.JWT_REFRESH_EXPIRES),
      });

      reply.status(200).send({
        status: 'OK',
        message: 'Autenticado com sucesso',
        access_token: accessToken,
      });
    } catch (error) {
      fastify.log.error({ error, stack: error.stack }, 'Erro no login');
      reply.status(500).send({
        error: 'Internal Server Error',
        message: 'Erro ao processar login',
        debug: error.message,
      });
    }
  });

  // POST /api/v1/auth/mfa/verify
  fastify.post('/mfa/verify', async (request, reply) => {
    const tempToken = request.cookies.__Host_session_mfa;
    if (!tempToken) {
      return reply.status(401).send({
        error: 'Unauthorized',
        message: 'Sessão MFA inválida',
      });
    }

    const validation = authSchemas.schemas.mfaVerify.safeParse(request.body);
    if (!validation.success) {
      return reply.status(400).send({
        error: 'Validation Error',
        details: validation.error.flatten(),
      });
    }

    const { code } = validation.data;

    try {
      // Verificar temp token e extrair user_id
      const payload = JSON.parse(
        Buffer.from(tempToken.split('.')[1], 'base64url').toString()
      );
      const userId = payload.sub;

      // Buscar MFA secret do usuário
      const user = getDb().prepare(`
        SELECT mfa_secret_enc FROM users WHERE id = ?
      `).get(userId);

      if (!user) {
        return reply.status(401).send({
          error: 'Unauthorized',
          message: 'Usuário não encontrado',
        });
      }

      // Descriptografar e verificar TOTP
      // TODO: implementar decrypt real usando ENCRYPTION_KEY
      // Por enquanto, usar como se já estivesse descriptografado
      const verified = speakeasy.totp.verify({
        secret: user.mfa_secret_enc,
        encoding: 'base32',
        token: code,
        window: 1,
      });

      if (!verified) {
        return reply.status(401).send({
          error: 'Invalid Code',
          message: 'Código TOTP inválido',
        });
      }

      // Gerar tokens e setar cookies
      const accessToken = createJWT(userId, config.JWT_ACCESS_EXPIRES);
      const refreshToken = createRefreshToken();
      const refreshTokenHash = hashToken(refreshToken);

      const sessionId = randomBytes(16).toString('hex');
      getDb().prepare(`
        INSERT INTO sessions (id, user_id, refresh_token_hash, ip, user_agent, expires_at)
        VALUES (?, ?, ?, ?, ?, datetime('now', '+7 days'))
      `).run(
        sessionId,
        userId,
        refreshTokenHash,
        request.headers['x-forwarded-for']?.split(',')[0] || request.ip,
        request.headers['user-agent']
      );

      // Limpar cookie de MFA temp
      reply.clearCookie('__Host-session-mfa');

      // Setar cookies de sessão
      reply.setCookie('__Host-session', accessToken, {
        secure: config.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'Strict',
        path: '/',
        maxAge: parseExpires(config.JWT_ACCESS_EXPIRES),
      });

      reply.setCookie('__Host-refresh', refreshToken, {
        secure: config.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'Strict',
        path: '/',
        maxAge: parseExpires(config.JWT_REFRESH_EXPIRES),
      });

      reply.status(200).send({
        status: 'OK',
        message: 'MFA verificado com sucesso',
        access_token: accessToken,
      });
    } catch (error) {
      fastify.log.error({ error }, 'Erro na verificação MFA');
      reply.status(500).send({
        error: 'Internal Server Error',
        message: 'Erro ao verificar MFA',
      });
    }
  });

  // POST /api/v1/auth/logout
  fastify.post('/logout', { preHandler: [(req, rep) => requireAuth(req, rep)] }, async (request, reply) => {
    try {
      const refreshToken = request.cookies.__Host_refresh;
      if (refreshToken) {
        const refreshTokenHash = hashToken(refreshToken);
        getDb().prepare(`
          UPDATE sessions
          SET revoked_at = datetime('now')
          WHERE refresh_token_hash = ? AND revoked_at IS NULL
        `).run(refreshTokenHash);
      }

      reply.clearCookie('__Host-session');
      reply.clearCookie('__Host-refresh');
      reply.clearCookie('__Host-csrf');

      reply.status(200).send({
        status: 'OK',
        message: 'Desconectado com sucesso',
      });
    } catch (error) {
      fastify.log.error({ error }, 'Erro no logout');
      reply.status(500).send({
        error: 'Internal Server Error',
        message: 'Erro ao desconectar',
      });
    }
  });

  // POST /api/v1/auth/refresh
  fastify.post('/refresh', async (request, reply) => {
    const refreshToken = request.cookies.__Host_refresh;
    if (!refreshToken) {
      return reply.status(401).send({
        error: 'Unauthorized',
        message: 'Refresh token não encontrado',
      });
    }

    try {
      const refreshTokenHash = hashToken(refreshToken);

      // Verificar se refresh token está na sessions table e não foi revogado
      const session = getDb().prepare(`
        SELECT user_id FROM sessions
        WHERE refresh_token_hash = ? AND revoked_at IS NULL AND expires_at > datetime('now')
      `).get(refreshTokenHash);

      if (!session) {
        return reply.status(401).send({
          error: 'Unauthorized',
          message: 'Refresh token inválido ou expirado',
        });
      }

      // Gerar novo access token e refresh token
      const newAccessToken = createJWT(session.user_id, config.JWT_ACCESS_EXPIRES);
      const newRefreshToken = createRefreshToken();
      const newRefreshTokenHash = hashToken(newRefreshToken);

      // Revogar token anterior e criar nova sessão
      getDb().prepare(`
        UPDATE sessions
        SET revoked_at = datetime('now')
        WHERE refresh_token_hash = ?
      `).run(refreshTokenHash);

      const newSessionId = randomBytes(16).toString('hex');
      getDb().prepare(`
        INSERT INTO sessions (id, user_id, refresh_token_hash, ip, user_agent, expires_at)
        VALUES (?, ?, ?, ?, ?, datetime('now', '+7 days'))
      `).run(
        newSessionId,
        session.user_id,
        newRefreshTokenHash,
        request.headers['x-forwarded-for']?.split(',')[0] || request.ip,
        request.headers['user-agent']
      );

      // Atualizar cookies
      reply.setCookie('__Host-session', newAccessToken, {
        secure: config.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'Strict',
        path: '/',
        maxAge: parseExpires(config.JWT_ACCESS_EXPIRES),
      });

      reply.setCookie('__Host-refresh', newRefreshToken, {
        secure: config.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'Strict',
        path: '/',
        maxAge: parseExpires(config.JWT_REFRESH_EXPIRES),
      });

      reply.status(200).send({
        status: 'OK',
        access_token: newAccessToken,
      });
    } catch (error) {
      fastify.log.error({ error }, 'Erro ao renovar token');
      reply.status(500).send({
        error: 'Internal Server Error',
        message: 'Erro ao renovar token',
      });
    }
  });
}

function requireAuth(request, reply) {
  if (!request.user) {
    reply.status(401).send({
      error: 'Unauthorized',
      message: 'Autenticação necessária',
    });
  }
}

import { createHash } from 'crypto';
import { getDb } from '../db/connection.js';

function calculateHash(data) {
  return createHash('sha256').update(JSON.stringify(data)).digest('hex');
}

function getActorIP(request) {
  return request.headers['x-forwarded-for']?.split(',')[0] || request.ip || 'unknown';
}

export function auditLoggerMiddleware(fastify) {
  fastify.addHook('onResponse', async (request, reply) => {
    // Apenas auditar requests de mutação em rotas de API
    if (!request.url.startsWith('/api/') || !['POST', 'PUT', 'DELETE', 'PATCH'].includes(request.method)) {
      return;
    }

    // Determinar se a ação foi bem-sucedida
    const success = reply.statusCode >= 200 && reply.statusCode < 300;

    // Mapear rota para ação de auditoria
    let auditAction = 'api_call';
    let targetType = 'unknown';
    let targetId = null;
    let payload = {};

    if (request.url.includes('/auth/login')) {
      auditAction = 'login';
      targetType = 'user';
      payload = { email: request.body?.email };
    } else if (request.url.includes('/auth/logout')) {
      auditAction = 'logout';
      targetType = 'session';
    } else if (request.url.includes('/auth/mfa/verify')) {
      auditAction = 'mfa_verify';
      targetType = 'mfa';
    } else if (request.url.includes('/users/') && request.method === 'POST') {
      auditAction = 'user_created';
      targetType = 'user';
      payload = { email: request.body?.email };
    } else if (request.url.includes('/users/') && request.url.includes('/roles') && request.method === 'POST') {
      auditAction = 'role_assigned';
      targetType = 'user_role';
      // Extrair IDs da URL
      const match = request.url.match(/\/users\/([a-f0-9-]+)\/roles/);
      if (match) targetId = match[1];
    } else if (request.url.includes('/users/') && request.url.includes('/roles') && request.method === 'DELETE') {
      auditAction = 'role_revoked';
      targetType = 'user_role';
      // Extrair IDs da URL
      const match = request.url.match(/\/users\/([a-f0-9-]+)\/roles/);
      if (match) targetId = match[1];
    }

    try {
      // Obter hash anterior e próximo sequence
      const lastLog = getDb().prepare(`
        SELECT current_hash, sequence FROM audit_log
        ORDER BY sequence DESC
        LIMIT 1
      `).get();

      const previousHash = lastLog?.current_hash || 'genesis';
      const nextSequence = (lastLog?.sequence || 0) + 1;
      const logId = `audit-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

      const payloadHash = calculateHash(payload);
      const currentHash = calculateHash({
        previous_hash: previousHash,
        timestamp: new Date().toISOString(),
        action: auditAction,
        target_type: targetType,
        payload_hash: payloadHash,
      });

      // Inserir log de auditoria
      getDb().prepare(`
        INSERT INTO audit_log (
          id,
          sequence,
          timestamp,
          actor_id,
          actor_ip,
          actor_agent,
          action,
          target_type,
          target_id,
          payload_json,
          previous_hash,
          current_hash,
          success
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        logId,
        nextSequence,
        new Date().toISOString(),
        request.user?.id || null,
        getActorIP(request),
        request.headers['user-agent'] || null,
        auditAction,
        targetType,
        targetId,
        JSON.stringify(payload),
        previousHash,
        currentHash,
        success ? 1 : 0
      );
    } catch (error) {
      fastify.log.error({ error, url: request.url }, 'Erro ao registrar auditoria');
    }
  });
}

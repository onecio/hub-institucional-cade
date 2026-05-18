import { createHash } from 'crypto';
import { getDb } from '../../db/connection.js';
import * as userSchemas from '../../schemas/users.js';

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

function verifyHashChain(logs) {
  if (logs.length === 0) return true;

  let previousHash = 'genesis';
  for (const log of logs) {
    if (log.previous_hash !== previousHash) {
      return false;
    }
    previousHash = log.current_hash;
  }

  return true;
}

export async function registerAuditRoutes(fastify) {
  // GET /api/v1/audit/logs
  fastify.get('/logs', { preHandler: [requirePermission(['audit:read'])] }, async (request, reply) => {
    try {
      const validation = userSchemas.schemas.auditLogList.safeParse(request.query);
      if (!validation.success) {
        return reply.status(400).send({
          error: 'Validation Error',
          details: validation.error.flatten(),
        });
      }

      const { page, size, actor_id, action, target_type, start_date, end_date } = validation.data;
      const offset = (page - 1) * size;

      let query = 'SELECT * FROM audit_log WHERE 1=1';
      const params = [];

      if (actor_id) {
        query += ' AND actor_id = ?';
        params.push(actor_id);
      }

      if (action) {
        query += ' AND action = ?';
        params.push(action);
      }

      if (target_type) {
        query += ' AND target_type = ?';
        params.push(target_type);
      }

      if (start_date) {
        query += ' AND timestamp >= ?';
        params.push(start_date);
      }

      if (end_date) {
        query += ' AND timestamp <= ?';
        params.push(end_date);
      }

      query += ' ORDER BY sequence DESC LIMIT ? OFFSET ?';
      params.push(size, offset);

      const logs = getDb().prepare(query).all(...params);

      // Contar total
      let countQuery = 'SELECT COUNT(*) as count FROM audit_log WHERE 1=1';
      const countParams = [];

      if (actor_id) {
        countQuery += ' AND actor_id = ?';
        countParams.push(actor_id);
      }

      if (action) {
        countQuery += ' AND action = ?';
        countParams.push(action);
      }

      if (target_type) {
        countQuery += ' AND target_type = ?';
        countParams.push(target_type);
      }

      if (start_date) {
        countQuery += ' AND timestamp >= ?';
        countParams.push(start_date);
      }

      if (end_date) {
        countQuery += ' AND timestamp <= ?';
        countParams.push(end_date);
      }

      const { count } = getDb().prepare(countQuery).get(...countParams);

      reply.status(200).send({
        logs,
        total: count,
        page,
        size,
        pages: Math.ceil(count / size),
      });
    } catch (error) {
      fastify.log.error({ error }, 'Erro ao listar logs de auditoria');
      reply.status(500).send({
        error: 'Internal Server Error',
        message: 'Erro ao listar logs de auditoria',
      });
    }
  });

  // GET /api/v1/audit/logs/:id
  fastify.get('/logs/:id', { preHandler: [requirePermission(['audit:read'])] }, async (request, reply) => {
    try {
      const { id } = request.params;

      const log = getDb().prepare(`
        SELECT * FROM audit_log WHERE id = ?
      `).get(id);

      if (!log) {
        return reply.status(404).send({
          error: 'Not Found',
          message: 'Log de auditoria não encontrado',
        });
      }

      // Verificar integridade do hash chain (últimas 3 entradas)
      const previousLogs = getDb().prepare(`
        SELECT * FROM audit_log WHERE sequence < ? ORDER BY sequence DESC LIMIT 3
      `).all(log.sequence);

      let chainValid = log.previous_hash === (previousLogs[0]?.current_hash || 'genesis');

      // Recalcular hash atual para verificar integridade
      const recalculatedHash = createHash('sha256').update(JSON.stringify({
        previous_hash: log.previous_hash,
        timestamp: log.timestamp,
        action: log.action,
        target_type: log.target_type,
        payload_json: log.payload_json,
      })).digest('hex');

      chainValid = chainValid && recalculatedHash === log.current_hash;

      reply.status(200).send({
        log,
        chain_valid: chainValid,
      });
    } catch (error) {
      fastify.log.error({ error }, 'Erro ao buscar log de auditoria');
      reply.status(500).send({
        error: 'Internal Server Error',
        message: 'Erro ao buscar log de auditoria',
      });
    }
  });

  // GET /api/v1/audit/verify-chain
  fastify.get('/verify-chain', { preHandler: [requirePermission(['audit:read'])] }, async (request, reply) => {
    try {
      const logs = getDb().prepare(`
        SELECT * FROM audit_log ORDER BY sequence ASC
      `).all();

      const chainValid = verifyHashChain(logs);

      reply.status(200).send({
        chain_valid: chainValid,
        total_logs: logs.length,
        message: chainValid
          ? 'Hash chain íntegra'
          : 'Integridade do hash chain comprometida',
      });
    } catch (error) {
      fastify.log.error({ error }, 'Erro ao verificar hash chain');
      reply.status(500).send({
        error: 'Internal Server Error',
        message: 'Erro ao verificar hash chain',
      });
    }
  });
}

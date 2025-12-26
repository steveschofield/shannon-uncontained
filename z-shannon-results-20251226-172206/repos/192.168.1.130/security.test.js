/**
 * Security Tests - LSG v2 Generated
 * 
 * Target: http://192.168.1.130:3000
 * Vulnerability hypotheses: 4
 */

const request = require('supertest');
const app = require('../app');

const request = require('supertest');
const app = require('./app'); // assuming your app is in a separate file

describe('Security Tests', () => {
  describe('/api/v1', () => {
    it('should prevent SQL Injection via URL Parameter (A01:2021-Injection)', async () => {
      const url = '/api/v1?query=SELECT * FROM users WHERE id =';
      const response = await request(app).get(url + '1');

      expect(response.status).toBe(200);
      expect(response.body).not.toContain('SQL error');
    });

    it('should prevent SQL Injection via URL Parameter (A01:2021-Injection) - Multiple Queries', async () => {
      const url = '/api/v1?query=SELECT * FROM users WHERE id =';
      const response = await request(app).get(url + '1 OR 1=1');

      expect(response.status).toBe(200);
      expect(response.body).not.toContain('SQL error');
    });

    it('should prevent SQL Injection via URL Parameter (A01:2021-Injection) - Union Operator', async () => {
      const url = '/api/v1?query=SELECT * FROM users WHERE id =';
      const response = await request(app).get(url + '1 UNION SELECT * FROM users');

      expect(response.status).toBe(200);
      expect(response.body).not.toContain('SQL error');
    });
  });

  describe('/graphql', () => {
    it('should prevent Authentication Bypass via GraphQL (A07:2021-Identification of Vulnerable and Outdated Components)', async () => {
      const query = 'query { user { id } }';
      const headers = { Authorization: '' }; // no auth header
      const response = await request(app).post('/graphql')
        .set('Content-Type', 'application/json')
        .send({ query, variables: {} })
        .set(headers);

      expect(response.status).toBe(401);
    });

    it('should prevent Authentication Bypass via GraphQL (A07:2021-Identification of Vulnerable and Outdated Components) - Invalid Token', async () => {
      const query = 'query { user { id } }';
      const headers = { Authorization: 'Invalid-Token' };
      const response = await request(app).post('/graphql')
        .set('Content-Type', 'application/json')
        .send({ query, variables: {} })
        .set(headers);

      expect(response.status).toBe(401);
    });
  });

  describe('/rest', () => {
    it('should prevent SSRF via URL Parameter (A10:2021-Server-Side Request Forgery)', async () => {
      const url = '/rest?host=example.com';
      const response = await request(app).get(url);

      expect(response.status).toBe(200);
      expect(response.body).not.toContain('SSRF error');
    });

    it('should prevent SSRF via URL Parameter (A10:2021-Server-Side Request Forgery) - Invalid Host', async () => {
      const url = '/rest?host=invalid-host';
      const response = await request(app).get(url);

      expect(response.status).toBe(400);
    });
  });

  describe('/api/v2', () => {
    it('should prevent Insecure API Design via URL Parameter (A04:2021-Insecure Design)', async () => {
      const url = '/api/v2?query=SELECT * FROM users WHERE id =';
      const response = await request(app).get(url + '1');

      expect(response.status).toBe(200);
      expect(response.body).not.toContain('Insecure API error');
    });

    it('should prevent Insecure API Design via URL Parameter (A04:2021-Insecure Design) - Multiple Queries', async () => {
      const url = '/api/v2?query=SELECT * FROM users WHERE id =';
      const response = await request(app).get(url + '1 OR 1=1');

      expect(response.status).toBe(200);
      expect(response.body).not.toContain('Insecure API error');
    });
  });

  describe('/api/v1 and /graphql', () => {
    it('should not disclose sensitive information (Information Disclosure)', async () => {
      const response = await request(app).get('/api/v1');

      expect(response.status).toBe(200);
      expect(response.body).not.toContain('sensitive information');
    });

    it('should not disclose sensitive information (Information Disclosure) - GraphQL', async () => {
      const query = 'query { user { id } }';
      const response = await request(app).post('/graphql')
        .set('Content-Type', 'application/json')
        .send({ query, variables: {} });

      expect(response.status).toBe(200);
      expect(response.body).not.toContain('sensitive information');
    });
  });
});

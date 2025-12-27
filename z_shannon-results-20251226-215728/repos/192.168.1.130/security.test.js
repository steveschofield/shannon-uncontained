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
  describe('/api endpoint', () => {
    it('should prevent SQL Injection via URL Parameter (A01:2021-Injection)', async () => {
      const url = '/api';
      const payload = 'SELECT * FROM users WHERE id = \' OR 1=1 --';

      const response = await request(app)
        .get(url)
        .query({ param: payload });

      expect(response.statusCode).toBe(400);
      expect(response.body.error).toContain('Invalid query parameter');
    });

    it('should prevent SQL Injection via URL Parameter (A01:2021-Injection) - Blind Attack', async () => {
      const url = '/api';
      const payload = 'SELECT * FROM users WHERE id = \' OR 1=1 --\' AND 1=0';

      const response = await request(app)
        .get(url)
        .query({ param: payload });

      expect(response.statusCode).toBe(400);
      expect(response.body.error).toContain('Invalid query parameter');
    });
  });

  describe('/graphql endpoint', () => {
    it('should prevent GraphQL Injection via Query Parameter (A07:2021-Identification of Vulnerable and Outdated Components)', async () => {
      const url = '/graphql';
      const payload = '{ query: "query { users { id }" }';

      const response = await request(app)
        .post(url)
        .send({ query: payload });

      expect(response.statusCode).toBe(400);
      expect(response.body.errors[0].message).toContain('Invalid GraphQL query');
    });
  });

  describe('/rest endpoint', () => {
    it('should prevent SSRF via URL Parameter (A10:2021-Server-Side Request Forgery)', async () => {
      const url = '/rest';
      const payload = 'http://example.com';

      const response = await request(app)
        .get(url)
        .query({ param: payload });

      expect(response.statusCode).toBe(400);
      expect(response.body.error).toContain('Invalid URL parameter');
    });
  });

  describe('/api/v1 endpoint', () => {
    it('should prevent Insecure Design Pattern via API Versioning (A04:2021-Insufficient Attack Protection)', async () => {
      const url = '/api/v1';
      const payload = 'GET /users HTTP/1.1';

      const response = await request(app)
        .get(url)
        .set('Authorization', 'Bearer invalid-token');

      expect(response.statusCode).toBe(401);
      expect(response.body.error).toContain('Invalid token');
    });
  });
});

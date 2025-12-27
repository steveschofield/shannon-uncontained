/**
 * API Tests - LSG v2 Generated
 * 
 * Target: http://192.168.1.130:3000
 * Endpoints: 8
 */

const request = require('supertest');
const app = require('../app'); // Adjust path as needed

const BASE_URL = 'http://192.168.1.130:3000';

describe('API Endpoints', () => {

  describe('root', () => {

    // Confidence: 0.50
    it('should GET /', async () => {
      const response = await request(app)
        .get('/')
        
        .set('Accept', 'application/json');
      
      expect(response.status).toBeGreaterThanOrEqual(200);
      expect(response.status).toBeLessThan(500);
    });

    // Confidence: 0.50
    it('should GET /api', async () => {
      const response = await request(app)
        .get('/api')
        
        .set('Accept', 'application/json');
      
      expect(response.status).toBeGreaterThanOrEqual(200);
      expect(response.status).toBeLessThan(500);
    });

    // Confidence: 0.50
    it('should GET /api/v1', async () => {
      const response = await request(app)
        .get('/api/v1')
        
        .set('Accept', 'application/json');
      
      expect(response.status).toBeGreaterThanOrEqual(200);
      expect(response.status).toBeLessThan(500);
    });

    // Confidence: 0.50
    it('should GET /api/v2', async () => {
      const response = await request(app)
        .get('/api/v2')
        
        .set('Accept', 'application/json');
      
      expect(response.status).toBeGreaterThanOrEqual(200);
      expect(response.status).toBeLessThan(500);
    });

    // Confidence: 0.50
    it('should GET /v1', async () => {
      const response = await request(app)
        .get('/v1')
        
        .set('Accept', 'application/json');
      
      expect(response.status).toBeGreaterThanOrEqual(200);
      expect(response.status).toBeLessThan(500);
    });

    // Confidence: 0.50
    it('should GET /v2', async () => {
      const response = await request(app)
        .get('/v2')
        
        .set('Accept', 'application/json');
      
      expect(response.status).toBeGreaterThanOrEqual(200);
      expect(response.status).toBeLessThan(500);
    });
  });

  describe('graphql', () => {

    // Confidence: 0.50
    it('should GET /graphql', async () => {
      const response = await request(app)
        .get('/graphql')
        
        .set('Accept', 'application/json');
      
      expect(response.status).toBeGreaterThanOrEqual(200);
      expect(response.status).toBeLessThan(500);
    });
  });

  describe('rest', () => {

    // Confidence: 0.50
    it('should GET /rest', async () => {
      const response = await request(app)
        .get('/rest')
        
        .set('Accept', 'application/json');
      
      expect(response.status).toBeGreaterThanOrEqual(200);
      expect(response.status).toBeLessThan(500);
    });
  });

});
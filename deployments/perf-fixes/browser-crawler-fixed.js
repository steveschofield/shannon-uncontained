/**
 * BrowserCrawlerAgent Fix - Graceful degradation when browser not available
 * 
 * Apply to: src/local-source-generator/v2/agents/recon/browser-crawler-agent.js
 * 
 * The issue is that BrowserCrawler completes in 0.25s, meaning it's not actually crawling.
 * This happens when Playwright/Puppeteer isn't installed.
 * 
 * This fix adds proper dependency checking and clear error messages.
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent, EVENT_TYPES } from '../../worldmodel/evidence-graph.js';

export class BrowserCrawlerAgent extends BaseAgent {
    constructor(options = {}) {
        super('BrowserCrawlerAgent', options);

        this.inputs_schema = {
            type: 'object',
            required: ['target'],
            properties: {
                target: { type: 'string', description: 'Target URL' },
                maxDepth: { type: 'number', default: 2 },
                maxPages: { type: 'number', default: 50 },
            },
        };

        this.outputs_schema = {
            type: 'object',
            properties: {
                urls: { type: 'array', items: { type: 'string' } },
                forms: { type: 'array', items: { type: 'object' } },
                javascript_urls: { type: 'array', items: { type: 'string' } },
                crawled: { type: 'boolean' },
            },
        };

        this.requires = {
            evidence_kinds: [],
            model_nodes: []
        };

        this.emits = {
            evidence_events: [EVENT_TYPES.ENDPOINT_DISCOVERED, 'form_discovered'],
            model_updates: [],
            claims: [],
            artifacts: [],
        };

        this.default_budget = {
            max_time_ms: 120000, // 2 minutes
            max_network_requests: 100,
            max_tokens: 0,
            max_tool_invocations: 0,
        };

        // ✅ NEW: Cache dependency check result
        this.browserAvailable = null;
        this.browserModule = null;
    }

    /**
     * ✅ NEW: Check if browser automation is available
     */
    async checkBrowserAvailable() {
        // Return cached result
        if (this.browserAvailable !== null) {
            return this.browserAvailable;
        }

        // Try Playwright first
        try {
            this.browserModule = await import('playwright');
            this.browserAvailable = true;
            return true;
        } catch (e) {
            // Try Puppeteer
            try {
                this.browserModule = await import('puppeteer');
                this.browserAvailable = true;
                return true;
            } catch (e2) {
                this.browserAvailable = false;
                return false;
            }
        }
    }

    /**
     * ✅ FIXED: Main entry point with dependency checking
     */
    async run(ctx, inputs) {
        const { target, maxDepth = 2, maxPages = 50 } = inputs;

        const results = {
            urls: [],
            forms: [],
            javascript_urls: [],
            crawled: false,
        };

        // ✅ FIX: Check dependencies first
        const available = await this.checkBrowserAvailable();

        if (!available) {
            console.warn('⚠️  Browser automation not available - skipping BrowserCrawlerAgent');
            console.warn('   Install Playwright: npm install playwright');
            console.warn('   Then install browsers: npx playwright install chromium');
            console.warn('   Or install Puppeteer: npm install puppeteer');
            
            this.setStatus('Skipped (browser not available)');
            return results;
        }

        this.setStatus('Starting browser crawl...');

        try {
            // Launch browser
            const browser = await this.launchBrowser();

            // Crawl with browser
            const crawlResults = await this.crawlWithBrowser(
                ctx,
                browser,
                target,
                maxDepth,
                maxPages
            );

            // Close browser
            await browser.close();

            // Update results
            results.urls = crawlResults.urls;
            results.forms = crawlResults.forms;
            results.javascript_urls = crawlResults.javascript_urls;
            results.crawled = true;

            this.setStatus(`Crawled ${results.urls.length} pages`);

        } catch (error) {
            console.error('Browser crawl error:', error.message);
            this.setStatus('Crawl failed - see logs');
            // Return empty results instead of crashing
        }

        return results;
    }

    /**
     * Launch browser with appropriate module
     */
    async launchBrowser() {
        const moduleName = this.browserModule.name || 'unknown';

        if (moduleName === 'playwright' || this.browserModule.chromium) {
            // Playwright
            return await this.browserModule.chromium.launch({
                headless: true,
                args: ['--no-sandbox', '--disable-dev-shm-usage'],
            });
        } else {
            // Puppeteer
            return await this.browserModule.launch({
                headless: true,
                args: ['--no-sandbox', '--disable-dev-shm-usage'],
            });
        }
    }

    /**
     * Crawl with browser automation
     */
    async crawlWithBrowser(ctx, browser, startUrl, maxDepth, maxPages) {
        const visited = new Set();
        const toVisit = [{ url: startUrl, depth: 0 }];
        const urls = [];
        const forms = [];
        const javascriptUrls = [];

        while (toVisit.length > 0 && visited.size < maxPages) {
            const { url, depth } = toVisit.shift();

            // Skip if already visited
            if (visited.has(url)) {
                continue;
            }

            // Skip if too deep
            if (depth > maxDepth) {
                continue;
            }

            visited.add(url);

            try {
                // Open page
                const page = await browser.newPage();

                // Navigate
                await page.goto(url, {
                    waitUntil: 'domcontentloaded',
                    timeout: 30000,
                });

                // Extract URLs
                const pageUrls = await page.evaluate(() => {
                    const links = Array.from(document.querySelectorAll('a[href]'));
                    return links.map(a => a.href);
                });

                // Extract forms
                const pageForms = await page.evaluate(() => {
                    const forms = Array.from(document.querySelectorAll('form'));
                    return forms.map(form => ({
                        action: form.action,
                        method: form.method,
                        inputs: Array.from(form.querySelectorAll('input')).map(input => ({
                            name: input.name,
                            type: input.type,
                        })),
                    }));
                });

                // Extract JavaScript files
                const jsUrls = await page.evaluate(() => {
                    const scripts = Array.from(document.querySelectorAll('script[src]'));
                    return scripts.map(s => s.src);
                });

                // Add to results
                urls.push(url);
                forms.push(...pageForms);
                javascriptUrls.push(...jsUrls);

                // Emit evidence
                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: EVENT_TYPES.ENDPOINT_DISCOVERED,
                    target: startUrl,
                    payload: {
                        url,
                        discovered_via: 'browser_crawl',
                    },
                }));

                // Add new URLs to queue
                for (const newUrl of pageUrls) {
                    if (newUrl.startsWith(startUrl)) {
                        toVisit.push({ url: newUrl, depth: depth + 1 });
                    }
                }

                await page.close();

            } catch (error) {
                console.error(`Error crawling ${url}:`, error.message);
                continue;
            }
        }

        return {
            urls: Array.from(new Set(urls)),
            forms,
            javascript_urls: Array.from(new Set(javascriptUrls)),
        };
    }
}

export default BrowserCrawlerAgent;

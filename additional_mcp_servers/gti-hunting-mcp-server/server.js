#!/usr/bin/env node

/**
 * GTI Hunting MCP Server - Enhanced Version with Private URL Scanning
 * 
 * A Model Context Protocol server for VirusTotal API integration
 * Supports: Livehunt rulesets, IOC Collections, and Private URL Scanning
 * 
 * Usage: GTI_APIKEY="your-key" node server.js
 */

const readline = require('readline');
const https = require('https');

class GTIHuntingMCPServer {
  constructor() {
    this.apiKey = process.env.GTI_APIKEY;
    this.tools = [
      {
        name: "create_hunting_ruleset",
        description: "Create a new hunting ruleset in VirusTotal Livehunt with YARA rules",
        inputSchema: {
          type: "object",
          properties: {
            name: {
              type: "string",
              description: "Name of the hunting ruleset"
            },
            rules: {
              type: "string", 
              description: "YARA rules content (VT module will be auto-imported)"
            },
            enabled: {
              type: "boolean",
              description: "Whether the ruleset should be enabled (default: false for safety)",
              default: false
            }
          },
          required: ["name", "rules"]
        }
      },
      {
        name: "create_collection",
        description: "Create a new IOC collection in VirusTotal. IOCs (Indicators of Compromise) are security artifacts like domains, URLs, IP addresses, and file hashes.",
        inputSchema: {
          type: "object",
          properties: {
            name: {
              type: "string",
              description: "Name of the collection"
            },
            description: {
              type: "string",
              description: "Description of the collection"
            },
            domains: {
              type: "array",
              items: { type: "string" },
              description: "Domain names - e.g., ['malicious-site.com', 'phishing.net']"
            },
            urls: {
              type: "array", 
              items: { type: "string" },
              description: "URLs - e.g., ['https://evil.com/malware.exe', 'http://phishing.site/login']"
            },
            ip_addresses: {
              type: "array",
              items: { type: "string" },
              description: "IP addresses - e.g., ['192.168.1.100', '10.0.0.50']"
            },
            file_hashes: {
              type: "array",
              items: { type: "string" },
              description: "File hashes (SHA256/SHA1/MD5) - e.g., ['3e3e34d158db5a552483e76bb895b9d6e...']"
            }
          },
          required: ["name"]
        }
      },
      {
        name: "scan_private_url",
        description: "Submit a URL for private scanning and automatically retrieve the complete analysis report. This includes detection results, network information, and related artifacts.",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "The URL to scan (e.g., 'https://example.com/suspicious-page')"
            },
            include_relationships: {
              type: "boolean",
              description: "Whether to include additional relationship data (IP addresses, network location, downloaded files)",
              default: true
            },
            max_wait_time: {
              type: "number",
              description: "Maximum time to wait for scan completion in seconds (default: 300, max: 600)",
              default: 300,
              minimum: 30,
              maximum: 600
            }
          },
          required: ["url"]
        }
      }
    ];
    
    this.setupReadline();
  }

  setupReadline() {
    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: false
    });
    
    this.rl.on('line', (line) => {
      try {
        const message = JSON.parse(line.trim());
        this.handleMessage(message);
      } catch (error) {
        this.sendError(-32700, "Parse error", null);
      }
    });
    
    process.stdin.resume();
  }

  async handleMessage(message) {
    const { method, params, id } = message;
    
    try {
      switch (method) {
        case 'initialize':
          await this.handleInitialize(params, id);
          break;
        case 'tools/list':
          await this.handleToolsList(id);
          break;
        case 'tools/call':
          await this.handleToolCall(params, id);
          break;
        default:
          this.sendError(-32601, "Method not found", id);
      }
    } catch (error) {
      this.sendError(-32603, "Internal error", id);
    }
  }

  async handleInitialize(params, id) {
    if (!this.apiKey) {
      this.sendError(-32602, "GTI_APIKEY environment variable not set", id);
      return;
    }

    this.sendResponse({
      protocolVersion: "2024-11-05",
      capabilities: { tools: {} },
      serverInfo: {
        name: "gti-hunting-mcp-server",
        version: "1.1.0"
      }
    }, id);
  }

  async handleToolsList(id) {
    this.sendResponse({ tools: this.tools }, id);
  }

  async handleToolCall(params, id) {
    const { name, arguments: args } = params;
    
    try {
      let result;
      switch (name) {
        case 'create_hunting_ruleset':
          result = await this.createHuntingRuleset(args);
          break;
        case 'create_collection':
          result = await this.createCollection(args);
          break;
        case 'scan_private_url':
          result = await this.scanPrivateUrl(args);
          break;
        default:
          this.sendError(-32602, `Unknown tool: ${name}`, id);
          return;
      }
      
      const responseText = result.success 
        ? `✅ Success!\n\n${JSON.stringify(result.data, null, 2)}`
        : `❌ API Error (${result.statusCode})\n\n${JSON.stringify(result.error || result.data, null, 2)}`;
      
      this.sendResponse({
        content: [{ type: "text", text: responseText }]
      }, id);
    } catch (error) {
      this.sendError(-32603, `Tool execution failed: ${error.message}`, id);
    }
  }

  async createHuntingRuleset(args) {
    const { name, rules, enabled = false } = args;
    
    // Auto-import VT module for advanced features
    let processedRules = rules.includes('import "vt"') ? rules : `import "vt"\n${rules}`;
    
    // Add identification suffix
    const finalName = `${name}-Elevate2025`;
    
    const postData = JSON.stringify({
      data: {
        type: "hunting_ruleset",
        attributes: {
          name: finalName,
          rules: processedRules,
          enabled: enabled,
          match_object_type: "file",
          limit: 100
        }
      }
    });
    
    return this.makeRequest('/api/v3/intelligence/hunting_rulesets', 'POST', postData);
  }

  async createCollection(args) {
    const { name, description = '', domains = [], urls = [], ip_addresses = [], file_hashes = [] } = args;
    
    // Validate that at least one IOC is provided
    const hasIOCs = domains.length > 0 || urls.length > 0 || ip_addresses.length > 0 || file_hashes.length > 0;
    
    if (!hasIOCs) {
      return {
        success: false,
        statusCode: 400,
        error: {
          code: "NoIOCsError",
          message: "No IOCs provided. Collections must contain at least one IOC (domain, URL, IP address, or file hash)."
        }
      };
    }
    
    // Add identification
    const finalName = `${name}-Elevate2025`;
    const finalDescription = description 
      ? `${description} (automatically created via cline / mcp)` 
      : 'automatically created via cline / mcp';
    
    // Build relationships
    const relationships = {};
    
    if (domains.length > 0) {
      relationships.domains = { data: domains.map(domain => ({ type: "domain", id: domain })) };
    }
    
    if (urls.length > 0) {
      relationships.urls = { data: urls.map(url => ({ type: "url", url: url })) };
    }
    
    if (ip_addresses.length > 0) {
      relationships.ip_addresses = { data: ip_addresses.map(ip => ({ type: "ip_address", id: ip })) };
    }
    
    if (file_hashes.length > 0) {
      relationships.files = { data: file_hashes.map(hash => ({ type: "file", id: hash })) };
    }
    
    const postData = JSON.stringify({
      data: {
        type: "collection",
        attributes: {
          name: finalName,
          description: finalDescription
        },
        relationships: relationships
      }
    });
    
    return this.makeRequest('/api/v3/collections', 'POST', postData);
  }

  async scanPrivateUrl(args) {
    const { url, include_relationships = true, max_wait_time = 300 } = args;
    
    try {
      // Step 1: Submit URL for scanning
      const submitResult = await this.submitUrlForScanning(url);
      if (!submitResult.success) {
        return submitResult;
      }
      
      const analysisId = submitResult.data.data.id;
      
      // Step 2: Wait for analysis to complete
      const analysisResult = await this.waitForAnalysisCompletion(analysisId, max_wait_time);
      if (!analysisResult.success) {
        return analysisResult;
      }
      
      // Step 3: Get the detailed scan report (use the URL ID from meta, not analysis ID)
      const urlId = analysisResult.data.meta?.url_info?.id;
      if (!urlId) {
        return {
          success: false,
          statusCode: 500,
          error: {
            code: "MissingUrlIdError",
            message: "Could not extract URL ID from analysis response"
          }
        };
      }
      
      const reportResult = await this.getPrivateUrlReport(urlId);
      if (!reportResult.success) {
        return reportResult;
      }
      
      // Step 4: Optionally get relationship data
      let relationshipData = {};
      if (include_relationships) {
        relationshipData = await this.getUrlRelationships(urlId);
      }
      
      // Combine all results
      const combinedResult = {
        scan_summary: {
          url: url,
          analysis_id: analysisId,
          url_id: urlId,
          scan_date: analysisResult.data.data.attributes.date,
          status: analysisResult.data.data.attributes.status,
          sandbox_status: analysisResult.data.data.attributes.sandbox_status || {}
        },
        url_info: {
          original_url: reportResult.data.data.attributes.url,
          final_url: reportResult.data.data.attributes.last_final_url,
          title: reportResult.data.data.attributes.title,
          last_http_response_code: reportResult.data.data.attributes.last_http_response_code,
          redirection_chain: reportResult.data.data.attributes.redirection_chain || [],
          tld: reportResult.data.data.attributes.tld
        },
        gti_assessment: reportResult.data.data.attributes.gti_assessment || {},
        security_info: {
          tags: reportResult.data.data.attributes.tags || [],
          trackers: Object.keys(reportResult.data.data.attributes.trackers || {}).length,
          tracker_details: reportResult.data.data.attributes.trackers || {},
          outgoing_links_count: (reportResult.data.data.attributes.outgoing_links || []).length
        },
        technical_details: {
          favicon: reportResult.data.data.attributes.favicon,
          html_meta: reportResult.data.data.attributes.html_meta,
          last_http_response_headers: reportResult.data.data.attributes.last_http_response_headers,
          last_http_response_content_length: reportResult.data.data.attributes.last_http_response_content_length,
          last_http_response_content_sha256: reportResult.data.data.attributes.last_http_response_content_sha256
        },
        relationships: relationshipData
      };
      
      return {
        success: true,
        statusCode: 200,
        data: combinedResult,
        error: null
      };
      
    } catch (error) {
      return {
        success: false,
        statusCode: 500,
        error: {
          code: "ScanProcessError",
          message: `Failed to complete URL scan process: ${error.message}`
        }
      };
    }
  }

  async submitUrlForScanning(url) {
    // Use form-encoded data instead of JSON as shown in the sample
    const postData = `url=${encodeURIComponent(url)}`;
    return this.makeRequest('/api/v3/private/urls', 'POST', postData, 'application/x-www-form-urlencoded');
  }

  async waitForAnalysisCompletion(analysisId, maxWaitTime) {
    const startTime = Date.now();
    const checkInterval = 5000; // Check every 5 seconds
    
    while (Date.now() - startTime < maxWaitTime * 1000) {
      const result = await this.makeRequest(`/api/v3/private/analyses/${analysisId}`, 'GET');
      
      if (!result.success) {
        return result;
      }
      
      const status = result.data.data.attributes.status;
      
      if (status === 'finished') {
        return result;
      }
      
      if (status === 'error' || status === 'corrupted file' || status === 'unsupported file type' || status === 'timeout' || status === 'startup error') {
        return {
          success: false,
          statusCode: 400,
          error: {
            code: "AnalysisFailedError",
            message: `Analysis failed with status: ${status}`
          }
        };
      }
      
      // Wait before next check
      await this.sleep(checkInterval);
    }
    
    // Timeout reached
    return {
      success: false,
      statusCode: 408,
      error: {
        code: "AnalysisTimeoutError",
        message: `Analysis did not complete within ${maxWaitTime} seconds`
      }
    };
  }

  async getPrivateUrlReport(analysisId) {
    return this.makeRequest(`/api/v3/private/urls/${analysisId}`, 'GET');
  }

  async getUrlRelationships(analysisId) {
    const relationships = ['last_serving_ip_address', 'network_location', 'downloaded_files'];
    const relationshipData = {};
    
    for (const relationship of relationships) {
      try {
        const result = await this.makeRequest(`/api/v3/private/urls/${analysisId}/${relationship}`, 'GET');
        if (result.success) {
          relationshipData[relationship] = result.data;
        } else {
          relationshipData[relationship] = { error: `Failed to fetch ${relationship}` };
        }
      } catch (error) {
        relationshipData[relationship] = { error: error.message };
      }
    }
    
    return relationshipData;
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  makeRequest(path, method, postData = null, contentType = 'application/json') {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: 'www.virustotal.com',
        port: 443,
        path: path,
        method: method,
        headers: {
          'x-apikey': this.apiKey,
          'Content-Type': contentType
        }
      };
      
      if (postData) {
        options.headers['Content-Length'] = Buffer.byteLength(postData);
      }
      
      const req = https.request(options, (res) => {
        const chunks = [];
        let totalLength = 0;
        
        res.on('data', (chunk) => {
          chunks.push(chunk);
          totalLength += chunk.length;
        });
        
        res.on('end', () => {
          try {
            // Handle HTTP 204 No Content (empty response body is expected)
            if (res.statusCode === 204) {
              resolve({
                success: true,
                statusCode: res.statusCode,
                data: null,
                error: null
              });
              return;
            }
            
            // Efficiently concatenate chunks
            const responseBody = totalLength > 0 ? Buffer.concat(chunks, totalLength).toString() : '';
            
            // Handle empty response bodies for other success codes
            if (!responseBody && res.statusCode >= 200 && res.statusCode < 300) {
              resolve({
                success: true,
                statusCode: res.statusCode,
                data: {},
                error: null
              });
              return;
            }
            
            // Parse JSON response
            const response = responseBody ? JSON.parse(responseBody) : {};
            
            resolve({
              success: res.statusCode >= 200 && res.statusCode < 300,
              statusCode: res.statusCode,
              data: response,
              error: res.statusCode >= 400 ? (response.error || response) : null
            });
            
          } catch (error) {
            const snippet = chunks.length > 0 
              ? Buffer.concat(chunks, Math.min(totalLength, 200)).toString()
              : '(empty)';
            reject(new Error(`Failed to parse response (status: ${res.statusCode}): ${error.message}. Response body snippet: "${snippet}"`));
          }
        });
      });
      
      req.on('error', (error) => reject(new Error(`Request failed: ${error.message}`)));
      req.setTimeout(30000, () => req.destroy(new Error('Request timeout')));
      
      if (postData) req.write(postData);
      req.end();
    });
  }

  sendResponse(result, id) {
    console.log(JSON.stringify({ jsonrpc: "2.0", result, id }));
  }

  sendError(code, message, id) {
    console.log(JSON.stringify({ jsonrpc: "2.0", error: { code, message }, id }));
  }
}

// Start server
const server = new GTIHuntingMCPServer();

// Graceful shutdown
process.on('SIGINT', () => process.exit(0));
process.on('SIGTERM', () => process.exit(0));
# Mandiant Threat Intelligence MCP Server (Python)

A Python-based MCP (Model Context Protocol) server that provides Claude with access to Mandiant's Threat Intelligence API for querying threat data, indicators, reports, and campaigns.

## Features

- **Indicator Search**: Query IPs, domains, hashes, and other IOCs
- **Threat Reports**: Access detailed threat intelligence reports
- **Threat Actors**: Get information about APT groups and threat actors
- **Malware Families**: Research malware characteristics and capabilities
- **Campaign Data**: Analyze coordinated attack campaigns
- **Async Performance**: Built with aiohttp for efficient API requests
- **Type Safety**: Full type hints for better code reliability

## Prerequisites

- Python 3.8+ installed
- Mandiant Threat Intelligence API access and API key
- Claude Desktop application

## Installation

### Method 1: Quick Setup

1. **Clone or download the server file:**
   ```bash
   mkdir mandiant-mcp-server
   cd mandiant-mcp-server
   wget https://your-server-url/mandiant_mcp_server.py
   ```

2. **Create virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install mcp aiohttp python-dateutil pydantic
   ```

4. **Set up environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your Mandiant API key
   ```

5. **Test the server:**
   ```bash
   python mandiant_mcp_server.py
   ```

### Method 2: Package Installation

1. **Create the project structure:**
   ```bash
   mkdir mandiant-mcp-server
   cd mandiant-mcp-server
   ```

2. **Save the requirements.txt and pyproject.toml files**

3. **Install in development mode:**
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -e .
   ```

4. **Run the packaged server:**
   ```bash
   mandiant-mcp-server
   ```

## Configuration

### Environment Variables

Create a `.env` file in your project directory:

```env
MANDIANT_API_KEY=your_mandiant_api_key_here
MANDIANT_BASE_URL=https://api.intelligence.mandiant.com
MANDIANT_API_VERSION=v4
LOG_LEVEL=INFO
```

### Claude Desktop Integration

Edit your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/config.json`
**Windows**: `%APPDATA%/Claude/config.json`

```json
{
  "mcpServers": {
    "mandiant-threat-intel": {
      "command": "python",
      "args": ["/absolute/path/to/your/project/mandiant_mcp_server.py"],
      "env": {
        "MANDIANT_API_KEY": "your_api_key_here",
        "MANDIANT_BASE_URL": "https://api.intelligence.mandiant.com",
        "MANDIANT_API_VERSION": "v4"
      }
    }
  }
}
```

## Code Structure Explanation

### Main Components

**MandiantConfig Class (Lines 25-35)**
- Handles environment variable loading and validation
- Raises clear error if required API key is missing
- Provides default values for base URL and API version
- Centralizes all configuration management in one place

**MandiantMCPServer Class (Lines 38-45)**
- Main server class that orchestrates all functionality
- Initializes the MCP server with proper identification
- Sets up aiohttp session for efficient connection pooling
- Registers all tool handlers during initialization

**Tool Registration (_setup_handlers method, Lines 50-200)**
- Uses decorators (`@self.server.list_tools()` and `@self.server.call_tool()`) to register handlers
- Each tool definition includes comprehensive input schemas for validation
- The call_tool handler routes requests to appropriate private methods
- Implements proper error handling and returns formatted TextContent

**API Request Handler (_make_api_request method, Lines 220-260)**
- Centralizes all HTTP communication with Mandiant's API
- Implements proper authentication using Bearer token in Authorization header
- Builds URLs dynamically with query parameters
- Handles both HTTP errors and aiohttp client exceptions
- Uses connection pooling via aiohttp.ClientSession for performance

**Individual Tool Methods (Lines 265-500)**
- Each method corresponds to a specific Mandiant API endpoint
- `_search_indicators`: Handles IOC lookups with type filtering
- `_get_threat_reports`: Retrieves reports with date range and actor filtering
- `_get_threat_actors`: Gets APT group information with attribution data
- `_get_malware_families`: Provides malware analysis and capabilities
- `_get_campaigns`: Analyzes coordinated attack campaigns
- All methods format raw JSON responses into human-readable strings

**Date Handling**
- Uses `datetime.strptime()` to parse YYYY-MM-DD format dates
- Converts to Unix timestamps using `.timestamp()` for API compatibility
- Handles optional date parameters gracefully

**Error Handling Strategy**
- API errors return descriptive messages without exposing sensitive data
- HTTP client errors are caught and wrapped with context
- All exceptions are converted to user-friendly error messages
- Server continues running even if individual requests fail

**Resource Management**
- `cleanup()` method properly closes aiohttp session
- `async with` context manager ensures clean shutdown
- Uses `finally` block to guarantee resource cleanup

### Async Architecture Benefits

**Performance Advantages:**
- Non-blocking I/O operations allow handling multiple requests concurrently
- aiohttp session reuse reduces connection overhead
- Async/await pattern prevents blocking during API calls

**Scalability Features:**
- Can handle multiple Claude conversations simultaneously
- Connection pooling reduces latency for subsequent requests
- Proper resource cleanup prevents memory leaks

## Usage Examples

Once configured, you can use these commands in Claude:

### Indicator Analysis
```
Search Mandiant for the IP address 192.168.1.100
Check if the domain suspicious-site.com is known malicious
Look up the SHA256 hash a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef
Find any indicators related to this email address: attacker@evil.com
```

### Threat Intelligence Reporting
```
Get recent threat reports about APT29 from the last 60 days
Find reports mentioning Emotet malware family
Show me financial services targeting reports from 2024
Get threat reports published between 2024-01-01 and 2024-06-30
```

### Actor Attribution
```
Tell me about the Lazarus Group threat actor
Find APT groups with suspected North Korean attribution
Show me financially motivated threat actors active in 2024
Get information about threat actors targeting healthcare
```

### Malware Analysis
```
Get information about the Emotet malware family
Find ransomware families and their capabilities
Show me banking trojans that target Windows systems
Research backdoor malware families used by APT groups
```

### Campaign Intelligence
```
Find campaigns associated with APT28 in the last year
Show me recent campaigns targeting critical infrastructure
Get information about campaigns using spear-phishing tactics
Analyze campaigns attributed to Russian threat actors
```

## Advanced Usage

### Custom Filtering
You can combine multiple parameters for precise queries:

```
Get threat reports about ransomware targeting healthcare from APT groups between 2024-01-01 and 2024-12-31
Find IP indicators with high confidence scores from the last 30 days
Show me campaigns by financially motivated actors targeting financial services
```

### Development and Debugging

**Enable Debug Logging:**
```bash
export LOG_LEVEL=DEBUG
python mandiant_mcp_server.py
```

**Test Individual Methods:**
```python
# Create a test script
import asyncio
from mandiant_mcp_server import MandiantMCPServer

async def test_indicators():
    server = MandiantMCPServer()
    result = await server._search_indicators({"query": "8.8.8.8", "limit": 5})
    print(result)
    await server.cleanup()

asyncio.run(test_indicators())
```

**Monitor API Usage:**
- Check your Mandiant API dashboard for rate limit status
- Monitor response times and adjust timeout values if needed
- Review error logs for authentication or permission issues

## Security Best Practices

### API Key Protection
- Never commit `.env` files to version control
- Use environment variables in production deployments
- Rotate API keys regularly according to your security policy
- Consider using key management services for enterprise deployments

### Access Control
- Restrict file system permissions on the server script
- Use dedicated service accounts with minimal privileges
- Implement network-level access controls to Mandiant's API
- Log all API requests for audit purposes

### Data Handling
- Follow your organization's data classification policies
- Be aware that threat intelligence may contain sensitive information
- Implement appropriate data retention and disposal procedures
- Consider encrypting logs containing threat intelligence data

## Troubleshooting

### Common Issues and Solutions

**1. Authentication Errors**
```
Error: Mandiant API error (401): Unauthorized
```
- **Solution**: Verify your API key is correct and active
- Check that the key has appropriate permissions for the requested endpoints
- Ensure the API key hasn't expired

**2. Network Connectivity Issues**
```
HTTP request failed: Cannot connect to host
```
- **Solution**: Check network connectivity to api.intelligence.mandiant.com
- Verify firewall rules allow HTTPS traffic on port 443
- Test with curl: `curl -H "Authorization: Bearer YOUR_KEY" https://api.intelligence.mandiant.com/v4/indicators?limit=1`

**3. Claude Integration Problems**
```
Server not responding or tools not appearing
```
- **Solution**: Verify the absolute path in Claude Desktop config is correct
- Check that the Python script is executable
- Restart Claude Desktop after configuration changes
- Review Claude Desktop logs for error messages

**4. Rate Limiting**
```
Error: Mandiant API error (429): Rate limit exceeded
```
- **Solution**: Implement exponential backoff in your queries
- Check your API quota in the Mandiant portal
- Consider upgrading your API plan for higher limits

**5. Dependency Issues**
```
ModuleNotFoundError: No module named 'mcp'
```
- **Solution**: Ensure virtual environment is activated
- Reinstall dependencies: `pip install -r requirements.txt`
- Check Python version compatibility (3.8+ required)

### Performance Optimization

**Connection Pooling:**
The server uses aiohttp session pooling automatically, but you can tune it:

```python
# In _make_api_request method, customize connector
connector = aiohttp.TCPConnector(
    limit=100,  # Total connection pool size
    limit_per_host=30,  # Per-host connection limit
    ttl_dns_cache=300,  # DNS cache TTL
    use_dns_cache=True,
)
self.session = aiohttp.ClientSession(connector=connector)
```

**Caching Results:**
For frequently accessed data, consider implementing simple caching:

```python
import time
from functools import lru_cache

# Add to class
self.cache = {}
self.cache_ttl = 300  # 5 minutes

def _get_cached_or_fetch(self, cache_key, fetch_func, *args):
    if cache_key in self.cache:
        data, timestamp = self.cache[cache_key]
        if time.time() - timestamp < self.cache_ttl:
            return data
    
    result = await fetch_func(*args)
    self.cache[cache_key] = (result, time.time())
    return result
```

## API Reference

### Available Tools

| Tool Name | Parameters | Description |
|-----------|------------|-------------|
| `search_indicators` | `query` (required), `indicator_type`, `limit` | Search for IOCs in Mandiant database |
| `get_threat_reports` | `search_term`, `threat_actor`, `malware_family`, `start_date`, `end_date`, `limit` | Retrieve threat intelligence reports |
| `get_threat_actors` | `actor_name`, `motivation`, `country`, `limit` | Get APT group information |
| `get_malware_families` | `family_name`, `malware_type`, `limit` | Research malware families |
| `get_campaigns` | `campaign_name`, `threat_actor`, `start_date`, `end_date`, `limit` | Analyze threat campaigns |

### Parameter Details

**Indicator Types:**
- `ip`: IPv4 and IPv6 addresses
- `domain`: Domain names and subdomains
- `url`: Full URLs and URI paths
- `md5`: MD5 file hashes
- `sha1`: SHA1 file hashes
- `sha256`: SHA256 file hashes
- `email`: Email addresses

**Date Formats:**
- All dates should be in `YYYY-MM-DD` format
- Times are assumed to be UTC
- Date ranges are inclusive of start and end dates

**Motivations:**
- `financial`: Financially motivated attacks
- `espionage`: State-sponsored intelligence gathering
- `hacktivism`: Ideologically motivated attacks
- `unknown`: Motivation not determined

## Contributing

### Development Setup

1. **Fork and clone the repository**
2. **Set up development environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -e ".[dev]"
   ```

3. **Run tests:**
   ```bash
   pytest tests/
   ```

4. **Format code:**
   ```bash
   black mandiant_mcp_server.py
   flake8 mandiant_mcp_server.py
   ```

5. **Type checking:**
   ```bash
   mypy mandiant_mcp_server.py
   ```

### Adding New Features

When adding new tools or enhancing existing ones:

1. **Add the tool definition** to the `list_tools()` handler
2. **Implement the handler method** following the naming convention `_tool_name`
3. **Add the route** in the `call_tool()` handler
4. **Update documentation** with usage examples
5. **Add tests** for the new functionality

### Submitting Changes

1. Create a feature branch from main
2. Make your changes with appropriate tests
3. Ensure all tests pass and code is formatted
4. Submit a pull request with detailed description
5. Address any review feedback

## Resources

- [Mandiant Threat Intelligence API Documentation](https://docs.mandiant.com/home/threat-intelligence-api)
- [MCP SDK Documentation](https://modelcontextprotocol.io/docs)
- [aiohttp Documentation](https://docs.aiohttp.org/)
- [Claude Desktop MCP Guide](https://docs.anthropic.com/claude/docs/desktop-mcp)

## License

MIT License - see LICENSE file for details.

## Support

For issues related to:
- **MCP Server Code**: Create an issue in this repository
- **Mandiant API**: Contact Mandiant support or check their status page
- **Claude Integration**: Refer to Anthropic's MCP documentation
- **Python Dependencies**: Check the respective package documentation

---

*This server is designed for cybersecurity professionals and researchers. Use responsibly and in accordance with your organization's policies and applicable laws.*
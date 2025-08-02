#!/usr/bin/env python3

"""
Mandiant Threat Intelligence MCP Server (API v4)

Based on actual Mandiant API v4 documentation.
Uses Basic Authentication with API Key ID and Secret.

Required Environment Variables:
- MANDIANT_API_KEY_ID: Your Mandiant API Key ID  
- MANDIANT_API_SECRET: Your Mandiant API Secret
"""

import asyncio
import base64
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp
from mcp.server.fastmcp import FastMCP


class MandiantConfig:
    """Configuration class for Mandiant API credentials and settings"""
    
    def __init__(self):
        # Load configuration from environment variables
        self.api_key_id = os.getenv("MANDIANT_API_KEY_ID", "e72294d987598fd91927282ecdc1ea9de0dc64709a2247ed73cfe0bbab188477")
        self.api_secret = os.getenv("MANDIANT_API_SECRET", "69c70d2e4b00b370f791bb3e323e485871460195f507a2f6fb96ffa16f7e9c95")
        self.base_url = os.getenv("MANDIANT_BASE_URL", "https://api.intelligence.mandiant.com/v4")
        self.version = os.getenv("MANDIANT_API_VERSION", "v4")
        
        # Validate required configuration
        if not self.api_key_id or not self.api_secret:
            raise ValueError("Both MANDIANT_API_KEY_ID and MANDIANT_API_SECRET environment variables are required")
        
        # Create basic auth header
        credentials = f"{self.api_key_id}:{self.api_secret}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        self.auth_header = f"Basic {encoded_credentials}"


# Initialize configuration
config = MandiantConfig()

# Create FastMCP server instance
mcp = FastMCP("mandiant-threat-intel")

# Global HTTP session for connection pooling
http_session: Optional[aiohttp.ClientSession] = None


async def get_http_session() -> aiohttp.ClientSession:
    """Get or create HTTP session for API requests"""
    global http_session
    if http_session is None:
        http_session = aiohttp.ClientSession()
    return http_session


async def make_api_request(endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Make authenticated HTTP requests to the Mandiant API v4
    
    Args:
        endpoint: API endpoint path (e.g., 'indicator')
        params: Query parameters to include in the request
        
    Returns:
        JSON response data from the API
        
    Raises:
        Exception: If API request fails or returns error
    """
    
    if params is None:
        params = {}
    
    # Build the full URL - base_url now includes v4
    url = f"{config.base_url}/{endpoint}"
    
    # Set up authentication headers for Mandiant API v4
    headers = {
        'Authorization': config.auth_header,  # Basic auth with Key ID:Secret
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'X-App-Name': 'mcp-mandiant-server'  # Required by Mandiant API
    }
    
    # Get HTTP session
    session = await get_http_session()
    
    try:
        # Make the HTTP GET request
        async with session.get(url, headers=headers, params=params) as response:
            # Check for HTTP errors
            if response.status == 401:
                raise Exception("Authentication failed - check your Mandiant API Key ID and Secret")
            elif response.status == 403:
                raise Exception("Access forbidden - check your Mandiant subscription permissions")
            elif response.status == 429:
                raise Exception("Rate limit exceeded - please wait before making more requests")
            elif response.status == 404:
                raise Exception("Resource not found - check the endpoint or identifier")
            elif response.status != 200:
                error_text = await response.text()
                raise Exception(f"Mandiant API error ({response.status}): {error_text}")
            
            # Parse and return JSON response
            return await response.json()
            
    except aiohttp.ClientError as e:
        raise Exception(f"HTTP request failed: {str(e)}")


@mcp.tool()
async def search_indicators(
    value: str,
    limit: int = 10
) -> str:
    """
    Search for threat indicators in Mandiant's database
    
    Args:
        value: The indicator value to search for (IP, domain, hash, etc.)
        limit: Maximum number of results to return (default: 10)
    
    Returns:
        Formatted string with indicator search results
    """
    
    try:
        # Use the correct v4 endpoint for indicator lookup
        endpoint = f"indicator/{value}"
        data = await make_api_request(endpoint)
        
        # Handle API error responses
        if "error" in data:
            return f"No threat intelligence found for {value}: {data['error']}"
        
        # Format response for display
        result = f"Mandiant Threat Intelligence for: {value}\n\n"
        
        # Handle different response structures
        if "mscore" in data:
            result += f"Mandiant Score: {data.get('mscore', 'N/A')}\n"
        
        if "first_seen" in data:
            result += f"First Seen: {data.get('first_seen', 'N/A')}\n"
        
        if "last_seen" in data:
            result += f"Last Seen: {data.get('last_seen', 'N/A')}\n"
        
        if "sources" in data and data["sources"]:
            result += f"Sources: {len(data['sources'])} source(s)\n"
            for source in data["sources"][:3]:  # Show first 3 sources
                result += f"  - {source.get('source_name', 'Unknown')}\n"
        
        if "attributed_associations" in data and data["attributed_associations"]:
            result += f"\nAssociated Threats:\n"
            for assoc in data["attributed_associations"][:5]:  # Limit to 5
                result += f"  - {assoc.get('name', 'Unknown')} ({assoc.get('type', 'Unknown')})\n"
        
        return result
        
    except Exception as e:
        return f"Error searching indicators: {str(e)}"


@mcp.tool()
async def get_threat_actors(
    name: Optional[str] = None,
    limit: int = 10
) -> str:
    """
    Get information about threat actors and APT groups
    
    Args:
        name: Specific threat actor name to search for (optional)
        limit: Maximum number of results to return (default: 10)
    
    Returns:
        Formatted string with threat actor information
    """
    
    try:
        # Build API parameters
        params = {"limit": limit}
        
        if name:
            # Search for specific threat actor
            endpoint = f"actor"
            params["q"] = name
        else:
            # Get list of actors
            endpoint = "actor"
        
        data = await make_api_request(endpoint, params)
        
        # Handle API error responses
        if "error" in data:
            search_term = name if name else "threat actors"
            return f"No threat actors found for {search_term}: {data['error']}"
        
        # Handle response structure
        actors = data.get("objects", []) if "objects" in data else [data] if data else []
        
        if not actors:
            search_term = name if name else "actors"
            return f"No threat actors found for: {search_term}"
        
        result = f"Found {len(actors)} threat actor(s)\n\n"
        
        for i, actor in enumerate(actors[:limit], 1):
            if isinstance(actor, dict):
                actor_name = actor.get("name", "Unknown Actor")
                result += f"{i}. {actor_name}\n"
                
                if "aliases" in actor and actor["aliases"]:
                    result += f"   Aliases: {', '.join(actor['aliases'][:3])}\n"
                
                if "description" in actor:
                    desc = actor["description"][:200] + "..." if len(actor["description"]) > 200 else actor["description"]
                    result += f"   Description: {desc}\n"
                
                result += "\n"
        
        return result
        
    except Exception as e:
        return f"Error retrieving threat actors: {str(e)}"


@mcp.tool()
async def get_malware_families(
    name: Optional[str] = None,
    limit: int = 10
) -> str:
    """
    Get information about malware families and their characteristics
    
    Args:
        name: Specific malware family name to search for (optional)
        limit: Maximum number of results to return (default: 10)
    
    Returns:
        Formatted string with malware family information
    """
    
    try:
        # Build API parameters
        params = {"limit": limit}
        
        if name:
            endpoint = "malware"
            params["q"] = name
        else:
            endpoint = "malware"
        
        data = await make_api_request(endpoint, params)
        
        # Handle API error responses
        if "error" in data:
            search_term = name if name else "malware families"
            return f"No malware families found for {search_term}: {data['error']}"
        
        # Handle response structure
        malware_families = data.get("objects", []) if "objects" in data else [data] if data else []
        
        if not malware_families:
            search_term = name if name else "malware families"
            return f"No malware families found for: {search_term}"
        
        result = f"Found {len(malware_families)} malware famil(y/ies)\n\n"
        
        for i, family in enumerate(malware_families[:limit], 1):
            if isinstance(family, dict):
                family_name = family.get("name", "Unknown Family")
                result += f"{i}. {family_name}\n"
                
                if "aliases" in family and family["aliases"]:
                    result += f"   Aliases: {', '.join(family['aliases'][:3])}\n"
                
                if "malware_types" in family and family["malware_types"]:
                    result += f"   Types: {', '.join(family['malware_types'])}\n"
                
                if "description" in family:
                    desc = family["description"][:200] + "..." if len(family["description"]) > 200 else family["description"]
                    result += f"   Description: {desc}\n"
                
                result += "\n"
        
        return result
        
    except Exception as e:
        return f"Error retrieving malware families: {str(e)}"


@mcp.tool()
async def get_vulnerability_intelligence(
    cve_id: str
) -> str:
    """
    Get Mandiant vulnerability intelligence for a specific CVE
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2024-1234)
    
    Returns:
        Formatted string with vulnerability intelligence
    """
    
    try:
        # Use the vulnerability endpoint
        endpoint = f"vulnerability/{cve_id}"
        data = await make_api_request(endpoint)
        
        # Handle API error responses
        if "error" in data:
            return f"No vulnerability intelligence found for {cve_id}: {data['error']}"
        
        if not data:
            return f"No Mandiant intelligence found for {cve_id}"
        
        result = f"Mandiant Vulnerability Intelligence for {cve_id}\n\n"
        
        if "risk_rating" in data:
            result += f"Risk Rating: {data['risk_rating']}\n"
        
        if "exploitation_consequence" in data:
            result += f"Exploitation Consequence: {data['exploitation_consequence']}\n"
        
        if "exploitation_state" in data:
            result += f"Exploitation State: {data['exploitation_state']}\n"
        
        if "description" in data:
            desc = data["description"][:400] + "..." if len(data["description"]) > 400 else data["description"]
            result += f"\nDescription: {desc}\n"
        
        if "associated_actors" in data and data["associated_actors"]:
            result += f"\nAssociated Threat Actors:\n"
            for actor in data["associated_actors"][:5]:
                result += f"  - {actor.get('name', 'Unknown')}\n"
        
        if "associated_malware" in data and data["associated_malware"]:
            result += f"\nAssociated Malware:\n"
            for malware in data["associated_malware"][:5]:
                result += f"  - {malware.get('name', 'Unknown')}\n"
        
        return result
        
    except Exception as e:
        return f"Error retrieving vulnerability intelligence: {str(e)}"


@mcp.tool()
async def search_reports(
    query: Optional[str] = None,
    limit: int = 5
) -> str:
    """
    Search Mandiant threat intelligence reports
    
    Args:
        query: Search term for reports (optional)
        limit: Maximum number of results to return (default: 5)
    
    Returns:
        Formatted string with report information
    """
    
    try:
        # Build API parameters
        params = {"limit": limit}
        
        if query:
            params["q"] = query
        
        endpoint = "report"
        data = await make_api_request(endpoint, params)
        
        # Handle API error responses
        if "error" in data:
            search_term = query if query else "recent reports"
            return f"No reports found for {search_term}: {data['error']}"
        
        # Handle response structure
        reports = data.get("objects", []) if "objects" in data else []
        
        if not reports:
            search_term = query if query else "recent reports"
            return f"No reports found for: {search_term}"
        
        result = f"Found {len(reports)} report(s)\n\n"
        
        for i, report in enumerate(reports[:limit], 1):
            if isinstance(report, dict):
                title = report.get("title", "Untitled Report")
                result += f"{i}. {title}\n"
                
                if "published_date" in report:
                    result += f"   Published: {report['published_date']}\n"
                
                if "report_type" in report:
                    result += f"   Type: {report['report_type']}\n"
                
                if "executive_summary" in report:
                    summary = report["executive_summary"][:200] + "..." if len(report["executive_summary"]) > 200 else report["executive_summary"]
                    result += f"   Summary: {summary}\n"
                
                result += "\n"
        
        return result
        
    except Exception as e:
        return f"Error searching reports: {str(e)}"


async def cleanup():
    """Clean up HTTP session on shutdown"""
    global http_session
    if http_session:
        await http_session.close()
        http_session = None


if __name__ == "__main__":
    try:
        # Log startup message to stderr (won't interfere with MCP protocol)
        print("Mandiant Threat Intelligence MCP Server starting...", file=sys.stderr)
        print(f"Base URL: {config.base_url}", file=sys.stderr)
        print(f"API Key ID configured: {'Yes' if config.api_key_id else 'No'}", file=sys.stderr)
        
        # Run the MCP server
        mcp.run()
        
    except KeyboardInterrupt:
        print("Server shutting down...", file=sys.stderr)
        
    except Exception as e:
        print(f"Server error: {e}", file=sys.stderr)
        sys.exit(1)
        
    finally:
        # Clean up resources
        if http_session:
            asyncio.run(cleanup())

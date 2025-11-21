# **Model Context Protocol (MCP) Authorization Flow (RFC 7591 & RFC 9728 Integration)**

This document describes the required, end-to-end authorization flow for an MCP Client connecting to a protected MCP Server, integrating the OAuth 2.0 Protected Resource Metadata (RFC 9728\) and Dynamic Client Registration (RFC 7591\) standards as mandated by the MCP specification.

## **1\. Initial Discovery and Protected Resource Metadata (PRM)**

This phase allows the client to discover that authorization is required and where to find the Authorization Server (AS).

### **Step 1.1: MCP Client Initiates Communication**

The MCP Client attempts to execute an operation (e.g., initialize) without a token against a specific MCP endpoint.

* **Client Action:** HTTP request to the MCP Server Protected Resource (e.g., https://api.example.com/public/mcp).

### **Step 1.2: MCP Server Challenges (HTTP 401\)**

The MCP Server rejects the request due to missing authorization, initiating the discovery process.

* **Server Action:** Returns HTTP 401 Unauthorized.  
* **Response Header:** Includes the WWW-Authenticate header.  
  * **Crucial Parameter:** resource-metadata parameter contains the URI for the Protected Resource Metadata (PRM) document. The Server MAY also suggest a scope in this header.

### **Step 1.3: Client Determines URI and Fetches Protected Resource Metadata (PRM)**

The Client first attempts to retrieve the PRM document using the URI provided in the resource-metadata parameter from Step 1.2. If the resource-metadata parameter is **not included** in the WWW-Authenticate header, the Client **MUST** fall back to constructing and requesting the PRM document via one of the following well-known URI paths, in the specified order.

* **Client Action:**  
  1. Determine URI: Prioritize resource-metadata value.  
  2. **Fallback Logic (MUST be attempted in order):**  
     * **Note:** While the *Resource URI* (Step 4.1) includes the path (e.g., /public/mcp), the MCP specification mandates that for **discovery**, the client usually determines the base URL by discarding the path component, unless the server implementation specifically hosts metadata at the resource path.  
     * **Path A (Standard PRM, RFC 9728):** \[MCP Server Host\]/.well-known/oauth-protected-resource (Primary discovery path).  
     * **Path B (OAuth AS Metadata, RFC 8414):** \[MCP Server Host\]/.well-known/oauth-authorization-server (Fallback path to discover the AS, which may host the PRM).  
     * **Path C (Root Host Discovery):** \[MCP Server Host\] (Final fallback to the root of the server host).  
  3. HTTP GET request to the first successful determined PRM URI.  
* **Information Extracted:**  
  * authorization\_servers: URL(s) of the Authorization Server(s).  
  * scopes\_supported: List of scopes relevant to this MCP Server.

## **2\. Authorization Server (AS) Discovery**

The Client determines the capabilities and endpoints of the selected Authorization Server.

### **Step 2.1: Client Fetches AS Metadata**

The Client selects an Authorization Server URL and performs a discovery request (e.g., using RFC 8414).

* **Client Action:** HTTP GET request to the Authorization Server's well-known metadata endpoint (e.g., /.well-known/oauth-authorization-server).  
* **Information Extracted:**  
  * registration\_endpoint: The URI for the Dynamic Client Registration (DCR) endpoint.  
  * authorization\_endpoint: The URI for the OAuth authorization request.  
  * token\_endpoint: The URI for the token exchange request.  
  * scopes\_supported: List of scopes supported by the Authorization Server.

## **3\. Dynamic Client Registration (DCR)**

If the client is not pre-registered, it uses the DCR endpoint to obtain a client\_id and client configuration.

### **Step 3.1: Client Submits DCR Request (RFC 7591\)**

The Client sends a registration request to the registration\_endpoint extracted in Step 2.1.

* **Client Action:** HTTP POST request to the registration\_endpoint.  
* **Required Request Body Parameters:**  
  * client\_name: A human-readable name for the client.  
  * redirect\_uris: One or more https URIs where the authorization response will be sent.  
  * grant\_types: MUST include "authorization\_code".  
  * response\_types: MUST include "code".  
  * token\_endpoint\_auth\_method: Typically "none" for public clients using PKCE.

### **Step 3.2: AS Returns Client Credentials**

The Authorization Server successfully registers the client and returns the necessary credentials.

* **Server Action:** Returns HTTP 201 Created.  
* **Response Body Parameters:**  
  * client\_id: **REQUIRED.** The unique identifier for the MCP Client.  
  * client\_secret (OPTIONAL, but typically omitted for public MCP clients).  
  * registration\_access\_token (OPTIONAL).

## **4\. Token Acquisition (OAuth 2.1 with PKCE)**

The Client uses its new client\_id to acquire an access token for the MCP Server.

### **Step 4.1: Client Initiates Authorization Request (PKCE)**

The Client constructs an authorization request, including Proof Key for Code Exchange (PKCE) parameters.

* **Client Action:** Redirects the user's browser (or opens a UI component) to the authorization\_endpoint.  
* **Required Query Parameters:**  
  * client\_id: The ID obtained in Step 3.2.  
  * response\_type: "code".  
  * scope: Scopes required for the operation, following the MCP Scope Selection Strategy (prioritizing the scope from Step 1.2, then PRM).  
  * redirect\_uri: One of the registered URIs from Step 3.1.  
  * code\_challenge, code\_challenge\_method: PKCE parameters.  
  * resource: **REQUIRED.** MUST identify the MCP Server's canonical URI (RFC 8707).  
    * *Example:* https://api.example.com/public/mcp (Note: Must include the full path to the resource).

### **Step 4.2: User Consent and Code Grant**

The Authorization Server handles user interaction (login, consent) and grants an authorization code.

* **AS Action:** Redirects the user's browser back to the redirect\_uri with the authorization code.  
* **Query Parameters:** code (the authorization code).

### **Step 4.3: Client Exchanges Code for Token**

The Client performs a backend request to the Authorization Server's token endpoint.

* **Client Action:** HTTP POST request to the token\_endpoint.  
* **Required Request Body Parameters:**  
  * grant\_type: "authorization\_code".  
  * client\_id: The client ID.  
  * code: The code received in Step 4.2.  
  * redirect\_uri: The same URI used in Step 4.1.  
  * code\_verifier: The PKCE verifier corresponding to the challenge in Step 4.1.  
  * resource: **REQUIRED.** MUST be included and match the value from Step 4.1 (e.g., https://api.example.com/public/mcp).

### **Step 4.4: AS Issues Access Token**

The Authorization Server validates the code and PKCE parameters and issues the token.

* **AS Action:** Returns HTTP 200 OK.  
* **Response Body:** Includes access\_token, token\_type (Bearer), and usually expires\_in.

## **5\. Protected Resource Access**

The Client now uses the acquired token to successfully communicate with the MCP Server.

### **Step 5.1: Client Retries Initial Command**

The Client sends the original initialize command (or subsequent operation) with the new token.

* **Client Action:** HTTP request to the MCP Server (e.g., https://api.example.com/public/mcp).  
* **Request Header:** Authorization: Bearer \<access-token\>.

### **Step 5.2: MCP Server Validates and Responds**

The MCP Server validates the token (ensuring it contains the correct audience/resource claim for itself) and processes the request.

* **Server Action:** Returns HTTP 200 OK and proceeds with the MCP operation.

*Status: Complete authorization flow detailing DCR and OAuth 2.1 integration, with explicit public/mcp resource URI examples.*
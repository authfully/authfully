/**
 * A very simple OAuth 2.0 client application
 */
class Client {
    constructor({
        name = "Client",
        version = "1.0.0",
        description = "A simple client application",
        authEndpoint = "",
        clientId = "",
        clientSecret = "",
        redirectUri = "",
        scope = "",
        grantType = "authorization_code",
        state = "",
    }) {
        this.name = "Client";
        this.version = version;
        this.description = description;
        this.authEndpoint = authEndpoint;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.grantType = grantType;
        this.state = state;
    }
    
    login() {
        // Redirect to the authorization endpoint
        const authQuery = new URLSearchParams({
            response_type: "code",
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            scope: this.scope,
            state: this.state,
        });
        const authUrl = `${this.authEndpoint}?${authQuery.toString()}`;
        window.location.href = authUrl;
    }
}

export default Client;
export { Client };

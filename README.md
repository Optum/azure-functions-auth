# azure-functions-auth

An easy way to wrap Azure Functions in automatic OAuth2 JWT authorization!

This library will wrap any javascript/typescript Azure Function implementation and automatically provide access to 
the JwtToken that was included on the request.  If the auth requirements weren't met, 401/403 responses are 
automatically sent back.

Examples:
# Require a JWT token with no role requirements

```typescript
import { requireAuthorization, AuthenticatedContext } from "@optum/azure-functions-auth"

const httpTrigger: AzureFunction = requireAuthorization(async (context: AuthenticatedContext, req: HttpRequest): Promise<void> => {
    context.log("Received request from subject", context.jwtToken.sub)
}, {
    jwksEndpoint: process.env.JWKS_ENDPOINT,        // configurable based on your OAuth2 provider
    requiredIssuer: process.env.REQUIRED_ISSUER,    // configurable based on your OAuth2 provider
    requiredAud: process.env.REQUIRED_AUD           // the specific audiance value for your service
})

export default httpTrigger
```

# Require a JWT token with additional role requirements

```typescript
import { requireAuthorization, AuthenticatedContext } from "@optum/azure-functions-auth"

const httpTrigger: AzureFunction = requireAuthorization(async (context: AuthenticatedContext, req: HttpRequest, token: JwtToken): Promise<void> => {
    context.log("Received request from subject", context.jwtToken.sub)
}, {
    jwksEndpoint: process.env.JWKS_ENDPOINT,        // configurable based on your OAuth2 provider
    requiredIssuer: process.env.REQUIRED_ISSUER,    // configurable based on your OAuth2 provider
    requiredAud: process.env.REQUIRED_AUD,          // the specific audiance value for your service
    requiredRole: "MY_FUNCTION_ROLE"                // the role guarding access to this specific function endpoint
})

export default httpTrigger
```

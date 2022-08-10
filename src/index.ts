import { AzureFunction, Context, HttpRequest, Logger } from "@azure/functions"
import { TelemetryClient } from "applicationinsights"
import { createRemoteJWKSet, jwtVerify } from "jose"
import {
    AuthenticatedContext,
    AuthorizeOptions,
    InvalidHeaderFormatError,
    InvalidTokenError,
    MissingHeaderError,
    TokenValidationError,
    TokenValidationOptions,
    TokenValidationResponse
} from "./types"

export * from "./types"

export function requireAuthorization(
    f: AzureFunction,
    options: AuthorizeOptions,
): AzureFunction {
    return async (context: Context, req: HttpRequest, ...bindings: any[]): Promise<void> => {
        const {appInsightsClient, requiredRole} = options
        const {validateTokenFromHeader} = generateHelpers(context, appInsightsClient)
        try {
            const authHeader = req.headers.authorization;

            const validationOptions = {
                logger: context.log,
                ...options,
            };
            context.log.info(`setting up authorize handler with options: ${validationOptions}`);
            const {token} = await validateTokenFromHeader(authHeader, validationOptions);
            const authContext: AuthenticatedContext = context as AuthenticatedContext
            authContext.jwtToken = token

            if (requiredRole) {
                context.log.info(`checking for required role: ${requiredRole}`);
                const roles: string[] = token.roles as string[] ?? [];

                // The next line is calculated wrong in branch coverage, so I'm ignoring it
                /* istanbul ignore next */
                if (!roles.includes(requiredRole)) {
                    context.log.error(`token is missing required role, ${requiredRole}`);
                    context.res = {
                        status: 403,
                        body: {
                            reason: 'Token does not contain required role',
                        },
                    };
                    return;
                }
            }

            const bindingArgs = ([req] as any[]).concat(bindings).concat([token])
            const args: [Context, ...any[]] = ([authContext].concat(bindingArgs) as [Context, ...any[]]);
            await f.apply(null, args);
        } catch (e) {
            context.log.error(`encountered error: ${JSON.stringify(e)}`);
            if (e instanceof TokenValidationError) {
                context.res = {
                    status: 401,
                    body: {
                        reason: e.message,
                    },
                };
                context.done();
                return;
            } else {
                throw e;
            }
        }
    };
}

function generateHelpers(context: Context, appInsightsClient?: TelemetryClient) {
    const overrides = {"ai.operation.id": context.traceContext.traceparent as string}
    const getJwtFromHeader = (authHeader: string | undefined, logger: Logger) => {
        if (authHeader === undefined || authHeader.length === 0) {
            logger.error('Header is null or empty');
            appInsightsClient?.trackMetric({
                name: `${context.executionContext.functionName} - Authorization Failure - Header is null or empty`,
                value: 1,
                tagOverrides: overrides
            })
            throw new MissingHeaderError('Header is null or empty');
        }

        const authHeaderParts = authHeader.split(' ');
        if (authHeaderParts.length !== 2 || authHeaderParts[0] !== 'Bearer') {
            logger.error('Header is not in the correct format.  Expecting Bearer token');
            appInsightsClient?.trackMetric({
                name: `${context.executionContext.functionName} - Authorization Failure - Bad Header Format`,
                value: 1,
                tagOverrides: overrides
            })
            throw new InvalidHeaderFormatError('Header is not in the correct format.  Expecting Bearer token');
        }

        return authHeaderParts[1];
    }
    return {
        validateTokenFromHeader: async (
            authHeader: string | undefined,
            options: TokenValidationOptions,
        ): Promise<TokenValidationResponse> => {
            const jwks = createRemoteJWKSet(new URL(options.jwksEndpoint));

            try {
                const jwt = getJwtFromHeader(authHeader, options.logger);
                const validationResponse = await jwtVerify(jwt, jwks, {
                    issuer: options.requiredIssuer,
                    audience: options.requiredAud
                });
                appInsightsClient?.trackMetric({
                    name: `${context.executionContext.functionName} - Authorization Success`,
                    value: 1,
                    tagOverrides: overrides
                })

                options.logger.info('Verified token successfully');

                return {
                    token: validationResponse.payload,
                };
            } catch (e) {
                options.logger.error(`encountered error validating token: ${JSON.stringify(e)}`);
                appInsightsClient?.trackMetric({
                    name: `${context.executionContext.functionName} - Authorization Failure - Internal Error`,
                    value: 1,
                    tagOverrides: overrides
                })
                throw new InvalidTokenError(e.message);
            }
        }
    }
}
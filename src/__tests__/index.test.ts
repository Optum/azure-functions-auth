// tslint:disable:no-shadowed-variable
// tslint:disable:no-empty

import { AuthorizeOptions, TokenValidationError } from '../types';

import { requireAuthorization } from '../index';
import { Context, HttpRequest, Logger } from '@azure/functions';
import { mock } from 'jest-mock-extended';
import { jwtVerify, createRemoteJWKSet } from 'jose';

describe("azure-function-auth tests", () => {
  beforeEach(() => {
    jest.clearAllMocks()
  });

    it('authorize - Valid token calls handler once', async () => {
        const handler = jest.fn(async (context: Context, req: HttpRequest, token: string) => {});
        const options: AuthorizeOptions = {jwksEndpoint: "https://mock.optum.com", requiredIssuer: "", requiredAud: 'aud' };

        const wrapperHandler = requireAuthorization(handler, options);

        const request: HttpRequest = mock<HttpRequest>();
        request.headers = {
            authorization: 'Bearer Token',
        };

        const context: Context = mock<Context>();

        context.log = mock<Logger>();

        (createRemoteJWKSet as jest.Mock).mockReturnValue({});

        (jwtVerify as jest.Mock).mockReturnValue(Promise.resolve({}));

        await wrapperHandler(context, request);

        expect(handler).toBeCalled();
    });

  it('authorize - Missing role returns 403', async () => {
    const handler = jest.fn(async (context: Context, req: HttpRequest, token: string) => {});
    const options: AuthorizeOptions = {jwksEndpoint: "https://mock.optum.com", requiredIssuer: "", requiredAud: 'aud', requiredRole: 'role' };

    const wrapperHandler = requireAuthorization(handler, options);

    const request: HttpRequest = mock<HttpRequest>();
    request.headers = {
      authorization: 'Bearer Token',
    };

    const context: Context = mock<Context>();

    context.log = mock<Logger>();

    (createRemoteJWKSet as jest.Mock).mockReturnValue({});

    (jwtVerify as jest.Mock).mockReturnValue(
        Promise.resolve({
          payload: {
            roles: ['something else'],
          },
        }),
    );

    await wrapperHandler(context, request);

    expect(context.res?.status).toBe(403);
    expect(context.res?.body.reason).toBe('Token does not contain required role');
  });

 it('authorize - Undefined role returns 403', async () => {
    const handler = jest.fn(async (context: Context, req: HttpRequest, token: string) => {});
    const options: AuthorizeOptions = {jwksEndpoint: "https://mock.optum.com", requiredIssuer: "", requiredAud: 'aud', requiredRole: 'role' };

    const wrapperHandler = requireAuthorization(handler, options);

    const request: HttpRequest = mock<HttpRequest>();
    request.headers = {
      authorization: 'Bearer Token',
    };

    const context: Context = mock<Context>();

    context.log = mock<Logger>();

    (createRemoteJWKSet as jest.Mock).mockReturnValue({});

    (jwtVerify as jest.Mock).mockReturnValue(
        Promise.resolve({
          payload: {
          },
        }),
    );

    await wrapperHandler(context, request);

    expect(context.res?.status).toBe(403);
    expect(context.res?.body.reason).toBe('Token does not contain required role');
  });

  it('authorize - Undefined roles returns 403', async () => {
    const handler = jest.fn(async (context: Context, req: HttpRequest, token: string) => {});
    const options: AuthorizeOptions = {jwksEndpoint: "https://mock.optum.com", requiredIssuer: "", requiredAud: 'aud', requiredRole: 'role' };

    const wrapperHandler = requireAuthorization(handler, options);

    const request: HttpRequest = mock<HttpRequest>();
    request.headers = {
      authorization: 'Bearer Token',
    };

    const context: Context = mock<Context>();

    context.log = mock<Logger>();

    (createRemoteJWKSet as jest.Mock).mockReturnValue({});

    (jwtVerify as jest.Mock).mockReturnValue(
        Promise.resolve({
          payload: {},
          roles: undefined,
        }),
    );

    await wrapperHandler(context, request);

    expect(context.res?.status).toBe(403);
    expect(context.res?.body.reason).toBe('Token does not contain required role');
  });

  it('authorize - Invalid token returns 401', async () => {
    const handler = async (context: Context): Promise<void> => {};
    const options: AuthorizeOptions = {jwksEndpoint: "https://mock.optum.com", requiredIssuer: "", requiredAud: 'aud', requiredRole: 'role' };

    const wrapperHandler = requireAuthorization(handler, options);

    const request: HttpRequest = mock<HttpRequest>();
    request.headers = {
      authorization: 'Bearer Token',
    };

    const context: Context = mock<Context>();

    context.log = mock<Logger>();

    (jwtVerify as jest.Mock).mockImplementation(() => {
      throw new TokenValidationError('Bad Token');
    });

    await wrapperHandler(context, request);

    expect(context.res?.status).toBe(401);
    expect(context.res?.body.reason).toBe('Bad Token');
  });

  it('authorize - Empty header returns 401', async () => {
    const handler = async (context: Context): Promise<void> => {};
    const options: AuthorizeOptions = {jwksEndpoint: "https://mock.optum.com", requiredIssuer: "", requiredAud: 'aud', requiredRole: 'role' };

    const wrapperHandler = requireAuthorization(handler, options);

    const request: HttpRequest = mock<HttpRequest>();
    request.headers = {
      authorization: '',
    };

    const context: Context = mock<Context>();

    context.log = mock<Logger>();

    await wrapperHandler(context, request);

    expect(context.res?.status).toBe(401);
    expect(context.res?.body.reason).toBe('Header is null or empty');
  });

  it('authorize - Non-Bearer header returns 401', async () => {
    const handler = async (context: Context): Promise<void> => {};
    const options: AuthorizeOptions = {jwksEndpoint: "https://mock.optum.com", requiredIssuer: "", requiredAud: 'aud', requiredRole: 'role' };

    const wrapperHandler = requireAuthorization(handler, options);

    const request: HttpRequest = mock<HttpRequest>();
    request.headers = {
      authorization: 'NotBarer 123',
    };

    const context: Context = mock<Context>();

    context.log = mock<Logger>();

    await wrapperHandler(context, request);

    expect(context.res?.status).toBe(401);
    expect(context.res?.body.reason).toBe('Header is not in the correct format.  Expecting Bearer token');
  });

  it('authorize - undefined header returns 401', async () => {
    const handler = async (context: Context): Promise<void> => {};
    const options: AuthorizeOptions = {jwksEndpoint: "https://mock.optum.com", requiredIssuer: "", requiredAud: 'aud', requiredRole: 'role' };

    const wrapperHandler = requireAuthorization(handler, options);

    const request: HttpRequest = mock<HttpRequest>();
    request.headers = {
    };

    const context: Context = mock<Context>();

    context.log = mock<Logger>();

    await wrapperHandler(context, request);

    expect(context.res?.status).toBe(401);
    expect(context.res?.body.reason).toBe('Header is null or empty');
  });

  it('authorize - JWKS error throws error', async () => {
    const handler = async (context: Context): Promise<void> => {};
    const options: AuthorizeOptions = {jwksEndpoint: "https://mock.optum.com", requiredIssuer: "", requiredAud: 'aud', requiredRole: 'role' };

    const wrapperHandler = requireAuthorization(handler, options);

    const request: HttpRequest = mock<HttpRequest>();
    request.headers = {
      authorization: 'Bearer Token',
    };

    const context: Context = mock<Context>();

    context.log = mock<Logger>();

    const error = new Error('Bad JWKS');
    (createRemoteJWKSet as jest.Mock).mockImplementation(() => {
      throw error;
    });

    await expect(wrapperHandler(context, request)).rejects.toEqual(error);
  });
})

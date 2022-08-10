import { Context, Logger } from "@azure/functions"
import { TelemetryClient } from "applicationinsights"

export interface JwtToken {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  jti?: string;
  nbf?: number;
  exp?: number;
  iat?: number;
  [propName: string]: unknown;
}

export interface AuthenticatedContext extends Context {
  jwtToken: JwtToken
}

export interface TokenValidationResponse {
  token: JwtToken;
}

export interface TokenValidationOptions {
  logger: Logger;
  jwksEndpoint: string;
  requiredIssuer: string;
  requiredAud: string;
}

export interface AuthorizeOptions {
  jwksEndpoint: string;
  requiredIssuer: string;
  requiredAud: string;
  requiredRole?: string;
  appInsightsClient?: TelemetryClient
}

export class TokenValidationError extends Error {
  constructor(public message: string) {
    super(message);

    Object.setPrototypeOf(this, TokenValidationError.prototype);
  }
}

export class InvalidHeaderFormatError extends TokenValidationError {
  constructor(public message: string) {
    super(message);
    this.name = 'InvalidHeaderFormatError';
    Object.setPrototypeOf(this, InvalidHeaderFormatError.prototype);
  }
}

export class MissingHeaderError extends TokenValidationError {
  constructor(public message: string) {
    super(message);
    this.name = 'MissingHeaderError';
    Object.setPrototypeOf(this, MissingHeaderError.prototype);
  }
}

export class InvalidTokenError extends TokenValidationError {
  constructor(public message: string) {
    super(message);
    this.name = 'InvalidTokenError';
    Object.setPrototypeOf(this, InvalidTokenError.prototype);
  }
}

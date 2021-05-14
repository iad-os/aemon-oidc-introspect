import crypto from 'crypto';
import { Request, RequestHandler } from 'express';
import httpStatus from 'http-status';
import jwt from 'jws';
import reduce from 'lodash.reduce';
import LRUCache from 'lru-cache';
import query from 'query-string';

export type Identity = {
  subject: string;
  issuer: string;
  email: string;
  familyName: string;
  givenName: string;
  emailVerified: boolean;
  token: string;
  roles: string[];
  allRoles: string[];
  audience: string;
  expires: number;
  issuedAt: number;
  active: boolean;
  clientId: string;
};

export type TokenData = {
  active: string;
  aud: string;
  iss: string;
  sub: string;
  email: string;
  email_verified: string;
  realm_access: string;
  resource_access: string;
  exp: string;
  iat: string;
  clientId: string;
  family_name: string;
  given_name: string;
};

export type doPostHandler = (
  req: Request,
  url: string,
  queryString: string,
  options?: {
    headers: Record<string, string>;
  }
) => Promise<{ data: TokenData }>;

export type loggerHandler = (
  req: Request,
  level: 'info' | 'debug' | 'error' | 'trace' | 'warn',
  msg: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  payload?: any
) => void;

declare module 'http' {
  interface IncomingMessage {
    uid: Identity;
  }
}

export interface IssuerEndpoints {
  issuer: string;
  introspection_endpoint: string;
  client: {
    client_secret: string;
    client_id: string;
  };
}

export async function checkIntrospectCredentials(
  req: Request,
  options: {
    issuers: IssuerEndpoints[];
    devMode?: DevModeConfig;
    doPost: doPostHandler;
  }
): Promise<void> {
  if (options?.devMode?.enabled) return;
  const checks = await Promise.allSettled(
    options.issuers.map(issuer => introspectToken(issuer, 'dontcaretoken', options.doPost, req))
  );

  const errors = checks
    .map((check, i) => ({ check, issuer: options.issuers[i] }))
    .filter(({ check }) => check.status === 'rejected')
    .map(({ check, issuer }) => {
      const { reason } = check as PromiseRejectedResult;
      return { msg: 'TEST-INTROSPECT - KO', reason: reason.message, issuer };
    });

  if (errors.length) {
    throw errors;
  }
  return;
}

export interface DevModeConfig {
  enabled: boolean;
  fakeUid: Identity;
}

export default function aemonOidcIntrospect(options: {
  issuers: IssuerEndpoints[];
  extractToken: (req: Request) => string | undefined;
  doPost: doPostHandler;
  logger: loggerHandler;
  devMode?: DevModeConfig;
}): RequestHandler {
  const { issuers } = options;

  const IntrospectCache = new LRUCache({
    max: 1000,
    maxAge: 300,
  });

  if (options?.devMode?.enabled) {
    return (req, res, next) => {
      req.uid = { ...(options?.devMode?.fakeUid as Identity), issuedAt: new Date().getTime() };
      Math.random() > 0.98 || options.logger(req, 'error', '---- DEV-MODE: ENABLED ----');
      next();
    };
  }

  return function (req, res, next) {
    const tokenInfo = extractToken(options.extractToken(req));

    if (tokenInfo === undefined) {
      res.status(httpStatus.UNAUTHORIZED).send();
      return;
    }
    const { token, signature } = tokenInfo;
    const cacheKey = keyFor(signature);

    // Search UID in cache
    const uid = IntrospectCache.get(cacheKey) as Identity;

    if (uid) {
      options.logger(req, 'trace', 'INTROSPECT-CACHE-HIT', { ...uid });
      // Also cache active:false token
      if (uid.active) {
        req.uid = uid;
        return next();
      } else {
        res.status(httpStatus.UNAUTHORIZED).send();
        return;
      }
    }
    const { payload } = decodeToken(token) || {};
    if (!payload) {
      options.logger(req, 'warn', 'INTROSPECT-INVALID-TOKEN-HIT', { payload });
      IntrospectCache.set(cacheKey, { active: false }, 1800);
      res.status(httpStatus.UNAUTHORIZED).send();
      return;
    }
    const issuer = issuers.find(({ issuer }) => issuer === payload?.iss);
    if (!issuer) {
      options.logger(req, 'warn', 'INTROSPECT-UNKNOWN-ISSUER-HIT', { payload });
      IntrospectCache.set(signature, { active: false }, 1800);
      res.status(httpStatus.UNAUTHORIZED).send();
      return;
    }
    introspectToken(issuer, token, options.doPost, req)
      .then(({ data }) => {
        const { active } = data;

        if (!active) {
          options.logger(req, 'warn', 'INTROSPECT-CACHE-PUT - ACTIVE:FALSE', { active: false, issuer });
          IntrospectCache.set(signature, { active: false }, 1800);
          res.status(httpStatus.UNAUTHORIZED).send();
          return;
        }

        req.uid = buildUid(data, issuer, token);

        const exp = req.uid.expires - Date.now() / 1000 || 1800;
        options.logger(req, 'debug', 'INTROSPECT-CACHE-PUT - ACTIVE:TRUE', {
          req: { subject: req.uid.subject },
          exp,
          uid: req.uid,
        });
        IntrospectCache.set(signature, req.uid, exp);
        next();
      })
      .catch(err => {
        next(err);
      });
  };

  function buildUid(data: any, issuer: IssuerEndpoints, token: string) {
    const {
      active,
      aud,
      iss,
      sub,
      email,
      email_verified,
      realm_access,
      resource_access,
      exp,
      iat,
      client_id,
      family_name,
      given_name,
      name,
      preferred_username,
    } = data;

    const allRoles = extractAllRoles(realm_access, resource_access);
    const roles = extractSelfRoles(resource_access, issuer);
    return {
      active,
      issuer: iss,
      audience: aud,
      subject: sub,
      email: email,
      familyName: family_name,
      givenName: given_name,
      emailVerified: email_verified,
      token,
      roles,
      allRoles,
      expires: exp,
      expiresIn: expiresIn(exp),
      issuedAt: iat,
      clientId: client_id,
      name,
      username: preferred_username,
    };
  }
}

function expiresIn(exp: number): number {
  const value = Math.max.apply(null, [exp * 1000 - Date.now(), 0]);
  return Math.floor(value / 1000);
}

function introspectToken(issuer: IssuerEndpoints, token: string, doPost: doPostHandler, req: Request) {
  return doPost(req, issuer.introspection_endpoint, query.stringify({ token }), {
    headers: {
      authorization: toBasic(issuer.client.client_id, issuer.client.client_secret),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  });
}

function extractSelfRoles(resource_access: any, { client }: IssuerEndpoints) {
  return (resource_access && resource_access[client.client_id] && resource_access[client.client_id].roles) || [];
}

function extractAllRoles(realm_access: { roles: string[] }, resource_access: { [key: string]: { roles: string[] } }) {
  return [
    ...(realm_access?.roles || []),
    ...reduce(
      resource_access,
      (acc, curr, key) => {
        return [...acc, ...curr.roles.map(role => `${key}:${role}`)];
      },
      [] as string[]
    ),
  ];
}

function toBasic(username: string, password: string) {
  const toEncode = Buffer.from(`${username}:${password}`);
  return `Basic ${toEncode.toString('base64')}`;
}

function decodeToken(token: string): jwt.Signature {
  const tokenContent = jwt.decode(token);
  return tokenContent;
}

function extractToken(token: string | undefined): { signature: string; token: string } | undefined {
  if (!token) return;
  const [, , signature] = token.split('.');
  return { signature, token };
}

function keyFor(text: string) {
  return crypto.createHash('md5').update(text).digest('hex');
}

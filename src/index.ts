import httpStatus from 'http-status';
import { RequestHandler, Request } from 'express';
import jwt from 'jws';
import NodeCache from 'node-cache';
import query from 'query-string';
import reduce from 'lodash.reduce';
import axios, { AxiosInstance } from 'axios';
import crypto from 'crypto';

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

declare module 'http' {
  interface IncomingMessage {
    uid: Identity;
    axios: ReturnType<typeof axios.create>;
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

export async function checkIntrospectCredentials(options: {
  issuers: IssuerEndpoints[];
  devMode?: DevModeConfig;
}): Promise<void> {
  if (options?.devMode?.enabled) return;
  const checks = await Promise.allSettled(
    options.issuers.map(issuer => introspectToken(axios.create(), issuer, 'dontcaretoken'))
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
  extractToken: (req: Request) => string;
  decorateAxiosInstace?: (axiosInstace: AxiosInstance) => void;
  devMode?: DevModeConfig;
}): RequestHandler {
  const { issuers } = options;

  const IntrospectCache = new NodeCache({
    deleteOnExpire: true,
    maxKeys: 1000,
    stdTTL: 300,
    useClones: true,
  });

  if (options?.devMode?.enabled) {
    return (req, res, next) => {
      req.uid = { ...(options?.devMode?.fakeUid as Identity), issuedAt: new Date().getTime() };
      Math.random() > 0.98 || req.log.error('---- DEV-MODE: ENABLED ----');
      next();
    };
  }

  return function (req, res, next) {
    if (options.decorateAxiosInstace) {
      options.decorateAxiosInstace(req.axios);
    }

    const tokenInfo = extractToken(options.extractToken(req));

    if (tokenInfo === undefined) {
      res.status(httpStatus.UNAUTHORIZED).send();
      return;
    }
    const { token, signature } = tokenInfo;
    const cacheKey = keyFor(signature);

    // Search UID in cache
    const uid = IntrospectCache.get<Identity & { active: boolean }>(cacheKey);

    if (uid) {
      req.log.trace({ ...uid }, 'INTROSPECT-CACHE-HIT');
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
      req.log.warn({ payload }, 'INTROSPECT-INVALID-TOKEN-HIT');
      IntrospectCache.set(cacheKey, { active: false }, 1800);
      res.status(httpStatus.UNAUTHORIZED).send();
      return;
    }
    const issuer = issuers.find(({ issuer }) => issuer === payload?.iss);
    if (!issuer) {
      req.log.warn({ payload }, 'INTROSPECT-UNKNOWN-ISSUER-HIT');
      IntrospectCache.set(signature, { active: false }, 1800);
      res.status(httpStatus.UNAUTHORIZED).send();
      return;
    }
    introspectToken(req.axios, issuer, token)
      .then(({ data }) => {
        const { active } = data;

        if (!active) {
          req.log.warn({ active: false, issuer }, 'INTROSPECT-CACHE-PUT - ACTIVE:FALSE');
          IntrospectCache.set(signature, { active: false }, 1800);
          res.status(httpStatus.UNAUTHORIZED).send();
          return;
        }

        req.uid = buildUid(data, issuer, token);

        const exp = req.uid.expires - Date.now() / 1000 || 1800;
        req.log.debug({ req: { subject: req.uid.subject }, exp, uid: req.uid }, 'INTROSPECT-CACHE-PUT - ACTIVE:TRUE');
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
      clientId,
      family_name,
      given_name,
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
      issuedAt: iat,
      clientId,
    };
  }
}

function introspectToken(axios: AxiosInstance, issuer: IssuerEndpoints, token: string) {
  return axios.post(issuer.introspection_endpoint, query.stringify({ token }), {
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

function extractToken(token: string): { signature: string; token: string } | undefined {
  if (!token) return;
  const [, , signature] = token.split('.');
  return { signature, token };
}

function keyFor(text: string) {
  return crypto.createHash('md5').update(text).digest('hex');
}

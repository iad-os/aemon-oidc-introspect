# OIDC Smart Introspect middleware

### Add dependency to project

```sh
npm i @iad-os/aemon-oidc-introspect
```

## Configure

```typescript
import aemonOidcIntrospect from '@iad-os/aemon-oidc-introspect';

//...

const expressApp = express()
  // other middleware ...
  .use(
    aemonOidcIntrospect({
      issuers: [
        {
          issuer: 'https://XXX/auth/realms/YYY',
          introspection_endpoint:
            'https://XXX/auth/realms/YYY/protocol/openid-connect/token/introspect',
          client: {
            client_id: 'client_id',
            client_secret: 'aClientSecret',
          },
        },
      ],
      extractToken: (req: Request): string => {
        
        // Bearer token example (Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c)

        const authorization = req.headers['authorization'];
        if (!authorization) return;
        const [, token] = authorization.split(' ');
        return token;
      },
      doPost: async (
          req: Request,
          url: string,
          queryString: string,
          options?: { headers: Record<string, string> }
        ) => {
          return await axios.create().post(url, queryString, options);
        },
      logger: (req: Request, level: string, msg: string, payload?: any) =>
        logger[level](msg, payload),
    })
  );
```

## Usage

```typescript
const myMiddleware: RequestHandler = function (req, res, next) {
  // ... code here
  if (!req.uid) {
    logger.info('User IDentity not found.');
    return next(null);
  }

  sendEmail(req.uid.email)
};
```

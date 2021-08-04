## 0.1.0

[All Changes](https://github.com/crossid/crossid-go/compare/v0.0.5...v0.1.0)

### Major Changes

- jwtmw - `WithScopes` middleware to protect endpoints with JWT scopes.

## 0.0.5

[All Changes](https://github.com/crossid/crossid-go/compare/v0.0.4...v0.0.5)

### Minor Changes

- jwtmw - Enhance context using the `WithContext` opt.

## 0.0.4

[All Changes](https://github.com/crossid/crossid-go/compare/v0.0.3...v0.0.4)

### Minor Changes

- jwtmw - pass ctx to KeyFunc and.
- jwtmw - support SigningMethod for alg assertion.

## 0.0.3

[All Changes](https://github.com/crossid/crossid-go/compare/v0.0.2...v0.0.3)

### Minor Changes

- jwtmw - pass http.Request in tokenValidator.

## 0.0.2

[All Changes](https://github.com/crossid/crossid-go/compare/v0.0.1...v0.0.2)

### Minor Changes

- jwtmw - Package and folder rename (jwt_mw -> jwtmw) for easy import.
- jwtmw - Bug fix where ErrorWriter was ignored.

## 0.0.1

[All Changes](https://github.com/crossid/crossid-go/compare/5986057...v0.0.1)

### Major Changes

- Initial version, with an HTTP middleware that extracts, parses and validates JWT tokens.

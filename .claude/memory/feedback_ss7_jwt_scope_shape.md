---
name: ss7-jwt-scope-shape
description: Spring AS 7 serialises the `scope` claim inside JWT payload as a JSON array, while the token endpoint response uses a space-separated string. Token tests reading the JWT must parse `scope` as ArrayNode.
metadata:
  type: feedback
---

In Spring Authorization Server 7.0.5, the JWT payload (`access_token`) emits the `scope` claim as a JSON array:

```json
"scope": ["mqtt:pub", "mqtt:sub"]
```

The `/oauth2/token` response body, however, returns the scope as a space-separated string:

```json
"scope": "mqtt:pub mqtt:sub"
```

**Why:** Both formats are spec-compliant — RFC 6749 §3.3 defines token-response scope as space-delimited, while JWT profile (RFC 9068) does not normatively constrain `scope` shape and Spring AS picks an array.

**How to apply:** Integration tests that base64-decode the JWT payload and assert `scope` must use `JsonNode.isArray()` / `objectMapper.readValue(... List.class)`. `.asText()` on an `ArrayNode` throws a `JsonNodeException` in Jackson 3.

Related: [[feedback_jackson3_imports]] — tests live under `tools.jackson.databind`.

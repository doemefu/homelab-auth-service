---
name: MockMvc query string for Spring AS
description: MockMvc .param() does not populate query string — use UriComponentsBuilder for GET requests to Spring Authorization Server endpoints
type: feedback
---

MockMvc's `.param()` only adds to the servlet parameter map, NOT to `request.getQueryString()`. Spring Authorization Server reads OAuth2 authorization params from the query string via `OAuth2EndpointUtils.getQueryParameters()`.

**Why:** Spring AS's own tests use `updateQueryString(request)` after `addParameter()`. Issue #1489 confirms `getFormParameters` explicitly excludes query string params. This caused 2 test failures where `/oauth2/authorize` returned 400 `[invalid_request] OAuth 2.0 Parameter: response_type`.

**How to apply:** For any GET request to Spring AS endpoints (especially `/oauth2/authorize`), build the URL with `UriComponentsBuilder.fromPath(...).queryParam(...).build().encode().toUriString()` and pass it to `get(url)`. POST requests (like `/oauth2/token`) can still use `.param()` for form data.

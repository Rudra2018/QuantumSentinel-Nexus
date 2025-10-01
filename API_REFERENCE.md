# 📚 QuantumSentinel-Nexus API Reference

## Authentication

All API endpoints use session-based authentication.

## File Analysis Endpoints

### Upload File for Analysis
```http
POST /api/upload
Content-Type: multipart/form-data

Parameters:
- file: File to analyze (APK, binary, source code)
- analysis_type: Type of analysis (auto, sast, dast, mobile)
```

### Get Analysis Results
```http
GET /api/results/{analysis_id}

Response:
{
  "id": "analysis_123",
  "status": "completed",
  "vulnerabilities": [...],
  "report_url": "/reports/analysis_123.pdf"
}
```

## Security Engine Endpoints

### Start Security Analysis
```http
POST /api/engines/{engine_name}/analyze
Content-Type: application/json

{
  "target": "file_path or URL",
  "options": {
    "deep_scan": true,
    "timeout": 1800
  }
}
```

### Get Engine Status
```http
GET /api/engines/status

Response:
{
  "engines": {
    "reverse_engineering": "available",
    "sast": "running",
    "dast": "available"
  }
}
```

## Bug Bounty Endpoints

### Start Bug Bounty Hunt
```http
POST /api/bugbounty/hunt
Content-Type: application/json

{
  "target": "example.com",
  "scope": {
    "subdomains": true,
    "out_of_scope": ["admin.example.com"]
  }
}
```

## Reporting Endpoints

### Generate Report
```http
POST /api/reports/generate
Content-Type: application/json

{
  "analysis_id": "analysis_123",
  "format": "pdf",
  "template": "executive"
}
```

### Download Report
```http
GET /api/reports/{report_id}/download
```

## WebSocket Events

### Real-time Analysis Updates
```javascript
const ws = new WebSocket('ws://localhost:8160/ws/analysis');

ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  console.log('Analysis update:', data);
};
```

## Error Responses

All endpoints return standard HTTP status codes:

- `200 OK` - Success
- `400 Bad Request` - Invalid parameters
- `401 Unauthorized` - Authentication required
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error

Error response format:
```json
{
  "error": "Error description",
  "code": "ERROR_CODE",
  "details": {...}
}
```

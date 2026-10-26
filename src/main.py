import httpx
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse

from src.config import settings
from src.utils import generate_request_signature
from src.redis_client import redis_db, is_rate_limited, get_cached_score, set_cached_score
from src.engine import SemanticWAFEngine

waf_engine = SemanticWAFEngine()
http_client = httpx.AsyncClient(base_url=settings.upstream_url)

@asynccontextmanager
async def lifespan(app: FastAPI):
    waf_engine.start_worker()
    yield
    await waf_engine.stop_worker()
    await http_client.aclose()
    await redis_db.close()

app = FastAPI(title="Semgress: Semantic WAF Gateway", lifespan=lifespan)

def is_fast_path_eligible(request: Request, body: bytes) -> bool:
    if request.method != "GET": return False
    if request.url.query: return False
    if len(body) > 0: return False
    return True

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_gateway(request: Request, path: str):
    # Tier 1: Distributed Redis Rate Limiting
    client_ip = request.client.host
    if await is_rate_limited(client_ip):
        return JSONResponse(status_code=429, content={"error": "Too Many Requests"})

    body = await request.body()
    risk_score = 0.0

    # Tier 2: Fast Path vs Deep Inspection
    if not is_fast_path_eligible(request, body):
        
        # Tier 3: Redis Exact-Match Decision Caching
        req_sig = generate_request_signature(request, body)
        cached_score = await get_cached_score(req_sig)
        
        if cached_score is not None:
            risk_score = cached_score
            print(f"[CACHE HIT] IP: {client_ip} | Score: {risk_score:.4f}")
        else:
            # Tier 4: GPU Batch Inference
            risk_score = await waf_engine.evaluate_payload(request, body)
            # Store result in Redis asynchronously
            await set_cached_score(req_sig, risk_score)
        
        # Tier 5: Dropping malicious traffic
        if risk_score > settings.risk_threshold:
            print(f"[WAF BLOCKED] IP: {client_ip} | Path: /{path} | Score: {risk_score:.4f}")
            return JSONResponse(
                status_code=403, 
                content={"error": "Forbidden: Payload rejected by Semgress WAF"}
            )

    # Proxy Forwarding (Clean Traffic)
    proxy_headers = dict(request.headers)
    proxy_headers.pop("host", None)
    proxy_headers["X-WAF-Risk-Score"] = f"{risk_score:.4f}"

    try:
        upstream_response = await http_client.request(
            method=request.method,
            url=f"/{path}",
            params=request.query_params,
            headers=proxy_headers,
            content=body
        )
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="Bad Gateway: Upstream unroutable.")

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=dict(upstream_response.headers)
    )

if __name__ == "__main__":
    # In production, use multiple workers (e.g., uvicorn --workers 4). 
    # Redis will coordinate rate limits and caching across all of them.
    uvicorn.run("src.main:app", host=settings.host, port=settings.port, reload=False)
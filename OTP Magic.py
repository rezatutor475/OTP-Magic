# main.py - Secure OTP Verification API (Final Professional Version - 2025)
import os
import random
import logging
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
import redis.asyncio as redis
from typing import Optional

# =====================================
# Logging Configuration (حرفه‌ای)
# =====================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("otp-api")

# =====================================
# FastAPI App
# =====================================
app = FastAPI(
    title="Secure OTP Verification Service",
    description="High-performance, secure, one-time-use OTP system with rate limiting",
    version="2.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# =====================================
# CORS
# =====================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),  # بهتر از *
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================================
# Redis Client (با تزریق وابستگی - بهترین روش)
# =====================================
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
_redis_client: Optional[redis.Redis] = None

async def get_redis() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        try:
            _redis_client = redis.from_url(
                REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=10,
                socket_timeout=10,
                retry_on_timeout=True,
                health_check_interval=30,
            )
            await _redis_client.ping()
            logger.info("Connected to Redis successfully")
        except Exception as e:
            logger.critical(f"Failed to connect to Redis: {e}")
            raise
    return _redis_client

# =====================================
# Pydantic Models (اصلاح شده)
# =====================================
class SendOTPRequest(BaseModel):
    phone: Optional[str] = Field(None, example="+989123456789")
    email: Optional[str] = Field(None, example="user@example.com")

    @validator("phone", "email", always=True)
    def check_at_least_one(cls, v, values, field):
        phone = values.get("phone")
        email = values.get("email")
        if not phone and not email:
            raise ValueError("Either 'phone' or 'email' must be provided")
        return v

class VerifyOTPRequest(BaseModel):
    identifier: str = Field(..., example="+989123456789")
    code: str = Field(..., min_length=6, max_length=6, regex=r"^\d{6}$")

# =====================================
# Rate Limiting (5 درخواست در 10 دقیقه)
# =====================================
async def check_rate_limit(identifier: str, redis_client: redis.Redis = Depends(get_redis)):
    key = f"rate_limit:otp:{identifier}"
    count = await redis_client.get(key)

    if count is None:
        await redis_client.setex(key, 600, 1)  # 10 دقیقه
        return False

    if int(count) >= 5:
        raise HTTPException(
            status_code=429,
            detail="Too many OTP requests. Try again later."
        )

    await redis_client.incr(key)
    return False

# =====================================
# Routes
# =====================================
@app.post("/api/send-otp")
async def send_otp(
    request: SendOTPRequest,
    redis_client: redis.Redis = Depends(get_redis)
):
    identifier = request.phone or request.email

    # بررسی Rate Limit
    await check_rate_limit(identifier, redis_client)

    # تولید OTP
    otp = f"{random.SystemRandom().randint(100000, 999999):06d}"

    # ذخیره در Redis (5 دقیقه)
    await redis_client.setex(f"otp:{identifier}", 300, otp)

    # لاگ حرفه‌ای (به جای print)
    logger.info(f"OTP generated for {identifier} | Code: {otp}")

    return {
        "success": True,
        "message": "OTP sent successfully",
        "expires_in": 300,
        "debug_otp": otp if os.getenv("DEBUG", "false") == "true" else None
    }


@app.post("/api/verify-otp")
async def verify_otp(
    payload: VerifyOTPRequest,
    redis_client: redis.Redis = Depends(get_redis)
):
    key = f"otp:{payload.identifier}"
    stored_otp = await redis_client.get(key)

    if not stored_otp:
        raise HTTPException(status_code=410, detail="OTP expired or not found")

    if stored_otp != payload.code:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # یک‌بار مصرف
    await redis_client.delete(key)

    logger.info(f"OTP verified successfully for {payload.identifier}")
    
    return {
        "success": True,
        "message": "OTP verified successfully",
        "verified": True
    }


@app.get("/")
async def root():
    return {"message": "OTP Service is running", "docs": "/docs"}

@app.get("/health")
async def health(redis_client: redis.Redis = Depends(get_redis)):
    try:
        await redis_client.ping()
        return {"status": "healthy", "database": "redis_connected"}
    except:
        return {"status": "unhealthy", "database": "redis_disconnected"}


# =====================================
# Lifecycle Events
# =====================================
@app.on_event("startup")
async def startup():
    await get_redis()  # Force connection test

@app.on_event("shutdown")
async def shutdown():
    if _redis_client:
        await _redis_client.close()
        logger.info("Redis connection closed")


# =====================================
# Run (فقط در توسعه)
# =====================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=os.getenv("ENV") != "production",
        log_level="info"
    )
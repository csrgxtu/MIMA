import asyncio
import time

from fastapi import FastAPI

app = FastAPI()


@app.get("/resource/{latency}")
async def read_item(latency: int):
    start_ts = round(time.time() * 1000)
    await asyncio.sleep(float(latency)/1000)
    return {
        "expect_latency(ms)": latency,
        "real_latency(ms)": round(time.time() * 1000) - start_ts
    }

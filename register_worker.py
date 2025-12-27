import os
import logging
import sys
import time
import httpx
import json
import asyncio

#set where to send registration request
ORCH_URL = os.environ.get("ORCH_URL", "")
ORCH_SECRET = os.environ.get("ORCH_SECRET","")
#create registration request
CAPABILITY_NAME = os.environ.get("CAPABILITY_NAME", "")
CAPABILITY_URL = os.environ.get("CAPABILITY_URL","http://localhost:9876")
CAPABILITY_DESCRIPTION = os.environ.get("CAPABILITY_DESCRIPTION","")

# Get the logger instance
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def register_to_orchestrator():
    capability_capacity = int(os.environ.get("CAPABILITY_CAPACITY", 1))
    capability_price_per_unit = int(os.environ.get("CAPABILITY_PRICE_PER_UNIT", "0"))
    capability_price_scaling = int(os.environ.get("CAPABILITY_PRICE_SCALING", "1"))
    capability_currency = os.environ.get("CAPABILITY_PRICE_CURRENCY","WEI")

    register_req = {
        "url": CAPABILITY_URL,
        "name": CAPABILITY_NAME,
        "description": CAPABILITY_DESCRIPTION,
        "capacity": capability_capacity,
        "price_per_unit": capability_price_per_unit,
        "price_scaling": capability_price_scaling,
        "currency": capability_currency
    }
    headers = {
        "Authorization": ORCH_SECRET,
        "Content-Type": "application/json",
    }
    #do the registration
    max_retries = 10
    delay = 2  # seconds
    logger.info("registering: "+json.dumps(register_req))
    for attempt in range(1, max_retries + 1):
        try:
            response = httpx.post(
                f"{ORCH_URL}/capability/register",
                json=register_req,
                headers=headers,
                timeout=5,
                verify=False,      # Orch not expected to have legit signed certs
            )

            if response.status_code == 200:
                logger.info("Capability registered")
                return True
            elif response.status_code == 400:
                logger.error("orch secret incorrect")
                return False
            else:
                logger.info(f"Attempt {attempt} failed: status {response.status_code} - {response.text}")
        except httpx.HTTPError as e:
            if attempt == max_retries:
                logger.error("All retries failed.")
            else:
                time.sleep(delay)

    return False


async def start_periodic_registration(interval_seconds: int = 60):
    """Async task that re-runs registration every `interval_seconds` seconds.

    This runs until cancelled by the caller.
    """
    logger.info(f"Starting periodic orchestrator registration every {interval_seconds}s")
    try:
        while True:
            # Run the blocking register function in a thread
            try:
                success = await asyncio.to_thread(register_to_orchestrator)
                if success:
                    logger.debug("Periodic registration succeeded")
                else:
                    logger.warning("Periodic registration failed")
            except Exception as e:
                logger.exception(f"Exception during periodic registration: {e}")

            await asyncio.sleep(interval_seconds)
    except asyncio.CancelledError:
        logger.info("Periodic registration task cancelled")
        raise

# utils/helpers.py
import time
import logging
from datetime import datetime, timedelta
from threading import Thread

# Import configuration
from config import config
from models import db

def init_app():
    with db.session.begin():
        db.create_all()
        logger.info("✓ Database initialized with incremental scanning support")

# Set up logger
logger = logging.getLogger("background_tasks")
if not logger.handlers:  # Prevent adding multiple handlers
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

def check_daily():
    """Background tasks"""
    while True:
        try:
            # Calculate time until next midnight
            now = datetime.now()
            next_midnight = now.replace(hour=config.CHECK_HOUR, minute=config.CHECK_MINUTE, second=config.CHECK_SECOND, microsecond=0) + timedelta(days=1)
            seconds_until_midnight = (next_midnight - now).total_seconds()
            logger.info(f"✓ Next premium check at: {next_midnight} (in {seconds_until_midnight:.0f} seconds)")
            
            # Sleep until midnight
            time.sleep(seconds_until_midnight)
            
            # Perform the premium check
            perform_premium_check()
            
        except Exception as e:
            logger.error(f"✗ Error in premium check scheduler: {e}")
            # Sleep for a while before retrying if there's an error
            time.sleep(3600)  # 1 hour

def perform_premium_check():
        logger.info(f"★ Daily premium check started at {datetime.now()}")

# Start all background tasks
def start_background_tasks():
    
    try:
        Thread(target=check_daily, daemon=True).start()
        logger.info("✓ Background tasks started successfully")
    except Exception as e:
        logger.error(f"✗ Failed to start background tasks: {e}")
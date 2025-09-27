#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Evidence Collection System
Comprehensive evidence collection and preservation for security testing
"""

import asyncio
import logging
import json
import hashlib
import zipfile
import io
import base64
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from datetime import datetime, timezone
import tempfile
import shutil
import mimetypes
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import pickle

# Screenshot and screen recording
import selenium
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

# Network capture
import asyncio
import aiofiles
import aiohttp
from scapy.all import *
import pyshark

# Media processing
from PIL import Image, ImageDraw, ImageFont
import cv2
import numpy as np

# Document generation
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image as RLImage, Table, TableStyle
from reportlab.lib.colors import black, red, orange, yellow, green, blue
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# Encryption and integrity
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

@dataclass
class EvidenceItem:
    """Individual evidence item"""
    evidence_id: str
    evidence_type: str
    title: str
    description: str
    file_path: Optional[str]
    data: Optional[bytes]
    mime_type: str
    size_bytes: int
    sha256_hash: str
    metadata: Dict[str, Any]
    timestamp: datetime
    source: str
    vulnerability_id: Optional[str]
    severity: str
    tags: List[str]

@dataclass
class EvidenceCollection:
    """Collection of evidence items"""
    collection_id: str
    target_info: Dict[str, Any]
    evidence_items: List[EvidenceItem]
    collection_metadata: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    total_size_bytes: int
    integrity_hash: str

@dataclass
class ScreenshotConfig:
    """Screenshot configuration"""
    width: int = 1920
    height: int 1080
    format: str = "PNG"
    quality: int = 95
    full_page: bool = True
    element_selector: Optional[str] = None
    wait_time: int = 3
    highlight_elements: List[str] = None

@dataclass
class RecordingConfig:
    """Screen recording configuration"""
    duration: int = 30
    fps: int = 24
    width: int = 1920
    height: int = 1080
    format: str = "MP4"
    quality: str = "high"

class EvidenceCollector:
    """Comprehensive evidence collection system"""

    def __init__(self, evidence_dir: str = "./evidence", config_path: str = None):
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(exist_ok=True)
        self.config = self._load_config(config_path)
        self.logger = logging.getLogger(__name__)

        # Evidence storage
        self.evidence_db = EvidenceDatabase(self.evidence_dir / "evidence.db")
        self.active_collections = {}

        # WebDriver setup
        self.webdriver = None
        self.webdriver_options = self._setup_webdriver_options()

        # Network capture
        self.network_captures = {}
        self.packet_captures = {}

        # Encryption setup
        self.encryption_key = self._setup_encryption()

        # Thread pool for concurrent operations
        self.executor = ThreadPoolExecutor(max_workers=8)

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load evidence collection configuration"""
        default_config = {
            "auto_screenshot": True,
            "auto_network_capture": True,
            "max_evidence_size_mb": 500,
            "compress_evidence": True,
            "encrypt_sensitive_evidence": True,
            "retain_evidence_days": 90,
            "screenshot_format": "PNG",
            "video_format": "MP4",
            "enable_watermarks": True,
            "chain_of_custody": True,
            "webdriver_path": "/usr/local/bin/chromedriver",
            "headless_browser": True,
            "browser_timeout": 30,
            "network_interface": "any",
            "capture_pcap": True,
            "capture_har": True,
            "evidence_integrity_checks": True
        }

        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)

        return default_config

    def _setup_webdriver_options(self) -> ChromeOptions:
        """Setup Chrome WebDriver options"""
        options = ChromeOptions()

        if self.config["headless_browser"]:
            options.add_argument("--headless")

        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-plugins")
        options.add_argument("--disable-images")  # Faster loading
        options.add_argument("--disable-javascript")  # Sometimes needed for static analysis

        # Enable logging for network capture
        options.add_argument("--enable-logging")
        options.add_argument("--log-level=0")
        options.add_experimental_option("useAutomationExtension", False)
        options.add_experimental_option("excludeSwitches", ["enable-automation"])

        return options

    def _setup_encryption(self) -> Fernet:
        """Setup encryption for sensitive evidence"""
        # In production, this should use proper key management
        key = Fernet.generate_key()
        return Fernet(key)

    async def start_evidence_collection(self, target_info: Dict[str, Any]) -> str:
        """Start a new evidence collection session"""
        collection_id = hashlib.md5(f"{target_info}_{datetime.now()}".encode()).hexdigest()[:12]

        self.logger.info(f"Starting evidence collection: {collection_id}")

        collection = EvidenceCollection(
            collection_id=collection_id,
            target_info=target_info,
            evidence_items=[],
            collection_metadata={
                "collector_version": "1.0",
                "collection_start": datetime.now(timezone.utc),
                "config_snapshot": self.config.copy()
            },
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            total_size_bytes=0,
            integrity_hash=""
        )

        self.active_collections[collection_id] = collection

        # Initialize collection directory
        collection_dir = self.evidence_dir / collection_id
        collection_dir.mkdir(exist_ok=True)

        # Save collection metadata
        await self._save_collection_metadata(collection)

        return collection_id

    async def capture_screenshot(self, collection_id: str, url: str, config: ScreenshotConfig = None) -> str:
        """Capture screenshot of web page"""
        if config is None:
            config = ScreenshotConfig()

        self.logger.info(f"Capturing screenshot: {url}")

        try:
            # Setup WebDriver if not already done
            if not self.webdriver:
                await self._initialize_webdriver()

            # Navigate to URL
            self.webdriver.get(url)

            # Wait for page load
            WebDriverWait(self.webdriver, self.config["browser_timeout"]).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )

            # Additional wait time
            await asyncio.sleep(config.wait_time)

            # Highlight elements if specified
            if config.highlight_elements:
                await self._highlight_elements(config.highlight_elements)

            # Capture screenshot
            if config.full_page:
                # Full page screenshot
                screenshot_data = self._capture_full_page_screenshot()
            elif config.element_selector:
                # Element-specific screenshot
                screenshot_data = self._capture_element_screenshot(config.element_selector)
            else:
                # Viewport screenshot
                screenshot_data = self.webdriver.get_screenshot_as_png()

            # Add watermark if enabled
            if self.config["enable_watermarks"]:
                screenshot_data = await self._add_watermark(screenshot_data, {
                    "url": url,
                    "timestamp": datetime.now(),
                    "collection_id": collection_id
                })

            # Create evidence item
            evidence_id = await self._create_evidence_item(
                collection_id=collection_id,
                evidence_type="screenshot",
                title=f"Screenshot: {url}",
                description=f"Full page screenshot of {url}",
                data=screenshot_data,
                mime_type="image/png",
                metadata={
                    "url": url,
                    "viewport_size": f"{config.width}x{config.height}",
                    "full_page": config.full_page,
                    "browser": "Chrome",
                    "screenshot_config": asdict(config)
                },
                source="webdriver",
                tags=["screenshot", "web", "visual"]
            )

            self.logger.info(f"Screenshot captured: {evidence_id}")
            return evidence_id

        except Exception as e:
            self.logger.error(f"Error capturing screenshot: {e}")
            raise

    async def start_screen_recording(self, collection_id: str, url: str, config: RecordingConfig = None) -> str:
        """Start screen recording"""
        if config is None:
            config = RecordingConfig()

        self.logger.info(f"Starting screen recording: {url}")

        try:
            # Setup WebDriver if not already done
            if not self.webdriver:
                await self._initialize_webdriver()

            # Navigate to URL
            self.webdriver.get(url)
            await asyncio.sleep(3)  # Wait for page load

            # Start recording
            recording_id = hashlib.md5(f"{url}_{datetime.now()}".encode()).hexdigest()[:8]
            recording_path = self.evidence_dir / collection_id / f"recording_{recording_id}.{config.format.lower()}"

            # Use OpenCV for screen recording
            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            out = cv2.VideoWriter(str(recording_path), fourcc, config.fps, (config.width, config.height))

            # Record for specified duration
            start_time = datetime.now()
            frame_count = 0

            while (datetime.now() - start_time).seconds < config.duration:
                # Capture frame
                screenshot = self.webdriver.get_screenshot_as_png()

                # Convert to OpenCV format
                img = Image.open(io.BytesIO(screenshot))
                img = img.resize((config.width, config.height))
                frame = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)

                # Write frame
                out.write(frame)
                frame_count += 1

                # Wait for next frame
                await asyncio.sleep(1 / config.fps)

            out.release()

            # Read recorded file
            with open(recording_path, 'rb') as f:
                recording_data = f.read()

            # Create evidence item
            evidence_id = await self._create_evidence_item(
                collection_id=collection_id,
                evidence_type="screen_recording",
                title=f"Screen Recording: {url}",
                description=f"Screen recording of {url} for {config.duration} seconds",
                file_path=str(recording_path),
                data=None,  # Large files stored as files, not in memory
                mime_type="video/mp4",
                metadata={
                    "url": url,
                    "duration_seconds": config.duration,
                    "fps": config.fps,
                    "resolution": f"{config.width}x{config.height}",
                    "frame_count": frame_count,
                    "recording_config": asdict(config)
                },
                source="webdriver",
                tags=["recording", "video", "web", "behavior"]
            )

            self.logger.info(f"Screen recording completed: {evidence_id}")
            return evidence_id

        except Exception as e:
            self.logger.error(f"Error in screen recording: {e}")
            raise

    async def capture_network_traffic(self, collection_id: str, duration: int = 60) -> str:
        """Capture network traffic"""
        self.logger.info(f"Starting network traffic capture for {duration} seconds")

        try:
            capture_id = hashlib.md5(f"{collection_id}_{datetime.now()}".encode()).hexdigest()[:8]
            pcap_path = self.evidence_dir / collection_id / f"network_{capture_id}.pcap"

            # Start packet capture using pyshark
            capture = pyshark.LiveCapture(
                interface=self.config["network_interface"],
                output_file=str(pcap_path)
            )

            # Capture for specified duration
            def capture_packets():
                capture.sniff(timeout=duration)

            await asyncio.get_event_loop().run_in_executor(
                self.executor, capture_packets
            )

            # Read captured data
            with open(pcap_path, 'rb') as f:
                pcap_data = f.read()

            # Analyze captured packets
            packet_analysis = await self._analyze_packet_capture(pcap_path)

            # Create evidence item
            evidence_id = await self._create_evidence_item(
                collection_id=collection_id,
                evidence_type="network_capture",
                title=f"Network Traffic Capture",
                description=f"Network packet capture for {duration} seconds",
                file_path=str(pcap_path),
                data=None,
                mime_type="application/vnd.tcpdump.pcap",
                metadata={
                    "duration_seconds": duration,
                    "interface": self.config["network_interface"],
                    "packet_count": packet_analysis["packet_count"],
                    "protocols": packet_analysis["protocols"],
                    "unique_hosts": packet_analysis["unique_hosts"]
                },
                source="pyshark",
                tags=["network", "pcap", "traffic", "packets"]
            )

            self.logger.info(f"Network capture completed: {evidence_id}")
            return evidence_id

        except Exception as e:
            self.logger.error(f"Error capturing network traffic: {e}")
            raise

    async def capture_http_traffic(self, collection_id: str, url: str) -> str:
        """Capture HTTP traffic for specific URL"""
        self.logger.info(f"Capturing HTTP traffic: {url}")

        try:
            # Setup WebDriver with network logging
            chrome_options = self.webdriver_options
            chrome_options.add_argument("--enable-logging")
            chrome_options.add_argument("--log-level=0")
            chrome_options.add_experimental_option("perfLoggingPrefs", {
                "enableNetwork": True,
                "enablePage": True
            })
            chrome_options.add_experimental_option("loggingPrefs", {
                "performance": "ALL"
            })

            # Initialize driver with logging
            if self.webdriver:
                self.webdriver.quit()

            service = ChromeService(executable_path=self.config["webdriver_path"])
            self.webdriver = webdriver.Chrome(service=service, options=chrome_options)

            # Navigate to URL
            self.webdriver.get(url)
            await asyncio.sleep(5)  # Wait for all requests

            # Get network logs
            logs = self.webdriver.get_log("performance")

            # Process logs into HAR format
            har_data = await self._convert_logs_to_har(logs, url)

            # Create evidence item
            evidence_id = await self._create_evidence_item(
                collection_id=collection_id,
                evidence_type="http_traffic",
                title=f"HTTP Traffic: {url}",
                description=f"HTTP requests and responses for {url}",
                data=json.dumps(har_data).encode(),
                mime_type="application/json",
                metadata={
                    "url": url,
                    "request_count": len(har_data.get("log", {}).get("entries", [])),
                    "format": "HAR"
                },
                source="webdriver",
                tags=["http", "har", "network", "requests"]
            )

            self.logger.info(f"HTTP traffic captured: {evidence_id}")
            return evidence_id

        except Exception as e:
            self.logger.error(f"Error capturing HTTP traffic: {e}")
            raise

    async def capture_page_source(self, collection_id: str, url: str) -> str:
        """Capture HTML source code"""
        self.logger.info(f"Capturing page source: {url}")

        try:
            # Setup WebDriver if not already done
            if not self.webdriver:
                await self._initialize_webdriver()

            # Navigate to URL
            self.webdriver.get(url)
            await asyncio.sleep(3)

            # Get page source
            page_source = self.webdriver.page_source

            # Create evidence item
            evidence_id = await self._create_evidence_item(
                collection_id=collection_id,
                evidence_type="page_source",
                title=f"Page Source: {url}",
                description=f"HTML source code of {url}",
                data=page_source.encode('utf-8'),
                mime_type="text/html",
                metadata={
                    "url": url,
                    "encoding": "utf-8",
                    "size_chars": len(page_source)
                },
                source="webdriver",
                tags=["html", "source", "web", "code"]
            )

            self.logger.info(f"Page source captured: {evidence_id}")
            return evidence_id

        except Exception as e:
            self.logger.error(f"Error capturing page source: {e}")
            raise

    async def capture_response_headers(self, collection_id: str, url: str) -> str:
        """Capture HTTP response headers"""
        self.logger.info(f"Capturing response headers: {url}")

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    headers = dict(response.headers)
                    status = response.status

                    # Create evidence item
                    evidence_id = await self._create_evidence_item(
                        collection_id=collection_id,
                        evidence_type="response_headers",
                        title=f"Response Headers: {url}",
                        description=f"HTTP response headers from {url}",
                        data=json.dumps({
                            "status_code": status,
                            "headers": headers,
                            "url": url
                        }).encode(),
                        mime_type="application/json",
                        metadata={
                            "url": url,
                            "status_code": status,
                            "header_count": len(headers)
                        },
                        source="aiohttp",
                        tags=["headers", "http", "response"]
                    )

            self.logger.info(f"Response headers captured: {evidence_id}")
            return evidence_id

        except Exception as e:
            self.logger.error(f"Error capturing response headers: {e}")
            raise

    async def capture_payload_evidence(self, collection_id: str, vulnerability_type: str, payload: str, response: str) -> str:
        """Capture payload and response evidence"""
        self.logger.info(f"Capturing payload evidence: {vulnerability_type}")

        try:
            evidence_data = {
                "vulnerability_type": vulnerability_type,
                "payload": payload,
                "response": response,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "test_details": {
                    "payload_length": len(payload),
                    "response_length": len(response),
                    "payload_encoded": base64.b64encode(payload.encode()).decode()
                }
            }

            # Create evidence item
            evidence_id = await self._create_evidence_item(
                collection_id=collection_id,
                evidence_type="payload_evidence",
                title=f"Payload Evidence: {vulnerability_type}",
                description=f"Payload and response for {vulnerability_type} vulnerability",
                data=json.dumps(evidence_data).encode(),
                mime_type="application/json",
                metadata={
                    "vulnerability_type": vulnerability_type,
                    "payload_type": self._classify_payload(payload),
                    "response_indicators": self._analyze_response_indicators(response)
                },
                source="vulnerability_scanner",
                tags=["payload", "vulnerability", vulnerability_type.lower().replace(" ", "_")]
            )

            self.logger.info(f"Payload evidence captured: {evidence_id}")
            return evidence_id

        except Exception as e:
            self.logger.error(f"Error capturing payload evidence: {e}")
            raise

    async def capture_file_evidence(self, collection_id: str, file_path: Path, description: str = None) -> str:
        """Capture file as evidence"""
        self.logger.info(f"Capturing file evidence: {file_path}")

        try:
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")

            # Read file
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Determine MIME type
            mime_type, _ = mimetypes.guess_type(str(file_path))
            if not mime_type:
                mime_type = "application/octet-stream"

            # Create evidence item
            evidence_id = await self._create_evidence_item(
                collection_id=collection_id,
                evidence_type="file_evidence",
                title=f"File: {file_path.name}",
                description=description or f"File evidence: {file_path}",
                data=file_data,
                mime_type=mime_type,
                metadata={
                    "original_path": str(file_path),
                    "file_extension": file_path.suffix,
                    "file_size": len(file_data)
                },
                source="filesystem",
                tags=["file", "evidence", file_path.suffix.lower().replace(".", "")]
            )

            self.logger.info(f"File evidence captured: {evidence_id}")
            return evidence_id

        except Exception as e:
            self.logger.error(f"Error capturing file evidence: {e}")
            raise

    async def finalize_evidence_collection(self, collection_id: str) -> Dict[str, Any]:
        """Finalize evidence collection and generate summary"""
        self.logger.info(f"Finalizing evidence collection: {collection_id}")

        try:
            collection = self.active_collections.get(collection_id)
            if not collection:
                raise ValueError(f"Collection not found: {collection_id}")

            # Update collection metadata
            collection.updated_at = datetime.now(timezone.utc)
            collection.total_size_bytes = sum(item.size_bytes for item in collection.evidence_items)

            # Generate integrity hash
            collection.integrity_hash = await self._generate_collection_hash(collection)

            # Save to database
            await self.evidence_db.save_collection(collection)

            # Generate evidence package
            package_path = await self._create_evidence_package(collection)

            # Generate summary report
            summary = await self._generate_evidence_summary(collection)

            # Cleanup
            if self.webdriver:
                self.webdriver.quit()
                self.webdriver = None

            # Remove from active collections
            del self.active_collections[collection_id]

            self.logger.info(f"Evidence collection finalized: {collection_id}")

            return {
                "collection_id": collection_id,
                "evidence_count": len(collection.evidence_items),
                "total_size_bytes": collection.total_size_bytes,
                "integrity_hash": collection.integrity_hash,
                "package_path": str(package_path),
                "summary": summary
            }

        except Exception as e:
            self.logger.error(f"Error finalizing evidence collection: {e}")
            raise

    async def _initialize_webdriver(self):
        """Initialize Chrome WebDriver"""
        try:
            service = ChromeService(executable_path=self.config["webdriver_path"])
            self.webdriver = webdriver.Chrome(service=service, options=self.webdriver_options)
            self.logger.info("WebDriver initialized successfully")
        except Exception as e:
            self.logger.error(f"Error initializing WebDriver: {e}")
            raise

    async def _highlight_elements(self, selectors: List[str]):
        """Highlight elements on page"""
        highlight_script = """
        arguments[0].style.border = '3px solid red';
        arguments[0].style.backgroundColor = 'yellow';
        arguments[0].style.opacity = '0.8';
        """

        for selector in selectors:
            try:
                elements = self.webdriver.find_elements(By.CSS_SELECTOR, selector)
                for element in elements:
                    self.webdriver.execute_script(highlight_script, element)
            except:
                continue

    def _capture_full_page_screenshot(self) -> bytes:
        """Capture full page screenshot"""
        # Get page dimensions
        total_height = self.webdriver.execute_script("return document.body.scrollHeight")
        viewport_height = self.webdriver.execute_script("return window.innerHeight")

        # Capture screenshots of page sections
        screenshots = []
        current_position = 0

        while current_position < total_height:
            # Scroll to position
            self.webdriver.execute_script(f"window.scrollTo(0, {current_position})")
            time.sleep(0.5)  # Wait for scroll

            # Capture screenshot
            screenshot = self.webdriver.get_screenshot_as_png()
            screenshots.append(Image.open(io.BytesIO(screenshot)))

            current_position += viewport_height

        # Stitch screenshots together
        if len(screenshots) == 1:
            img_bytes = io.BytesIO()
            screenshots[0].save(img_bytes, format='PNG')
            return img_bytes.getvalue()

        # Calculate total image dimensions
        width = screenshots[0].width
        total_height = sum(img.height for img in screenshots)

        # Create combined image
        combined = Image.new('RGB', (width, total_height))
        y_offset = 0

        for screenshot in screenshots:
            combined.paste(screenshot, (0, y_offset))
            y_offset += screenshot.height

        # Convert to bytes
        img_bytes = io.BytesIO()
        combined.save(img_bytes, format='PNG')
        return img_bytes.getvalue()

    def _capture_element_screenshot(self, selector: str) -> bytes:
        """Capture screenshot of specific element"""
        try:
            element = self.webdriver.find_element(By.CSS_SELECTOR, selector)
            return element.screenshot_as_png
        except:
            # Fallback to full page screenshot
            return self.webdriver.get_screenshot_as_png()

    async def _add_watermark(self, image_data: bytes, metadata: Dict[str, Any]) -> bytes:
        """Add watermark to image"""
        try:
            # Open image
            img = Image.open(io.BytesIO(image_data))

            # Create watermark text
            watermark_text = f"QuantumSentinel Evidence\n{metadata['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC')}\n{metadata['url']}\nID: {metadata['collection_id']}"

            # Create watermark
            draw = ImageDraw.Draw(img)

            # Try to load a font
            try:
                font = ImageFont.truetype("arial.ttf", 16)
            except:
                font = ImageFont.load_default()

            # Calculate watermark position (bottom right)
            text_bbox = draw.textbbox((0, 0), watermark_text, font=font)
            text_width = text_bbox[2] - text_bbox[0]
            text_height = text_bbox[3] - text_bbox[1]

            x = img.width - text_width - 20
            y = img.height - text_height - 20

            # Draw semi-transparent background
            bg_bbox = [x - 10, y - 10, x + text_width + 10, y + text_height + 10]
            draw.rectangle(bg_bbox, fill=(0, 0, 0, 128))

            # Draw watermark text
            draw.text((x, y), watermark_text, fill=(255, 255, 255), font=font)

            # Convert back to bytes
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG')
            return img_bytes.getvalue()

        except Exception as e:
            self.logger.error(f"Error adding watermark: {e}")
            return image_data

    async def _create_evidence_item(self, collection_id: str, evidence_type: str, title: str,
                                  description: str, data: Optional[bytes] = None,
                                  file_path: Optional[str] = None, mime_type: str = "application/octet-stream",
                                  metadata: Dict[str, Any] = None, source: str = "unknown",
                                  vulnerability_id: Optional[str] = None, severity: str = "info",
                                  tags: List[str] = None) -> str:
        """Create and store evidence item"""

        evidence_id = hashlib.md5(f"{collection_id}_{title}_{datetime.now()}".encode()).hexdigest()[:12]

        if metadata is None:
            metadata = {}

        if tags is None:
            tags = []

        # Calculate size and hash
        if data:
            size_bytes = len(data)
            sha256_hash = hashlib.sha256(data).hexdigest()
        elif file_path and Path(file_path).exists():
            size_bytes = Path(file_path).stat().st_size
            with open(file_path, 'rb') as f:
                sha256_hash = hashlib.sha256(f.read()).hexdigest()
        else:
            size_bytes = 0
            sha256_hash = ""

        # Store file if data provided
        stored_file_path = None
        if data:
            # Determine file extension
            ext = mimetypes.guess_extension(mime_type) or ".bin"
            stored_file_path = self.evidence_dir / collection_id / f"{evidence_id}{ext}"

            # Encrypt if sensitive
            if self.config["encrypt_sensitive_evidence"] and severity in ["high", "critical"]:
                encrypted_data = self.encryption_key.encrypt(data)
                async with aiofiles.open(stored_file_path, 'wb') as f:
                    await f.write(encrypted_data)
                metadata["encrypted"] = True
            else:
                async with aiofiles.open(stored_file_path, 'wb') as f:
                    await f.write(data)
                metadata["encrypted"] = False

        # Create evidence item
        evidence_item = EvidenceItem(
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            title=title,
            description=description,
            file_path=stored_file_path or file_path,
            data=None,  # Don't store large data in memory
            mime_type=mime_type,
            size_bytes=size_bytes,
            sha256_hash=sha256_hash,
            metadata=metadata,
            timestamp=datetime.now(timezone.utc),
            source=source,
            vulnerability_id=vulnerability_id,
            severity=severity,
            tags=tags
        )

        # Add to collection
        collection = self.active_collections[collection_id]
        collection.evidence_items.append(evidence_item)

        # Save evidence item to database
        await self.evidence_db.save_evidence_item(evidence_item, collection_id)

        return evidence_id

    async def _analyze_packet_capture(self, pcap_path: Path) -> Dict[str, Any]:
        """Analyze packet capture file"""
        try:
            cap = pyshark.FileCapture(str(pcap_path))

            packet_count = 0
            protocols = set()
            hosts = set()

            for packet in cap:
                packet_count += 1

                # Extract protocol
                if hasattr(packet, 'highest_layer'):
                    protocols.add(packet.highest_layer)

                # Extract hosts
                if hasattr(packet, 'ip'):
                    hosts.add(packet.ip.src)
                    hosts.add(packet.ip.dst)

            cap.close()

            return {
                "packet_count": packet_count,
                "protocols": list(protocols),
                "unique_hosts": list(hosts)
            }

        except Exception as e:
            self.logger.error(f"Error analyzing packet capture: {e}")
            return {"packet_count": 0, "protocols": [], "unique_hosts": []}

    async def _convert_logs_to_har(self, logs: List[Dict], url: str) -> Dict[str, Any]:
        """Convert Chrome performance logs to HAR format"""
        har_entries = []

        for log in logs:
            message = log.get("message", {})
            method = message.get("method", "")

            if method == "Network.responseReceived":
                params = message.get("params", {})
                response = params.get("response", {})

                har_entry = {
                    "startedDateTime": datetime.now(timezone.utc).isoformat(),
                    "time": 0,  # Would need to calculate from request/response timing
                    "request": {
                        "method": response.get("method", "GET"),
                        "url": response.get("url", ""),
                        "headers": [],
                        "queryString": [],
                        "postData": {}
                    },
                    "response": {
                        "status": response.get("status", 0),
                        "statusText": response.get("statusText", ""),
                        "headers": [],
                        "content": {
                            "size": 0,
                            "mimeType": response.get("mimeType", "")
                        }
                    }
                }

                har_entries.append(har_entry)

        return {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "QuantumSentinel Evidence Collector",
                    "version": "1.0"
                },
                "entries": har_entries
            }
        }

    def _classify_payload(self, payload: str) -> str:
        """Classify payload type"""
        payload_lower = payload.lower()

        if any(sql_keyword in payload_lower for sql_keyword in ['select', 'union', 'drop', 'insert', 'update']):
            return "sql_injection"
        elif any(xss_pattern in payload_lower for xss_pattern in ['<script', 'javascript:', 'onerror=']):
            return "xss"
        elif 'admin' in payload_lower and ('or' in payload_lower or '=' in payload):
            return "auth_bypass"
        elif any(cmd_pattern in payload_lower for cmd_pattern in ['&&', '||', ';', '`']):
            return "command_injection"
        else:
            return "unknown"

    def _analyze_response_indicators(self, response: str) -> List[str]:
        """Analyze response for vulnerability indicators"""
        indicators = []
        response_lower = response.lower()

        # SQL error indicators
        if any(error in response_lower for error in ['sql error', 'mysql error', 'syntax error']):
            indicators.append("sql_error")

        # XSS indicators
        if '<script' in response_lower or 'javascript:' in response_lower:
            indicators.append("xss_reflection")

        # Directory traversal indicators
        if any(path in response_lower for path in ['root:x:', 'boot.ini', 'web.config']):
            indicators.append("directory_traversal")

        # Error disclosure
        if any(disclosure in response_lower for disclosure in ['stack trace', 'exception', 'debug']):
            indicators.append("information_disclosure")

        return indicators

    async def _save_collection_metadata(self, collection: EvidenceCollection):
        """Save collection metadata to file"""
        metadata_path = self.evidence_dir / collection.collection_id / "metadata.json"

        metadata = {
            "collection_id": collection.collection_id,
            "target_info": collection.target_info,
            "created_at": collection.created_at.isoformat(),
            "collection_metadata": collection.collection_metadata
        }

        async with aiofiles.open(metadata_path, 'w') as f:
            await f.write(json.dumps(metadata, indent=2))

    async def _generate_collection_hash(self, collection: EvidenceCollection) -> str:
        """Generate integrity hash for collection"""
        hash_data = f"{collection.collection_id}{collection.created_at}{len(collection.evidence_items)}"

        for item in collection.evidence_items:
            hash_data += f"{item.evidence_id}{item.sha256_hash}"

        return hashlib.sha256(hash_data.encode()).hexdigest()

    async def _create_evidence_package(self, collection: EvidenceCollection) -> Path:
        """Create compressed evidence package"""
        package_path = self.evidence_dir / f"{collection.collection_id}_evidence.zip"

        with zipfile.ZipFile(package_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            collection_dir = self.evidence_dir / collection.collection_id

            # Add all files in collection directory
            for file_path in collection_dir.rglob("*"):
                if file_path.is_file():
                    arcname = file_path.relative_to(collection_dir)
                    zipf.write(file_path, arcname)

            # Add collection summary
            summary = await self._generate_evidence_summary(collection)
            zipf.writestr("evidence_summary.json", json.dumps(summary, indent=2))

        return package_path

    async def _generate_evidence_summary(self, collection: EvidenceCollection) -> Dict[str, Any]:
        """Generate evidence collection summary"""
        evidence_by_type = {}
        total_size = 0

        for item in collection.evidence_items:
            if item.evidence_type not in evidence_by_type:
                evidence_by_type[item.evidence_type] = {
                    "count": 0,
                    "total_size": 0,
                    "items": []
                }

            evidence_by_type[item.evidence_type]["count"] += 1
            evidence_by_type[item.evidence_type]["total_size"] += item.size_bytes
            evidence_by_type[item.evidence_type]["items"].append({
                "id": item.evidence_id,
                "title": item.title,
                "timestamp": item.timestamp.isoformat(),
                "size": item.size_bytes
            })

            total_size += item.size_bytes

        return {
            "collection_id": collection.collection_id,
            "target_info": collection.target_info,
            "total_evidence_items": len(collection.evidence_items),
            "total_size_bytes": total_size,
            "evidence_by_type": evidence_by_type,
            "collection_period": {
                "start": collection.created_at.isoformat(),
                "end": collection.updated_at.isoformat()
            },
            "integrity_hash": collection.integrity_hash
        }

class EvidenceDatabase:
    """SQLite database for evidence storage"""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._initialize_database()

    def _initialize_database(self):
        """Initialize evidence database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Collections table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS collections (
                id TEXT PRIMARY KEY,
                target_info TEXT,
                metadata TEXT,
                created_at TIMESTAMP,
                updated_at TIMESTAMP,
                total_size_bytes INTEGER,
                integrity_hash TEXT
            )
        ''')

        # Evidence items table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence_items (
                id TEXT PRIMARY KEY,
                collection_id TEXT,
                evidence_type TEXT,
                title TEXT,
                description TEXT,
                file_path TEXT,
                mime_type TEXT,
                size_bytes INTEGER,
                sha256_hash TEXT,
                metadata TEXT,
                timestamp TIMESTAMP,
                source TEXT,
                vulnerability_id TEXT,
                severity TEXT,
                tags TEXT,
                FOREIGN KEY (collection_id) REFERENCES collections (id)
            )
        ''')

        conn.commit()
        conn.close()

    async def save_collection(self, collection: EvidenceCollection):
        """Save collection to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO collections
            (id, target_info, metadata, created_at, updated_at, total_size_bytes, integrity_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            collection.collection_id,
            json.dumps(collection.target_info),
            json.dumps(collection.collection_metadata),
            collection.created_at,
            collection.updated_at,
            collection.total_size_bytes,
            collection.integrity_hash
        ))

        conn.commit()
        conn.close()

    async def save_evidence_item(self, item: EvidenceItem, collection_id: str):
        """Save evidence item to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO evidence_items
            (id, collection_id, evidence_type, title, description, file_path, mime_type,
             size_bytes, sha256_hash, metadata, timestamp, source, vulnerability_id,
             severity, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            item.evidence_id,
            collection_id,
            item.evidence_type,
            item.title,
            item.description,
            item.file_path,
            item.mime_type,
            item.size_bytes,
            item.sha256_hash,
            json.dumps(item.metadata),
            item.timestamp,
            item.source,
            item.vulnerability_id,
            item.severity,
            json.dumps(item.tags)
        ))

        conn.commit()
        conn.close()

# Export main classes
__all__ = [
    'EvidenceCollector',
    'EvidenceItem',
    'EvidenceCollection',
    'ScreenshotConfig',
    'RecordingConfig'
]
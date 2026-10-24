import asyncio
import ipaddress
import io
import logging
import re
import sqlite3
import socket
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit

import requests
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from PIL import ExifTags, Image, UnidentifiedImageError
from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis")
Image.MAX_IMAGE_PIXELS = 40_000_000


class Settings(BaseSettings):
    secret_key: str = Field(alias="AEGIS_SECRET_KEY")
    database_path: Path = Field(default=Path("./aegis.db"), alias="AEGIS_DATABASE_PATH")
    allowed_origins: str = Field(default="http://localhost:5173", alias="AEGIS_ALLOWED_ORIGINS")
    token_expire_minutes: int = Field(default=30, alias="AEGIS_TOKEN_EXPIRE_MINUTES", ge=1, le=1440)
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]


settings = Settings()
if len(settings.secret_key) < 32:
    raise RuntimeError("AEGIS_SECRET_KEY must contain at least 32 characters.")

pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(settings.database_path, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


app = FastAPI(title="Aegis Intelligence Suite API", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


class Credentials(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=128)


class PasswordCheckRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class NetworkLookupRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2048)
    authorized: bool


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str


def create_access_token(username: str) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=settings.token_expire_minutes)
    return jwt.encode({"sub": username, "exp": expires}, settings.secret_key, algorithm="HS256")


def authenticated_username(token: str = Depends(oauth2_scheme)) -> str:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        username = payload.get("sub")
        if not isinstance(username, str):
            raise ValueError("Token subject is missing.")
        return username
    except (JWTError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@app.post("/api/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(credentials: Credentials) -> TokenResponse:
    if not USERNAME_PATTERN.fullmatch(credentials.username):
        raise HTTPException(status_code=422, detail="Username contains unsupported characters.")
    password_hash = pwd_context.hash(credentials.password)
    try:
        with get_connection() as connection:
            connection.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (credentials.username, password_hash, datetime.now(timezone.utc).isoformat()),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Username is already registered.") from exc
    return TokenResponse(access_token=create_access_token(credentials.username), username=credentials.username)


@app.post("/api/auth/login", response_model=TokenResponse)
def login(credentials: Credentials) -> TokenResponse:
    with get_connection() as connection:
        user = connection.execute(
            "SELECT username, password_hash FROM users WHERE username = ?",
            (credentials.username,),
        ).fetchone()
    if user is None or not pwd_context.verify(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password.")
    return TokenResponse(access_token=create_access_token(user["username"]), username=user["username"])


@app.get("/api/auth/me")
def get_current_user(username: str = Depends(authenticated_username)) -> dict[str, str]:
    return {"username": username}


def normalize_lookup_target(query: str) -> tuple[str, ipaddress.IPv4Address | ipaddress.IPv6Address | None]:
    value = query.strip()
    try:
        address = ipaddress.ip_address(value.strip("[]"))
        if not address.is_global:
            raise HTTPException(status_code=422, detail="Only public IP addresses can be looked up.")
        return str(address), address
    except ValueError:
        pass

    parts = urlsplit(value if "://" in value else f"//{value}")
    if parts.scheme and parts.scheme.lower() not in {"http", "https"}:
        raise HTTPException(status_code=422, detail="Enter an HTTP(S) URL, domain, or public IP address.")
    if parts.username or parts.password:
        raise HTTPException(status_code=422, detail="URLs containing credentials are not supported.")
    try:
        _ = parts.port
        hostname = parts.hostname
        hostname = hostname.encode("idna").decode("ascii").rstrip(".").lower() if hostname else ""
    except (UnicodeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Enter a valid URL, domain, or public IP address.") from exc
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None:
        if not address.is_global:
            raise HTTPException(status_code=422, detail="Only public IP addresses can be looked up.")
        return str(address), address
    if (
        not hostname
        or len(hostname) > 253
        or "." not in hostname
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in hostname.split(".")
        )
    ):
        raise HTTPException(status_code=422, detail="Enter a valid public website URL, domain, or IP address.")
    return hostname, None


def get_ip_location(address: str) -> dict[str, Any]:
    response = requests.get(f"https://ipapi.co/{address}/json/", timeout=(3.05, 10))
    response.raise_for_status()
    data = response.json()
    latitude, longitude = data.get("latitude"), data.get("longitude")
    if data.get("error") or not isinstance(latitude, (int, float)) or not isinstance(longitude, (int, float)):
        raise ValueError("Geolocation service returned no coordinates.")
    return {
        "city": data.get("city") if isinstance(data.get("city"), str) else None,
        "region": data.get("region") if isinstance(data.get("region"), str) else None,
        "country": data.get("country_name") if isinstance(data.get("country_name"), str) else None,
        "latitude": float(latitude),
        "longitude": float(longitude),
    }


@app.post("/api/network-lookup")
def network_lookup(
    request: NetworkLookupRequest,
    _: str = Depends(authenticated_username),
) -> dict[str, Any]:
    if not request.authorized:
        raise HTTPException(status_code=403, detail="Confirm that you are authorized to look up this domain or IP.")
    hostname, address = normalize_lookup_target(request.query)
    try:
        addresses = (
            [str(address)]
            if address is not None
            else sorted({
                str(ipaddress.ip_address(result[4][0]))
                for result in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
                if ipaddress.ip_address(result[4][0]).is_global
            })
        )
    except socket.gaierror as exc:
        raise HTTPException(status_code=404, detail="The domain could not be resolved.") from exc
    if not addresses:
        raise HTTPException(status_code=422, detail="The domain did not resolve to a public IP address.")

    primary_address = addresses[0]
    try:
        reverse_hostname = socket.gethostbyaddr(primary_address)[0]
    except (socket.herror, socket.gaierror):
        reverse_hostname = None
    try:
        location = get_ip_location(primary_address)
    except (requests.RequestException, ValueError) as exc:
        logger.warning("IP geolocation lookup failed: %s", exc)
        raise HTTPException(status_code=502, detail="The IP geolocation service is unavailable or returned invalid data.") from exc
    return {
        "hostname": hostname,
        "addresses": addresses,
        "reverse_hostname": reverse_hostname,
        "location": location,
    }


def json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, tuple):
        return [json_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    try:
        return float(value)
    except (TypeError, ValueError):
        return str(value)


def dms_to_decimal(values: Any, reference: Any) -> float:
    def as_float(part: Any) -> float:
        if isinstance(part, tuple) and len(part) == 2:
            numerator, denominator = part
            return float(numerator) / float(denominator)
        return float(part)

    degrees, minutes, seconds = (as_float(part) for part in values)
    decimal = degrees + minutes / 60 + seconds / 3600
    direction = reference.decode("ascii") if isinstance(reference, bytes) else str(reference)
    return -decimal if direction.upper() in {"S", "W"} else decimal


def extract_gps(exif: Any) -> dict[str, float] | None:
    gps_raw = exif.get(34853)
    if not gps_raw:
        return None
    gps = gps_raw
    try:
        gps = gps_raw.get_ifd(34853)
    except (AttributeError, KeyError, TypeError):
        pass
    gps_named = {ExifTags.GPSTAGS.get(key, key): value for key, value in gps.items()}
    latitude = gps_named.get("GPSLatitude")
    longitude = gps_named.get("GPSLongitude")
    latitude_ref = gps_named.get("GPSLatitudeRef")
    longitude_ref = gps_named.get("GPSLongitudeRef")
    if latitude is None or longitude is None or latitude_ref is None or longitude_ref is None:
        return None
    try:
        return {
            "latitude": dms_to_decimal(latitude, latitude_ref),
            "longitude": dms_to_decimal(longitude, longitude_ref),
        }
    except (TypeError, ValueError, ZeroDivisionError):
        return None


@app.post("/api/exif")
async def parse_exif(
    image: UploadFile = File(...),
    _: str = Depends(authenticated_username),
) -> dict[str, Any]:
    if image.content_type not in {"image/jpeg", "image/tiff", "image/webp"}:
        raise HTTPException(status_code=415, detail="Upload a JPEG, TIFF, or WebP image.")
    content = await image.read(12 * 1024 * 1024 + 1)
    if len(content) > 12 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Image exceeds the 12 MiB upload limit.")
    try:
        with Image.open(io.BytesIO(content)) as picture:
            picture.verify()
        with Image.open(io.BytesIO(content)) as picture:
            exif = picture.getexif()
            metadata = {
                ExifTags.TAGS.get(tag, str(tag)): json_value(value)
                for tag, value in exif.items()
                if tag != 34853
            }
            gps = extract_gps(exif)
            return {
                "filename": Path(image.filename or "upload").name,
                "format": picture.format,
                "metadata": metadata,
                "gps": gps,
            }
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise HTTPException(status_code=400, detail="The uploaded file is not a valid supported image.") from exc
    finally:
        await image.close()


def query_hibp(password: str) -> int:
    digest = __import__("hashlib").sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    response = requests.get(
        HIBP_RANGE_URL.format(prefix),
        headers={"Add-Padding": "true", "User-Agent": "Aegis-Intelligence-Suite/1.0"},
        timeout=(3.05, 10),
    )
    response.raise_for_status()
    for line in response.text.splitlines():
        candidate, separator, count = line.partition(":")
        if separator and candidate.upper() == suffix:
            if count.isdecimal():
                return int(count)
            raise ValueError("HIBP returned a malformed frequency.")
    return 0


@app.post("/api/password-check")
async def password_check(request: PasswordCheckRequest) -> dict[str, int | bool]:
    try:
        count = await asyncio.to_thread(query_hibp, request.password)
    except requests.RequestException as exc:
        logger.warning("HIBP password range request failed: %s", exc)
        raise HTTPException(status_code=502, detail="Password reputation service is unavailable.") from exc
    except ValueError as exc:
        logger.error("HIBP returned an invalid response.")
        raise HTTPException(status_code=502, detail="Password reputation service returned an invalid response.") from exc
    return {"compromised": count > 0, "frequency": count}


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

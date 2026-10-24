import asyncio
import hashlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PIL import Image
from starlette.datastructures import UploadFile

os.environ.setdefault("AEGIS_SECRET_KEY", "unit-test-only-secret-key-with-32-characters")

import main


class AegisApiLogicTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        main.settings.database_path = Path(self.temp_dir.name) / "test.db"
        main.initialize_database()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_registration_login_and_bearer_token(self) -> None:
        credentials = main.Credentials(username="aegis_user", password="a sufficiently long password")
        token = main.register(credentials)
        self.assertEqual(main.login(credentials).username, "aegis_user")
        self.assertEqual(main.authenticated_username(token.access_token), "aegis_user")

    def test_gps_dms_conversion_and_reference_directions(self) -> None:
        gps = {
            1: "N",
            2: ((40, 1), (30, 1), (0, 1)),
            3: "W",
            4: ((73, 1), (30, 1), (0, 1)),
        }
        self.assertEqual(
            main.extract_gps({34853: gps}),
            {"latitude": 40.5, "longitude": -73.5},
        )

    def test_network_lookup_normalizes_urls_and_rejects_private_ips(self) -> None:
        self.assertEqual(main.normalize_lookup_target("https://example.com/path")[0], "example.com")
        self.assertEqual(main.normalize_lookup_target("8.8.8.8")[0], "8.8.8.8")
        with self.assertRaises(main.HTTPException):
            main.normalize_lookup_target("127.0.0.1")

    def test_network_lookup_resolves_public_addresses_and_location(self) -> None:
        resolved = [
            (2, 1, 6, "", ("8.8.8.8", 0)),
            (2, 1, 6, "", ("10.0.0.1", 0)),
        ]
        location = {
            "city": "Mountain View",
            "region": "California",
            "country": "United States",
            "latitude": 37.4056,
            "longitude": -122.0775,
        }
        with (
            patch.object(main.socket, "getaddrinfo", return_value=resolved),
            patch.object(main.socket, "gethostbyaddr", return_value=("dns.google", [], [])),
            patch.object(main, "get_ip_location", return_value=location),
        ):
            result = main.network_lookup(
                main.NetworkLookupRequest(query="https://example.com", authorized=True),
                "aegis_user",
            )
        self.assertEqual(result["addresses"], ["8.8.8.8"])
        self.assertEqual(result["reverse_hostname"], "dns.google")
        self.assertEqual(result["location"], location)

    def test_password_check_matches_exact_hibp_suffix_and_count(self) -> None:
        password = "password for test"
        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

        class Response:
            text = f"{digest[5:]}:17\n{'0' * 35}:2\n"

            def raise_for_status(self) -> None:
                return None

        with patch.object(main.requests, "get", return_value=Response()) as request:
            result = asyncio.run(
                main.password_check(main.PasswordCheckRequest(password=password))
            )
        self.assertEqual(result, {"compromised": True, "frequency": 17})
        self.assertEqual(request.call_args.args[0], main.HIBP_RANGE_URL.format(digest[:5]))

    def test_exif_extracts_camera_metadata_without_gps(self) -> None:
        image_data = io.BytesIO()
        picture = Image.new("RGB", (8, 8), "white")
        exif = Image.Exif()
        exif[271] = "Aegis Test Camera"
        picture.save(image_data, format="JPEG", exif=exif)
        image_data.seek(0)
        upload = UploadFile(
            filename="sample.jpg",
            file=image_data,
            headers={"content-type": "image/jpeg"},
        )

        result = asyncio.run(main.parse_exif(upload, "aegis_user"))
        self.assertEqual(result["metadata"]["Make"], "Aegis Test Camera")
        self.assertIsNone(result["gps"])


if __name__ == "__main__":
    unittest.main()

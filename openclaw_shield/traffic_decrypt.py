"""
SSL/TLS Traffic Decryption Module
Provides SSL/TLS traffic interception and decryption for security inspection.
Supports MITM (Man-In-The-Middle) proxy for HTTPS traffic analysis.
"""

import ssl
import socket
import asyncio
import hashlib
import certifi
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from loguru import logger
from pathlib import Path
import os

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    logger.warning("cryptography library not available")


class DecryptionStatus(Enum):
    """Status of SSL decryption."""
    SUCCESS = "success"
    FAILED = "failed"
    CERTIFICATE_ERROR = "certificate_error"
    HANDSHAKE_FAILED = "handshake_failed"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"


class SNIInfo:
    """Server Name Indication information."""

    @staticmethod
    def parse_sni(data: bytes) -> Optional[str]:
        """
        Parse SNI from TLS ClientHello.

        Args:
            data: Raw TLS handshake data

        Returns:
            SNI hostname or None
        """
        try:
            # TLS content types
            CONTENT_TYPE_HANDSHAKE = 0x16

            if len(data) < 5:
                return None

            # Check for handshake
            if data[0] != CONTENT_TYPE_HANDSHAKE:
                return None

            # Find SNI extension
            sni_start = data.find(b'\x00\x00')  # Server Name Indication extension type
            if sni_start == -1:
                return None

            # Parse SNI
            sni_start += 2  # Skip extension type
            sni_length = int.from_bytes(data[sni_start:sni_start+2], 'big')
            sni_data = data[sni_start+2:sni_start+2+sni_length]

            # Skip list length
            name_list_length = int.from_bytes(sni_data[0:2], 'big')
            name_type = sni_data[2]
            if name_type == 0:  # DNS hostname
                name_length = int.from_bytes(sni_data[3:5], 'big')
                hostname = sni_data[5:5+name_length].decode('utf-8', errors='ignore')
                return hostname

        except Exception as e:
            logger.debug(f"Failed to parse SNI: {e}")

        return None


@dataclass
class DecryptedSession:
    """Information about a decrypted SSL session."""
    session_id: str
    client_ip: str
    server_hostname: str
    server_port: int
    cipher_suite: str
    start_time: str
    end_time: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    requests_count: int = 0
    status: DecryptionStatus = DecryptionStatus.SUCCESS

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        d = asdict(self)
        d['status'] = self.status.value
        return d


@dataclass
class DecryptedRequest:
    """A decrypted HTTP request."""
    session_id: str
    timestamp: str
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str]
    query_params: Dict[str, str]

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class DecryptedResponse:
    """A decrypted HTTP response."""
    session_id: str
    timestamp: str
    status_code: int
    headers: Dict[str, str]
    body: Optional[str]
    content_length: int

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class CertificateAuthority:
    """Manages CA certificate generation for MITM."""

    def __init__(self, config):
        """Initialize CA."""
        self.config = config
        self._ca_dir = Path(config.get('ssl_decrypt.ca_dir', './config/ssl_ca'))
        self._ca_dir.mkdir(parents=True, exist_ok=True)

        self._ca_key_path = self._ca_dir / 'ca_key.pem'
        self._ca_cert_path = self._ca_dir / 'ca_cert.pem'

        if HAS_CRYPTOGRAPHY:
            self._load_or_create_ca()

    def _load_or_create_ca(self):
        """Load existing CA or create new one."""
        if self._ca_cert_path.exists() and self._ca_key_path.exists():
            logger.info("Loading existing CA certificate")
            self._load_ca()
        else:
            logger.info("Creating new CA certificate")
            self._create_ca()

    def _create_ca(self):
        """Create a new CA certificate."""
        if not HAS_CRYPTOGRAPHY:
            return

        # Generate private key
        self._ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenClaw Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, "OpenClaw MITM CA"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self._ca_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                key_encipherment=True,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).sign(self._ca_private_key, hashes.SHA256(), default_backend())

        # Save to files
        with open(self._ca_key_path, 'wb') as f:
            f.write(self._ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(self._ca_cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        self._ca_certificate = cert
        logger.info(f"Created CA certificate: {self._ca_cert_path}")

    def _load_ca(self):
        """Load existing CA certificate."""
        with open(self._ca_key_path, 'rb') as f:
            self._ca_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

        with open(self._ca_cert_path, 'rb') as f:
            self._ca_certificate = x509.load_pem_x509_certificate(
                f.read(),
                default_backend()
            )

    def generate_server_certificate(self, hostname: str) -> Tuple[bytes, bytes]:
        """
        Generate a server certificate for a specific hostname.

        Returns:
            Tuple of (certificate_pem, private_key_pem)
        """
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError("cryptography library required")

        # Generate private key for the server cert
        server_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Build subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, hostname),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])

        # Create certificate signed by CA
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self._ca_certificate.subject
        ).public_key(
            server_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        ).sign(self._ca_private_key, hashes.SHA256(), default_backend())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        return cert_pem, key_pem

    def get_ca_certificate(self) -> bytes:
        """Get the CA certificate in PEM format."""
        with open(self._ca_cert_path, 'rb') as f:
            return f.read()

    def get_ca_fingerprint(self) -> str:
        """Get the CA certificate fingerprint."""
        cert = self.get_ca_certificate()
        der = ssl.PEM_cert_to_DER_cert(cert.decode())
        return hashlib.sha256(der).hexdigest()


class SSLMITMProxy:
    """
    SSL/TLS MITM proxy for decrypting HTTPS traffic.
    """

    def __init__(self, config):
        """Initialize the MITM proxy."""
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError("cryptography library required for SSL decryption")

        self.config = config
        self.ca = CertificateAuthority(config)
        self._sessions: Dict[str, DecryptedSession] = {}
        self._cert_cache: Dict[str, Tuple[bytes, bytes]] = {}
        self._running = False

        # Configuration
        self._listen_host = config.get('ssl_decrypt.listen_host', '127.0.0.1')
        self._listen_port = config.get('ssl_decrypt.listen_port', 8080)
        self._upstream_timeout = config.get('ssl_decrypt.upstream_timeout', 30)
        self._max_sessions = config.get('ssl_decrypt.max_sessions', 10000)

        # Callbacks
        self._on_request: List[Callable] = []
        self._on_response: List[Callable] = []

        # Blocklist
        self._hostname_blocklist = set(config.get('ssl_decrypt.hostname_blocklist', []))

    def register_request_callback(self, callback: Callable[[DecryptedRequest], None]):
        """Register callback for decrypted requests."""
        self._on_request.append(callback)

    def register_response_callback(self, callback: Callable[[DecryptedResponse], None]):
        """Register callback for decrypted responses."""
        self._on_response.append(callback)

    async def start(self):
        """Start the MITM proxy server."""
        if self._running:
            logger.warning("MITM proxy is already running")
            return

        self._running = True
        logger.info(f"Starting SSL MITM proxy on {self._listen_host}:{self._listen_port}")

        try:
            server = await asyncio.start_server(
                self._handle_client,
                self._listen_host,
                self._listen_port
            )

            async with server:
                await server.serve_forever()

        except Exception as e:
            logger.error(f"MITM proxy error: {e}")
            self._running = False

    async def stop(self):
        """Stop the MITM proxy."""
        self._running = False
        logger.info("Stopping SSL MITM proxy")

    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter):
        """Handle a client connection."""
        client_addr = writer.get_extra_info('peername')
        logger.debug(f"New connection from {client_addr}")

        try:
            # Read initial data (might be HTTP CONNECT or direct HTTPS)
            data = await reader.read(4096)

            if not data:
                return

            # Check for HTTP CONNECT (proxy method)
            if b'CONNECT' in data:
                await self._handle_connect(reader, writer, data, client_addr)
            else:
                # Direct SSL/TLS connection
                await self._handle_ssl_direct(reader, writer, data, client_addr)

        except Exception as e:
            logger.debug(f"Client handler error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def _handle_connect(self, reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter,
                              data: bytes, client_addr: tuple):
        """Handle HTTP CONNECT method."""
        try:
            # Parse CONNECT request
            connect_line = data.split(b'\r\n')[0].decode()
            parts = connect_line.split()
            if len(parts) < 2:
                return

            _, target, _ = parts[:3]
            if ':' in target:
                hostname, port = target.split(':')
                port = int(port)
            else:
                hostname = target
                port = 443

            # Check blocklist
            if hostname in self._hostname_blocklist:
                writer.write(b'HTTP/1.1 403 Forbidden\r\n\r\n')
                await writer.drain()
                logger.warning(f"Blocked connection to: {hostname}")
                return

            # Send 200 Connection Established
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()

            # Now handle SSL/TLS
            await self._perform_mitm(reader, writer, hostname, port, client_addr)

        except Exception as e:
            logger.error(f"CONNECT handler error: {e}")

    async def _handle_ssl_direct(self, reader: asyncio.StreamReader,
                                  writer: asyncio.StreamWriter,
                                  data: bytes, client_addr: tuple):
        """Handle direct SSL/TLS connection."""
        # Try to extract SNI
        hostname = SNIInfo.parse_sni(data)

        if not hostname:
            logger.debug("No SNI found, cannot perform MITM")
            return

        port = 443  # Default HTTPS port

        # Check blocklist
        if hostname in self._hostname_blocklist:
            logger.warning(f"Blocked connection to: {hostname}")
            return

        # Perform MITM
        await self._perform_mitm(reader, writer, hostname, port, client_addr, data)

    async def _perform_mitm(self, reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter,
                            hostname: str, port: int,
                            client_addr: tuple, initial_data: bytes = None):
        """Perform the MITM attack."""
        import uuid
        session_id = str(uuid.uuid4())

        try:
            # Generate server certificate for hostname
            if hostname not in self._cert_cache:
                cert_pem, key_pem = self.ca.generate_server_certificate(hostname)
                self._cert_cache[hostname] = (cert_pem, key_pem)
            else:
                cert_pem, key_pem = self._cert_cache[hostname]

            # Create SSL context for client
            client_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            client_context.load_cert_chain(certfile=cert_pem, keyfile=key_pem)

            # Wrap client socket
            client_reader = asyncio.StreamReader()
            client_protocol = asyncio.StreamReaderProtocol(client_reader)
            transport, _ = await asyncio.get_event_loop().connect_accepted_socket(
                lambda: client_protocol,
                writer.get_extra_info('socket')
            )

            # Wait for client SSL handshake
            client_ssl_object = client_context.wrap_socket(transport, server_side=True)
            await asyncio.get_event_loop().sock_sendall(client_ssl_object.fileno(), initial_data or b'')

            # Create session
            session = DecryptedSession(
                session_id=session_id,
                client_ip=client_addr[0],
                server_hostname=hostname,
                server_port=port,
                cipher_suite='TLS_AES_256_GCM_SHA384',
                start_time=datetime.now().isoformat(),
                status=DecryptionStatus.SUCCESS
            )

            self._sessions[session_id] = session

            # Connect to upstream server
            server_reader, server_writer = await asyncio.open_connection(
                hostname, port, ssl=True
            )

            # Start bidirectional forwarding
            asyncio.create_task(
                self._forward_client_to_server(client_reader, server_writer, session)
            )
            asyncio.create_task(
                self._forward_server_to_client(server_reader, writer, session)
            )

        except ssl.SSLError as e:
            logger.warning(f"SSL error for {hostname}: {e}")
            session.status = DecryptionStatus.HANDSHAKE_FAILED
        except Exception as e:
            logger.error(f"MITM error for {hostname}: {e}")
            session.status = DecryptionStatus.FAILED

    async def _forward_client_to_server(self, reader: asyncio.StreamReader,
                                        writer: asyncio.StreamWriter,
                                        session: DecryptedSession):
        """Forward data from client to server."""
        try:
            while True:
                data = await reader.read(8192)

                if not data:
                    break

                # Try to parse HTTP request
                try:
                    request_data = self._parse_http_request(data)
                    if request_data:
                        request = DecryptedRequest(
                            session_id=session.session_id,
                            timestamp=datetime.now().isoformat(),
                            **request_data
                        )

                        # Trigger callbacks
                        for callback in self._on_request:
                            try:
                                callback(request)
                            except Exception as e:
                                logger.error(f"Request callback error: {e}")

                except Exception:
                    pass  # Not HTTP or parsing failed

                writer.write(data)
                await writer.drain()

                session.bytes_sent += len(data)
                session.requests_count += 1

        except Exception as e:
            logger.debug(f"Client to server forwarding error: {e}")
        finally:
            session.end_time = datetime.now().isoformat()

    async def _forward_server_to_client(self, reader: asyncio.StreamReader,
                                        writer: asyncio.StreamWriter,
                                        session: DecryptedSession):
        """Forward data from server to client."""
        try:
            while True:
                data = await reader.read(8192)

                if not data:
                    break

                # Try to parse HTTP response
                try:
                    response_data = self._parse_http_response(data)
                    if response_data:
                        response = DecryptedResponse(
                            session_id=session.session_id,
                            timestamp=datetime.now().isoformat(),
                            **response_data
                        )

                        # Trigger callbacks
                        for callback in self._on_response:
                            try:
                                callback(response)
                            except Exception as e:
                                logger.error(f"Response callback error: {e}")

                except Exception:
                    pass  # Not HTTP or parsing failed

                writer.write(data)
                await writer.drain()

                session.bytes_received += len(data)

        except Exception as e:
            logger.debug(f"Server to client forwarding error: {e}")
        finally:
            session.end_time = datetime.now().isoformat()

    def _parse_http_request(self, data: bytes) -> Optional[Dict]:
        """Parse HTTP request from raw bytes."""
        try:
            text = data.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')

            if not lines:
                return None

            # Parse request line
            request_line = lines[0]
            parts = request_line.split(' ')

            if len(parts) < 2:
                return None

            method, url = parts[0], parts[1]

            # Parse headers
            headers = {}
            body_start = 0

            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

            # Extract body
            body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else None

            # Extract query params
            query_params = {}
            if '?' in url:
                path, query = url.split('?', 1)
                for param in query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        query_params[key] = value

            return {
                'method': method,
                'url': url,
                'headers': headers,
                'body': body,
                'query_params': query_params
            }

        except Exception:
            return None

    def _parse_http_response(self, data: bytes) -> Optional[Dict]:
        """Parse HTTP response from raw bytes."""
        try:
            text = data.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')

            if not lines:
                return None

            # Parse status line
            status_line = lines[0]
            parts = status_line.split(' ')

            if len(parts) < 2:
                return None

            status_code = int(parts[1])

            # Parse headers
            headers = {}
            body_start = 0

            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

            # Get content length
            content_length = 0
            if 'content-length' in headers:
                content_length = int(headers['content-length'])

            return {
                'status_code': status_code,
                'headers': headers,
                'body': None,  # Don't include body in summary
                'content_length': content_length
            }

        except Exception:
            return None

    def get_sessions(self) -> List[DecryptedSession]:
        """Get all SSL sessions."""
        return list(self._sessions.values())

    def get_session(self, session_id: str) -> Optional[DecryptedSession]:
        """Get a specific SSL session."""
        return self._sessions.get(session_id)

    def get_ca_certificate_path(self) -> str:
        """Get the path to the CA certificate for installation."""
        return str(self.ca._ca_cert_path)

    def get_statistics(self) -> Dict:
        """Get decryption statistics."""
        sessions = list(self._sessions.values())

        return {
            'total_sessions': len(sessions),
            'active_sessions': sum(1 for s in sessions if s.end_time is None),
            'successful_decryptions': sum(1 for s in sessions if s.status == DecryptionStatus.SUCCESS),
            'failed_decryptions': sum(1 for s in sessions if s.status != DecryptionStatus.SUCCESS),
            'total_bytes_processed': sum(s.bytes_sent + s.bytes_received for s in sessions),
            'certificates_generated': len(self._cert_cache),
            'hostname_blocklist_size': len(self._hostname_blocklist)
        }


class SSLInspector:
    """
    High-level SSL/TLS traffic inspector.
    Provides simpler interface for SSL inspection operations.
    """

    def __init__(self, config):
        """Initialize SSL inspector."""
        self.config = config
        self._proxy = SSLMITMProxy(config)
        self._decrypted_requests: List[DecryptedRequest] = []
        self._decrypted_responses: List[DecryptedResponse] = []
        self._max_history = config.get('ssl_decrypt.max_history', 10000)

        # Register callbacks
        self._proxy.register_request_callback(self._on_request)
        self._proxy.register_response_callback(self._on_response)

    def _on_request(self, request: DecryptedRequest):
        """Handle decrypted request."""
        self._decrypted_requests.append(request)

        # Trim history
        if len(self._decrypted_requests) > self._max_history:
            self._decrypted_requests = self._decrypted_requests[-self._max_history:]

        logger.debug(f"Decrypted request: {request.method} {request.url}")

    def _on_response(self, response: DecryptedResponse):
        """Handle decrypted response."""
        self._decrypted_responses.append(response)

        # Trim history
        if len(self._decrypted_responses) > self._max_history:
            self._decrypted_responses = self._decrypted_responses[-self._max_history:]

        logger.debug(f"Decrypted response: {response.status_code}")

    async def start_inspection(self):
        """Start SSL inspection."""
        await self._proxy.start()

    async def stop_inspection(self):
        """Stop SSL inspection."""
        await self._proxy.stop()

    def get_decrypted_traffic(self, limit: int = 100) -> Dict[str, List]:
        """Get recent decrypted traffic."""
        return {
            'requests': [r.to_dict() for r in self._decrypted_requests[-limit:]],
            'responses': [r.to_dict() for r in self._decrypted_responses[-limit:]]
        }

    def get_ca_certificate(self) -> bytes:
        """Get the CA certificate for client installation."""
        return self._proxy.get_ca_certificate()

    def add_hostname_blocklist(self, hostname: str):
        """Add hostname to blocklist."""
        self._proxy._hostname_blocklist.add(hostname)
        logger.info(f"Added hostname to blocklist: {hostname}")

    def remove_hostname_blocklist(self, hostname: str):
        """Remove hostname from blocklist."""
        self._proxy._hostname_blocklist.discard(hostname)

    def get_statistics(self) -> Dict:
        """Get inspection statistics."""
        proxy_stats = self._proxy.get_statistics()

        return {
            **proxy_stats,
            'requests_captured': len(self._decrypted_requests),
            'responses_captured': len(self._decrypted_responses)
        }

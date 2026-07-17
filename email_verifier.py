import hashlib
import re
import socket
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

import dns.resolver
import requests


DEFAULT_DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "10minutemail.com",
    "tempmail.com",
    "trashmail.com",
    "guerrillamail.com",
    "maildrop.cc",
    "mailnesia.com",
    "yopmail.com",
    "sharklasers.com",
    "getnada.com",
}


class EmailVerificationEngine:
    """Production-ready email verification engine with layered checks."""

    def __init__(
        self,
        sender_email: str,
        helo_domain: str,
        timeout: float = 5.0,
        max_retries: int = 2,
        request_timeout: float = 3.0,
        disposable_domains: Optional[set] = None,
    ) -> None:
        if not sender_email or "@" not in sender_email:
            raise ValueError("sender_email must be a valid email address")
        if not helo_domain:
            raise ValueError("helo_domain must be provided")

        self.sender_email = sender_email
        self.helo_domain = helo_domain
        self.timeout = timeout
        self.max_retries = max_retries
        self.request_timeout = request_timeout
        self.disposable_domains = set(disposable_domains or DEFAULT_DISPOSABLE_DOMAINS)
        self.syntax_pattern = re.compile(
            r"^(?=.{1,254}$)(?=.{1,64}@)(?!\.)(?!.*\.\.)([A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?)@"
            r"(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$"
        )

    def verify_email(self, email: str) -> Dict[str, object]:
        normalized_email = email.strip().lower()
        context_logs: List[Dict[str, object]] = []
        social_profile_metadata: Dict[str, object] = {
            "social_identity_verified": False,
            "source": None,
            "hash": None,
            "status_code": None,
            "details": None,
        }

        syntax_ok = self._validate_syntax(normalized_email, context_logs)
        if not syntax_ok:
            return self._build_result(
                "Invalid",
                "Email format failed syntax validation",
                "Tier 1 - Syntax Validation",
                context_logs,
                social_profile_metadata,
            )

        disposable_or_gibberish = self._check_disposable_and_gibberish(normalized_email, context_logs)
        if disposable_or_gibberish[0]:
            return self._build_result(
                "Invalid",
                disposable_or_gibberish[1],
                "Tier 2 - Gibberish & Disposable Filter",
                context_logs,
                social_profile_metadata,
            )

        mx_hosts = self._resolve_mx_records(normalized_email, context_logs)
        if not mx_hosts:
            return self._build_result(
                "Invalid",
                "No active MX records were found for the domain",
                "Tier 3 - Active Domain & MX Lookup",
                context_logs,
                social_profile_metadata,
            )

        social_profile_metadata = self._perform_social_graph_check(normalized_email, context_logs)

        final_status = "Invalid"
        reason = "Mailbox could not be verified"
        verification_tier = "Tier 4 - SMTP Connection Handshake"

        catch_all_detected = False
        full_inbox_detected = False

        for host in mx_hosts:
            connection_ok = self._smtp_connection_handshake(host, context_logs)
            if not connection_ok:
                continue

            try:
                catch_all_detected = self._audit_catch_all_policy(host, normalized_email, context_logs)
                if catch_all_detected:
                    final_status = "Risky"
                    reason = "The domain appears to accept arbitrary addresses, indicating a catch-all policy"
                    verification_tier = "Tier 7 - Catch-All Policy Audit"
                    break

                mailbox_status, mailbox_reason = self._verify_mailbox(host, normalized_email, context_logs)
                if mailbox_status == "Valid":
                    final_status = "Valid"
                    reason = mailbox_reason
                    verification_tier = "Tier 6 - Mailbox Verification & Full Inbox Extraction"
                    break

                if mailbox_status == "Risky (Full)":
                    final_status = "Risky (Full)"
                    reason = mailbox_reason
                    verification_tier = "Tier 6 - Mailbox Verification & Full Inbox Extraction"
                    full_inbox_detected = True
                    break

                reason = mailbox_reason
                verification_tier = "Tier 6 - Mailbox Verification & Full Inbox Extraction"
            except Exception as exc:  # pragma: no cover - defensive branch
                context_logs.append(
                    {
                        "layer": 6,
                        "event": "smtp_exception",
                        "passed": False,
                        "details": f"SMTP verification raised an exception: {exc}",
                    }
                )
                reason = f"SMTP verification failed: {exc}"
                verification_tier = "Tier 6 - Mailbox Verification & Full Inbox Extraction"

        if final_status == "Invalid" and full_inbox_detected:
            final_status = "Risky (Full)"

        return self._build_result(
            final_status,
            reason,
            verification_tier,
            context_logs,
            social_profile_metadata,
        )

    def verify_batch(self, emails: List[str], max_workers: Optional[int] = None) -> List[Dict[str, object]]:
        if not emails:
            return []

        worker_count = max_workers or min(8, len(emails))
        results: List[Dict[str, object]] = []
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_map = {executor.submit(self.verify_email, email): email for email in emails}
            for future in as_completed(future_map):
                results.append(future.result())
        return results

    def _validate_syntax(self, email: str, context_logs: List[Dict[str, object]]) -> bool:
        is_valid = bool(self.syntax_pattern.match(email))
        context_logs.append(
            {
                "layer": 1,
                "event": "syntax_validation",
                "passed": is_valid,
                "details": email,
            }
        )
        return is_valid

    def _check_disposable_and_gibberish(self, email: str, context_logs: List[Dict[str, object]]) -> Tuple[bool, str]:
        local_part, domain = email.split("@", 1)
        if domain in self.disposable_domains:
            context_logs.append(
                {
                    "layer": 2,
                    "event": "disposable_domain",
                    "passed": False,
                    "details": domain,
                }
            )
            return True, "The domain is a known disposable or temporary provider"

        gibberish = self._looks_like_gibberish(local_part)
        if gibberish:
            context_logs.append(
                {
                    "layer": 2,
                    "event": "gibberish_pattern",
                    "passed": False,
                    "details": local_part,
                }
            )
            return True, "The local-part appears to be auto-generated gibberish"

        context_logs.append(
            {
                "layer": 2,
                "event": "disposable_and_gibberish_filter",
                "passed": True,
                "details": "Passed disposable and gibberish heuristics",
            }
        )
        return False, ""

    def _looks_like_gibberish(self, local_part: str) -> bool:
        if len(local_part) < 8:
            return False
        if not re.fullmatch(r"[a-z0-9]+", local_part):
            return False
        counts = {}
        for char in local_part:
            counts[char] = counts.get(char, 0) + 1
        entropy = 0.0
        total = len(local_part)
        for count in counts.values():
            p = count / total
            entropy -= p * (p and __import__("math").log2(p))
        return entropy >= 3.6 and (local_part.isalnum() and not re.search(r"[aeiou]{2,}", local_part))

    def _resolve_mx_records(self, email: str, context_logs: List[Dict[str, object]]) -> List[str]:
        _, domain = email.split("@", 1)
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        try:
            answers = list(resolver.resolve(domain, "MX"))
            ranked_hosts = []
            for answer in answers:
                ranked_hosts.append((int(answer.preference), str(answer.exchange).rstrip(".")))
            ranked_hosts.sort(key=lambda item: item[0])
            hosts = [host for _, host in ranked_hosts]
            context_logs.append(
                {
                    "layer": 3,
                    "event": "mx_lookup",
                    "passed": bool(hosts),
                    "details": hosts,
                }
            )
            return hosts
        except dns.resolver.NXDOMAIN:
            context_logs.append(
                {
                    "layer": 3,
                    "event": "mx_lookup",
                    "passed": False,
                    "details": "Domain does not exist",
                }
            )
            return []
        except dns.exception.DNSException as exc:
            context_logs.append(
                {
                    "layer": 3,
                    "event": "mx_lookup",
                    "passed": False,
                    "details": f"DNS lookup failed: {exc}",
                }
            )
            return []

    def _smtp_connection_handshake(self, host: str, context_logs: List[Dict[str, object]]) -> bool:
        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            sock: Optional[socket.socket] = None
            try:
                sock = socket.create_connection((host, 25), timeout=self.timeout)
                sock.settimeout(self.timeout)
                banner = self._read_response(sock)
                if not banner[0] or banner[0] < 200:
                    raise RuntimeError(f"Unexpected banner from {host}: {banner}")

                ehlo_code, ehlo_msg = self._send_command(sock, f"EHLO {self.helo_domain}")
                if ehlo_code >= 500:
                    helo_code, helo_msg = self._send_command(sock, f"HELO {self.helo_domain}")
                    if helo_code < 200 or helo_code >= 400:
                        raise RuntimeError(f"HELO failed for {host}: {helo_code} {helo_msg}")
                elif ehlo_code >= 400:
                    raise RuntimeError(f"EHLO failed for {host}: {ehlo_code} {ehlo_msg}")

                context_logs.append(
                    {
                        "layer": 4,
                        "event": "smtp_handshake",
                        "passed": True,
                        "details": f"Connected to {host}",
                    }
                )
                return True
            except (socket.timeout, ConnectionRefusedError, OSError) as exc:
                last_error = exc
                if attempt < self.max_retries:
                    context_logs.append(
                        {
                            "layer": 4,
                            "event": "smtp_retry",
                            "passed": False,
                            "details": f"Retrying {host} ({attempt + 1}/{self.max_retries + 1}): {exc}",
                        }
                    )
                else:
                    context_logs.append(
                        {
                            "layer": 4,
                            "event": "smtp_handshake",
                            "passed": False,
                            "details": f"Failed to connect to {host}: {exc}",
                        }
                    )
            finally:
                if sock is not None:
                    try:
                        self._send_command(sock, "QUIT")
                    except Exception:
                        pass
                    sock.close()

        if last_error is not None:
            return False
        return False

    def _audit_catch_all_policy(self, host: str, email: str, context_logs: List[Dict[str, object]]) -> bool:
        domain = email.split("@", 1)[1]
        random_address = f"{uuid.uuid4().hex}@{domain}"
        context_logs.append(
            {
                "layer": 7,
                "event": "catch_all_probe",
                "passed": True,
                "details": f"Probing {host} with {random_address}",
            }
        )

        sock: Optional[socket.socket] = None
        try:
            sock = socket.create_connection((host, 25), timeout=self.timeout)
            sock.settimeout(self.timeout)
            self._read_response(sock)
            self._send_command(sock, f"EHLO {self.helo_domain}")
            code, message = self._send_command(sock, f"RCPT TO:<{random_address}>")
            self._send_command(sock, "RSET")
            self._send_command(sock, "QUIT")
            accepted = code in {250, 251}
            context_logs.append(
                {
                    "layer": 7,
                    "event": "catch_all_result",
                    "passed": accepted,
                    "details": f"RCPT TO result: {code} {message}",
                }
            )
            return accepted
        except Exception as exc:
            context_logs.append(
                {
                    "layer": 7,
                    "event": "catch_all_result",
                    "passed": False,
                    "details": f"Catch-all audit failed: {exc}",
                }
            )
            return False
        finally:
            if sock is not None:
                sock.close()

    def _verify_mailbox(self, host: str, email: str, context_logs: List[Dict[str, object]]) -> Tuple[str, str]:
        sock: Optional[socket.socket] = None
        try:
            sock = socket.create_connection((host, 25), timeout=self.timeout)
            sock.settimeout(self.timeout)
            self._read_response(sock)
            self._send_command(sock, f"EHLO {self.helo_domain}")
            self._send_command(sock, f"MAIL FROM:<{self.sender_email}>")
            code, message = self._send_command(sock, f"RCPT TO:<{email}>")
            self._send_command(sock, "RSET")
            self._send_command(sock, "QUIT")

            response_text = f"{code} {message}".lower()
            if code in {250, 251}:
                context_logs.append(
                    {
                        "layer": 6,
                        "event": "mailbox_verified",
                        "passed": True,
                        "details": f"Mailbox accepted by {host}: {code} {message}",
                    }
                )
                return "Valid", "Mailbox exists and accepted the recipient address"

            if code in {452, 552, 422} or any(keyword in response_text for keyword in ["mailbox full", "quota exceeded", "over quota"]):
                context_logs.append(
                    {
                        "layer": 6,
                        "event": "full_inbox",
                        "passed": False,
                        "details": f"Server reported a full inbox condition: {code} {message}",
                    }
                )
                return "Risky (Full)", "The mailbox appears to be full or over quota"

            context_logs.append(
                {
                    "layer": 6,
                    "event": "mailbox_rejected",
                    "passed": False,
                    "details": f"Mailbox rejected by {host}: {code} {message}",
                }
            )
            return "Invalid", f"The mailbox was rejected: {code} {message}"
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            context_logs.append(
                {
                    "layer": 6,
                    "event": "mailbox_rejected",
                    "passed": False,
                    "details": f"SMTP verification failed: {exc}",
                }
            )
            return "Invalid", f"SMTP verification failed: {exc}"
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def _perform_social_graph_check(self, email: str, context_logs: List[Dict[str, object]]) -> Dict[str, object]:
        hash_value = hashlib.md5(email.encode("utf-8")).hexdigest()
        url = f"https://www.gravatar.com/{hash_value}.json?d=404"
        try:
            response = requests.get(url, timeout=self.request_timeout)
            status_code = response.status_code
            if status_code == 200:
                context_logs.append(
                    {
                        "layer": 0,
                        "event": "social_graph_check",
                        "passed": True,
                        "details": f"Gravatar profile identified for {email}",
                    }
                )
                return {
                    "social_identity_verified": True,
                    "source": "gravatar",
                    "hash": hash_value,
                    "status_code": status_code,
                    "details": "A public Gravatar profile was found",
                }
            context_logs.append(
                {
                    "layer": 0,
                    "event": "social_graph_check",
                    "passed": False,
                    "details": f"No Gravatar profile found: HTTP {status_code}",
                }
            )
            return {
                "social_identity_verified": False,
                "source": "gravatar",
                "hash": hash_value,
                "status_code": status_code,
                "details": "No public Gravatar profile was returned",
            }
        except requests.RequestException as exc:
            context_logs.append(
                {
                    "layer": 0,
                    "event": "social_graph_check",
                    "passed": False,
                    "details": f"Social graph request failed: {exc}",
                }
            )
            return {
                "social_identity_verified": False,
                "source": "gravatar",
                "hash": hash_value,
                "status_code": None,
                "details": f"Social graph request failed: {exc}",
            }

    def _read_response(self, sock: socket.socket) -> Tuple[int, str]:
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if b"\n" in chunk:
                break
        text = response.decode("utf-8", "ignore").strip()
        if not text:
            return 0, ""
        code = int(text[:3]) if text[:3].isdigit() else 0
        message = text[4:] if len(text) > 4 else ""
        return code, message

    def _send_command(self, sock: socket.socket, command: str) -> Tuple[int, str]:
        sock.sendall(f"{command}\r\n".encode("ascii"))
        return self._read_response(sock)

    def _build_result(
        self,
        status: str,
        reason: str,
        verification_tier: str,
        context_logs: List[Dict[str, object]],
        social_profile_metadata: Dict[str, object],
    ) -> Dict[str, object]:
        return {
            "status": status,
            "reason": reason,
            "verification_tier": verification_tier,
            "context_logs": context_logs,
            "social_profile_metadata": social_profile_metadata,
        }


if __name__ == "__main__":
    engine = EmailVerificationEngine(
        sender_email="sender@example.com",
        helo_domain="example.com",
        timeout=3.0,
        max_retries=1,
        request_timeout=2.0,
    )
    batch_emails = [
        "invalid-email",
        "user@mailinator.com",
        "someone@outlook.com",
        "test@domain.invalid",
        "jane.doe@example.com",
    ]
    results = engine.verify_batch(batch_emails, max_workers=3)
    for result in results:
        print(result["status"], result["reason"], result["verification_tier"])

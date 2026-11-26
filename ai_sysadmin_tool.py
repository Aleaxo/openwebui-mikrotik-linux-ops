"""
title: AI SysAdmin & SecOps SSH Tool
author: aleax
description: Controlled SSH access to MikroTik RouterOS and Linux nodes + read-only IMAP DMARC auditing.
version: 1.0.1
requirements: paramiko, pydantic
"""

import email
from email.header import decode_header
import gzip
import imaplib
import io
import json
import ssl
import zipfile
import paramiko
from pydantic import BaseModel, Field


class Tools:

    class Valves(BaseModel):
        KEY_PATH: str = Field(
            default="/app/backend/data/id_ed25519",
            description="Path to the Ed25519 private SSH key inside the Open WebUI container",
        )
        SERVERS_JSON: str = Field(
            default=json.dumps(
                {
                    "mikrotik": {
                        "ip": "192.0.2.1",
                        "user": "ai-ops",
                        "type": "mikrotik",
                    },
                    "vds1": {
                        "ip": "198.51.100.10",
                        "user": "ai-ops",
                        "type": "linux",
                    },
                    "node1": {
                        "ip": "192.0.2.20",
                        "user": "ai-ops",
                        "type": "linux",
                    },
                },
                indent=2,
            ),
            description="JSON map of managed infrastructure nodes",
        )
        IMAP_SERVER: str = Field(
            default="192.0.2.30",
            description="Mail server IP or hostname for DMARC/postmaster auditing",
        )
        IMAP_PORT: int = Field(default=993, description="IMAP SSL port")
        MAIL_USER: str = Field(
            default="postmaster@example.com",
            description="Postmaster mailbox address",
        )
        MAIL_PASS: str = Field(
            default="CHANGE_ME",
            description="IMAP application password",
        )

    def __init__(self):
        self.valves = self.Valves()

    def _get_servers(self) -> dict:
        try:
            return json.loads(self.valves.SERVERS_JSON)
        except Exception:
            return {}
    def run_server_command(self, target: str = "", command: str = "") -> str:
        """
        Executes a CLI command over SSH on a configured Linux server or MikroTik router.
        :param target: Node alias from SERVERS_JSON (e.g., 'mikrotik', 'vds1', 'node1').
        :param command: Exact Linux shell or MikroTik RouterOS CLI command to execute.
        """
        servers = self._get_servers()
        if target not in servers:
            return f"Error: Unknown target '{target}'. Available targets: {', '.join(servers.keys())}"
        if not command.strip():
            return "Error: Command cannot be empty."

        node = servers[target]
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            key = paramiko.Ed25519Key.from_private_key_file(
                self.valves.KEY_PATH
            )
            client.connect(
                hostname=node["ip"],
                username=node["user"],
                pkey=key,
                timeout=10,
                banner_timeout=10,
            )
            _, stdout, stderr = client.exec_command(command, timeout=25)
            out = stdout.read().decode("utf-8", errors="ignore").strip()
            err = stderr.read().decode("utf-8", errors="ignore").strip()
            result = out if out else err
            return (
                result[:12000]
                if result
                else "(Command executed with empty output)"
            )
        except Exception as e:
            return f"SSH execution error on {target}: {e}"
        finally:
            client.close()

    def get_mikrotik_address_lists(self, list_name: str = "") -> str:
        """
        Safely counts or inspects firewall address-list entries on MikroTik without hanging the SSH session.
        :param list_name: Optional firewall address-list name to inspect. Leave empty to list all distinct list names.
        """
        if not list_name:
            cmd = "/ip firewall address-list print terse without-paging"
            raw = self.run_server_command(target="mikrotik", command=cmd)
            lists = {}
            for line in raw.splitlines():
                for token in line.split():
                    if token.startswith("list="):
                        name = token.split("=", 1)[1]
                        lists[name] = lists.get(name, 0) + 1
            if not lists:
                return raw
            return "MikroTik address-lists summary:\n" + "\n".join(
                [f"- {k}: {v} entries" for k, v in sorted(lists.items())]
            )

        safe_list = list_name.replace('"', "")
        count_cmd = (
            f'/ip firewall address-list print count-only where list="{safe_list}"'
        )
        count_str = self.run_server_command(
            target="mikrotik", command=count_cmd
        )

        detail_cmd = f'/ip firewall address-list print terse without-paging where list="{safe_list}"'
        entries = self.run_server_command(target="mikrotik", command=detail_cmd)
        return (
            f"List '{safe_list}' total count: {count_str}\n{entries[:10000]}"
        )
    def _decode_str(self, s: str) -> str:
        if not s:
            return ""
        parts = decode_header(s)
        res = []
        for content, enc in parts:
            if isinstance(content, bytes):
                res.append(content.decode(enc or "utf-8", errors="ignore"))
            else:
                res.append(str(content))
        return "".join(res)

    def check_postmaster_mail(
        self, limit: int = 5, unread_only: bool = False
    ) -> str:
        """
        Reads recent emails from the postmaster mailbox in READ-ONLY mode and unpacks XML/GZ/ZIP DMARC reports.
        :param limit: Number of recent emails to fetch (default 5, max 15).
        :param unread_only: If True, fetches only UNSEEN messages.
        """
        limit = min(max(int(limit), 1), 15)
        mail = None
        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

            mail = imaplib.IMAP4_SSL(
                self.valves.IMAP_SERVER,
                self.valves.IMAP_PORT,
                ssl_context=ssl_ctx,
                timeout=15,
            )
            mail.login(self.valves.MAIL_USER, self.valves.MAIL_PASS)
            mail.select("INBOX", readonly=True)

            criteria = "UNSEEN" if unread_only else "ALL"
            status, messages = mail.search(None, criteria)
            if status != "OK" or not messages[0]:
                return f"No messages found in {self.valves.MAIL_USER} ({criteria})."

            msg_ids = messages[0].split()[-limit:]
            msg_ids.reverse()

            report_blocks = []
            for num in msg_ids:
                _, data = mail.fetch(num, "(RFC822)")
                msg = email.message_from_bytes(data[0][1])

                subject = self._decode_str(msg.get("Subject", "No Subject"))
                sender = self._decode_str(msg.get("From", "Unknown"))
                date_str = msg.get("Date", "")

                body_text = ""
                attachments_text = []

                for part in msg.walk():
                    ctype = part.get_content_type()
                    disp = str(part.get("Content-Disposition", ""))
                    filename = self._decode_str(part.get_filename() or "")

                    if (
                        filename
                        or "attachment" in disp
                        or ctype
                        in (
                            "application/gzip",
                            "application/x-gzip",
                            "application/zip",
                            "text/xml",
                            "application/xml",
                        )
                    ):
                        payload = part.get_payload(decode=True)
                        if not payload:
                            continue
                        try:
                            if filename.endswith(".gz") or "gzip" in ctype:
                                xml_data = gzip.decompress(payload).decode(
                                    "utf-8", errors="ignore"
                                )
                                attachments_text.append(
                                    f"[Attachment GZ: {filename}]\n{xml_data[:3500]}"
                                )
                            elif filename.endswith(".zip") or "zip" in ctype:
                                with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                                    for zname in zf.namelist():
                                        xml_data = zf.read(zname).decode(
                                            "utf-8", errors="ignore"
                                        )
                                        attachments_text.append(
                                            f"[Attachment ZIP/{zname}]\n{xml_data[:3500]}"
                                        )
                            elif filename.endswith(".xml") or "xml" in ctype:
                                xml_data = payload.decode(
                                    "utf-8", errors="ignore"
                                )
                                attachments_text.append(
                                    f"[Attachment XML: {filename}]\n{xml_data[:3500]}"
                                )
                        except Exception as ex:
                            attachments_text.append(
                                f"[Attachment error {filename}: {ex}]"
                            )
                        continue

                    if ctype == "text/plain" and not body_text:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_text = payload.decode(
                                part.get_content_charset() or "utf-8",
                                errors="ignore",
                            ).strip()

                block = (
                    f"=== EMAIL ===\n"
                    f"Date: {date_str}\n"
                    f"From: {sender}\n"
                    f"Subject: {subject}\n"
                    f"Body: {body_text[:1500] if body_text else '(empty / HTML only)'}\n"
                )
                if attachments_text:
                    block += "\n".join(attachments_text) + "\n"
                report_blocks.append(block)

            return "\n".join(report_blocks)[:12000]
        except Exception as e:
            return f"IMAP error for {self.valves.MAIL_USER}: {e}"
        finally:
            if mail:
                try:
                    mail.logout()
                except Exception:
                    pass

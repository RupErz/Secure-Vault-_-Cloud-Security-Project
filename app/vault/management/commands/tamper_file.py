"""DEMO HELPER - deliberately corrupts a stored ciphertext.

    python manage.py tamper_file <file_id>                 # flip 8 bytes at offset 100
    python manage.py tamper_file <file_id> --offset 5000 --count 1
    python manage.py tamper_file <file_id> --truncate 16   # chop bytes off the end
    (run the same flip command again to restore: XOR 0xFF twice is the identity)

Then try to download the file: AES-GCM authentication fails and the app refuses to
send anything. Remove this command before any real deployment.
"""
import os
import uuid

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Flip bytes in a stored ciphertext to demonstrate tamper detection (DEMO ONLY)."

    def add_arguments(self, parser):
        parser.add_argument("file_id", help="UUID of the file (see the file details page)")
        parser.add_argument("--offset", type=int, default=100, help="byte offset to start flipping (default 100)")
        parser.add_argument("--count", type=int, default=8, help="how many bytes to flip (default 8)")
        parser.add_argument("--truncate", type=int, default=0, help="instead: remove this many bytes from the end")

    def handle(self, *args, **opts):
        try:
            fid = uuid.UUID(opts["file_id"])
        except ValueError:
            raise CommandError("file_id must be a UUID")
        path = os.path.join(settings.FILE_STORAGE_DIR, f"{fid}.enc")
        if not os.path.exists(path):
            raise CommandError(f"No stored ciphertext at {path}")
        size = os.path.getsize(path)

        if opts["truncate"]:
            n = min(opts["truncate"], size)
            with open(path, "r+b") as fh:
                fh.truncate(size - n)
            self.stdout.write(self.style.WARNING(f"Truncated {n} bytes from the end of {path} ({size} -> {size - n})."))
            return

        offset, count = opts["offset"], opts["count"]
        if offset < 0 or offset >= size:
            raise CommandError(f"offset must be within the file (size {size})")
        count = min(count, size - offset)
        with open(path, "r+b") as fh:
            fh.seek(offset)
            before = fh.read(count)
            after = bytes(b ^ 0xFF for b in before)
            fh.seek(offset)
            fh.write(after)
        self.stdout.write(self.style.WARNING(f"Tampered {path}"))
        self.stdout.write(f"  offset {offset}, {count} byte(s)")
        self.stdout.write(f"  before: {before.hex()}")
        self.stdout.write(f"  after:  {after.hex()}")
        self.stdout.write("Now try downloading it - the app must refuse. Run the same command again to undo.")

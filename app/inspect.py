from pathlib import Path
from app.hook import decode_body
print(decode_body(Path("fixtures/event-a.json").read_bytes()))

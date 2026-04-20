import random
from datetime import datetime, timezone

ts = datetime(2025, 9, 22, 19, 39, 2, tzinfo=timezone.utc).timestamp()
seed = int(ts)

random.seed(seed)

charset = "abcdefghijklmnopqrstuvwxyz0123456789"
pwd = "".join(random.choice(charset) for _ in range(15))
print(pwd)

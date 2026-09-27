"""In-memory stand-in for the Upstash Redis REST API (POST a JSON command
array, get {"result": ...}), covering the commands services/store.jac uses."""

import time


class FakeUpstash:
    def __init__(self):
        self.data = {}
        self.expires = {}

    def _alive(self, key):
        if key in self.expires and self.expires[key] <= time.time():
            self.data.pop(key, None)
            self.expires.pop(key, None)
        return key in self.data

    def run(self, cmd):
        op, args = cmd[0].upper(), cmd[1:]
        key = args[0] if args else ""
        alive = self._alive(key)
        if op == "GET":
            return self.data.get(key) if alive else None
        if op == "SET":
            opts = [a.upper() for a in args[2:]]
            if "NX" in opts and alive:
                return None
            self.data[key] = args[1]
            self.expires.pop(key, None)
            if "EX" in opts:
                self.expires[key] = time.time() + int(args[2 + opts.index("EX") + 1])
            return "OK"
        if op == "INCR":
            self.data[key] = str(int(self.data.get(key, "0") if alive else "0") + 1)
            return int(self.data[key])
        if op == "TTL":
            if not alive:
                return -2
            return int(self.expires[key] - time.time()) if key in self.expires else -1
        if op == "RPUSH":
            self.data.setdefault(key, []).append(args[1])
            return len(self.data[key])
        if op == "LTRIM":
            items = self.data.get(key, [])
            start, stop = int(args[1]), int(args[2])
            self.data[key] = items[start:] if stop == -1 else items[start:stop + 1]
            return "OK"
        if op == "LRANGE":
            return list(self.data.get(key, [])) if alive else []
        if op == "HSET":
            self.data.setdefault(key, {})[args[1]] = args[2]
            return 1
        if op == "HGETALL":
            flat = []
            for k, v in (self.data.get(key, {}) if alive else {}).items():
                flat += [k, v]
            return flat
        raise ValueError(f"unsupported command {op}")

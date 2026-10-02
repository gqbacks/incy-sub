#!/usr/bin/env python3
"""Собирает подписку: скачивает ключи, проверяет, определяет страну, переименовывает, публикует."""
import asyncio, base64, json, pathlib, random, re, socket, ssl, sys, time
import urllib.parse as up
import urllib.request as ur
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).parent
DOCS = ROOT / "docs"
DOCS.mkdir(exist_ok=True)

# ---------- настройки ----------
PROFILE_TITLE = "Free Russia VPN"
UPDATE_INTERVAL = 6
MAX_CANDIDATES = 1500      # сколько ключей проверять за запуск
CONCURRENCY = 200
TIMEOUT = 5                # секунд на проверку одного сервера
GEO_LIMIT = 600            # сколько живых серверов определять по странам
MIN_TOTAL = 3              # меньше живых серверов, чем это число: не публиковать
CAPS = {"RU": 5, "DE": 3, "NL": 3, "US": 3, "FI": 3}
OTHER_EACH, OTHER_TOTAL = 1, 4
NAMES = {
    "RU": "Россия", "DE": "Германия", "NL": "Нидерланды", "US": "США", "FI": "Финляндия",
    "FR": "Франция", "GB": "Великобритания", "SE": "Швеция", "PL": "Польша", "KZ": "Казахстан",
    "TR": "Турция", "EE": "Эстония", "LV": "Латвия", "LT": "Литва", "CH": "Швейцария",
    "AT": "Австрия", "CZ": "Чехия", "IT": "Италия", "ES": "Испания", "CA": "Канада",
    "JP": "Япония", "SG": "Сингапур", "AM": "Армения", "GE": "Грузия", "UA": "Украина",
}
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
FLAG_RE = re.compile("[\U0001F1E6-\U0001F1FF]{2}")


def log(*a):
    print(*a, flush=True)


def fetch(url):
    req = ur.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with ur.urlopen(req, timeout=30) as r:
        text = r.read().decode("utf-8", "ignore")
    if "://" not in text:  # возможно, весь файл в Base64
        try:
            pad = "=" * (-len(text.strip()) % 4)
            text = base64.b64decode(text.strip() + pad).decode("utf-8", "ignore")
        except Exception:
            pass
    return text


def parse(line):
    line = line.strip()
    if not line.startswith("vless://"):
        return None
    try:
        p = up.urlsplit(line)
        uid, host, port = p.username, p.hostname, p.port
        if not (uid and host and port and UUID_RE.match(uid) and 0 < port < 65536):
            return None
        q = {k: v[0] for k, v in up.parse_qs(p.query).items()}
        sec = q.get("security", "none")
        if sec not in ("reality", "tls"):
            return None
        if sec == "reality" and not (q.get("pbk") and q.get("sni")):
            return None
        return {"p": p, "q": q, "host": host, "port": port, "uuid": uid, "sec": sec,
                "sni": q.get("sni") or q.get("host") or None, "orig_name": up.unquote(p.fragment)}
    except Exception:
        return None


async def probe(c, sem, ctx):
    async with sem:
        t0 = time.perf_counter()
        try:
            loop = asyncio.get_running_loop()
            infos = await asyncio.wait_for(
                loop.getaddrinfo(c["host"], c["port"], type=socket.SOCK_STREAM), TIMEOUT)
            ip = infos[0][4][0]
            _, w = await asyncio.wait_for(
                asyncio.open_connection(ip, c["port"], ssl=ctx, server_hostname=c["sni"]), TIMEOUT)
            w.close()
            c["ms"], c["ip"] = int((time.perf_counter() - t0) * 1000), ip
            return c
        except Exception:
            return None


async def check_all(cands):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sem = asyncio.Semaphore(CONCURRENCY)
    res = await asyncio.gather(*(probe(c, sem, ctx) for c in cands))
    return [r for r in res if r]


def geolocate(ips):
    out = {}
    ips = list(dict.fromkeys(ips))
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            req = ur.Request("http://ip-api.com/batch?fields=status,countryCode,query",
                             data=json.dumps(chunk).encode(),
                             headers={"Content-Type": "application/json"})
            for d in json.load(ur.urlopen(req, timeout=20)):
                if d.get("status") == "success":
                    out[d["query"]] = d["countryCode"]
        except Exception as e:
            log("geo error:", e)
        time.sleep(4.5)  # лимит бесплатного API: 15 пакетных запросов в минуту
    return out


def flag(cc):
    return "".join(chr(0x1F1E6 + ord(ch) - 65) for ch in cc)


def flag_to_cc(text):
    m = FLAG_RE.search(text or "")
    return "".join(chr(ord(ch) - 0x1F1E6 + 65) for ch in m.group()) if m else None


def main():
    sources = [l.strip() for l in (ROOT / "sources.txt").read_text(encoding="utf-8").splitlines()
               if l.strip() and not l.startswith("#")]
    seen, cands, src_status = set(), [], {}
    for url in sources:
        try:
            n = 0
            for line in fetch(url).splitlines():
                c = parse(line)
                if c:
                    key = (c["host"], c["port"], c["uuid"])
                    if key not in seen:
                        seen.add(key); cands.append(c); n += 1
            src_status[url] = f"ok, новых ключей: {n}"
        except Exception as e:
            src_status[url] = f"ошибка: {e}"
        log(url, "->", src_status[url])

    log("кандидатов:", len(cands))
    if len(cands) > MAX_CANDIDATES:
        cands = random.sample(cands, MAX_CANDIDATES)
    alive = sorted(asyncio.run(check_all(cands)), key=lambda c: c["ms"])
    log("живых:", len(alive))

    alive = alive[:GEO_LIMIT]
    geo = geolocate([c["ip"] for c in alive])
    for c in alive:
        c["cc"] = geo.get(c["ip"]) or flag_to_cc(c["orig_name"])
    alive = [c for c in alive if c["cc"]]

    chosen, counts, other_total = [], {}, 0
    for c in alive:  # уже отсортированы по пингу
        cc = c["cc"]
        if cc in CAPS:
            if counts.get(cc, 0) >= CAPS[cc]:
                continue
        else:
            if counts.get(cc, 0) >= OTHER_EACH or other_total >= OTHER_TOTAL:
                continue
            other_total += 1
        counts[cc] = counts.get(cc, 0) + 1
        c["name"] = f"{flag(cc)} {NAMES.get(cc, cc)} {counts[cc]}"
        chosen.append(c)

    status = {
        "updated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total": len(chosen), "by_country": counts, "russia_count": counts.get("RU", 0),
        "sources": src_status,
    }
    (DOCS / "status.json").write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")

    if len(chosen) < MIN_TOTAL:
        log(f"ОШИБКА: живых серверов {len(chosen)} < {MIN_TOTAL}. Старая подписка сохранена.")
        sys.exit(1)
    if counts.get("RU", 0) == 0:
        log("ВНИМАНИЕ: российских серверов сейчас нет, в подписке только другие страны.")

    links = [up.urlunsplit(c["p"]._replace(fragment=up.quote(c["name"]))) for c in chosen]
    header = [f"#profile-title: {PROFILE_TITLE}", f"#profile-update-interval: {UPDATE_INTERVAL}",
              "#sort-order: ping"]
    (DOCS / "sub").write_text("\n".join(header + links) + "\n", encoding="utf-8")
    (DOCS / "sub.b64").write_text(base64.b64encode("\n".join(links).encode()).decode(), encoding="utf-8")
    rows = "".join(f"<li>{up.unquote(up.quote(c['name']))} ({c['ms']} мс)</li>" for c in chosen)
    (DOCS / "index.html").write_text(
        f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>"
        f"<title>{PROFILE_TITLE}</title><h2>{PROFILE_TITLE}</h2>"
        f"<p>Обновлено: {status['updated_utc']} UTC. Серверов: {len(chosen)}.</p><ul>{rows}</ul>"
        f"<p>Ссылка подписки: <code>./sub</code></p>", encoding="utf-8")
    log("готово:", counts)


if __name__ == "__main__":
    main()

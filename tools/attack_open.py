"""Відкрита карта атаки — автоматичний прогін.

    python tools/attack_open.py                      # contract.json поруч
    python tools/attack_open.py --contract ../team3/contract.json
    python tools/attack_open.py --only 18,19,21      # лише вибрані рядки

Рядки 1–20 — по 1 балу. 21 (гонка на одній заявці) і 22 (гонка за ресурс) рахуються
окремо. Скрипт сам створює потрібні заявки від attacker1 і attacker2. Перед повторним
прогоном 22-го рядка відновіть залишок: python manage.py seed_attack.

Ганяйте його проти себе скільки завгодно: це специфікація, а не іспит.
"""
import argparse
import http.cookiejar
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

from apiclient import Api, _NoRedirect, fire_at_once, is_ok, load_contract

DENIED = (403, 404)
ROWS = {}


def row(number, title, expected):
    def wrap(fn):
        ROWS[number] = (title, expected, fn)
        return fn
    return wrap


class Ctx:
    """Спільні дані прогону: токени, звичайний елемент, чужа заявка."""

    def __init__(self, api):
        self.api = api
        self.t1 = api.token("attacker1")
        self.t2 = api.token("attacker2")
        items = api.items()
        left_field = api.c["left_field"]
        regular = [i for i in items
                   if isinstance(i, dict) and i.get("id") != api.c["race_item"]
                   and isinstance(i.get(left_field), int)]
        if not regular:
            raise SystemExit(f"GET {api.item_path()} не повернув елементів із полем '{left_field}'.")
        self.item = max(regular, key=lambda i: i[left_field])["id"]
        if api.left(self.item) < 10:
            raise SystemExit("Найбільший залишок у каталозі менший за 10 — запустіть seed_attack.")

    def new_order(self, token=None, qty=1, item=None):
        code, data = self.api.create_order(token or self.t1, item or self.item, qty)
        if code not in (200, 201) or not isinstance(data, dict) or "id" not in data:
            raise RuntimeError(f"не вдалося створити заявку: {code} {data}")
        return data["id"]

    def foreign(self):
        return self.new_order(self.t2)


# --- без токена --------------------------------------------------------------

@row(1, "GET каталогу без токена", "200")
def r1(c):
    code, _ = c.api.request("GET", c.api.item_path())
    return code == 200, code


@row(2, "GET заявок без токена", "401")
def r2(c):
    code, _ = c.api.request("GET", c.api.order_path())
    return code == 401, code


@row(3, "POST заявки без токена", "401")
def r3(c):
    code, _ = c.api.request("POST", c.api.order_path(), c.api.order_body(c.item, 1))
    return code == 401, code


@row(4, "confirm без токена", "401")
def r4(c):
    code, _ = c.api.request("POST", c.api.order_path(c.foreign(), "confirm"))
    return code == 401, code


@row(5, "неіснуюча адреса /api/v1/neisnuie/", "404")
def r5(c):
    code, _ = c.api.request("GET", "/api/v1/neisnuie/")
    return code == 404, code


def _admin_login(base, username, password):
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), _NoRedirect)
    url = base + "/admin/login/"
    try:
        html = opener.open(url, timeout=15).read().decode(errors="replace")
    except urllib.error.HTTPError as err:
        return err.code
    match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', html)
    form = urllib.parse.urlencode({
        "username": username, "password": password, "next": "/admin/",
        "csrfmiddlewaretoken": match.group(1) if match else "",
    }).encode()
    req = urllib.request.Request(url, data=form, method="POST", headers={"Referer": url})
    try:
        return opener.open(req, timeout=15).status
    except urllib.error.HTTPError as err:
        return err.code


@row(6, "вхід в /admin/ з admin/admin і admin/1234", "вхід не проходить")
def r6(c):
    codes = [_admin_login(c.api.base, "admin", pw) for pw in ("admin", "1234")]
    # 302 після POST — успішний вхід і редірект в адмінку.
    return 302 not in codes, "/".join(map(str, codes))


# --- зі своїм токеном ----------------------------------------------------------

@row(7, "список заявок attacker1", "чужих немає")
def r7(c):
    foreign = c.foreign()
    code, data = c.api.request("GET", c.api.order_path(), token=c.t1)
    ids = [o.get("id") for o in c.api.as_list(data) if isinstance(o, dict)]
    return code == 200 and foreign not in ids, f"{code}, чужа {'є' if foreign in ids else 'немає'}"


@row(8, "GET чужої заявки", "403/404")
def r8(c):
    code, _ = c.api.request("GET", c.api.order_path(c.foreign()), token=c.t1)
    return code in DENIED, code


@row(9, "PATCH і DELETE чужої заявки", "403/404 обидва")
def r9(c):
    foreign = c.foreign()
    patch, _ = c.api.request("PATCH", c.api.order_path(foreign),
                             {c.api.c["qty_field"]: 2}, token=c.t1)
    delete, _ = c.api.request("DELETE", c.api.order_path(foreign), token=c.t1)
    return patch in DENIED and delete in DENIED, f"{patch}/{delete}"


@row(10, "confirm чужої заявки", "403/404")
def r10(c):
    before = c.api.left(c.item)
    code = c.api.action(c.t1, c.foreign(), "confirm")
    after = c.api.left(c.item)
    return code in DENIED and after == before, f"{code}, залишок {before}→{after}"


@row(11, "\"owner\" чужий у тілі створення", "власник — ви (або 400)")
def r11(c):
    code, data = c.api.request("GET", c.api.order_path(c.foreign()), token=c.t2)
    owner = data.get("owner") if isinstance(data, dict) else None
    owner = owner if isinstance(owner, int) else 1
    code, data = c.api.create_order(c.t1, c.item, 1, owner=owner)
    if code == 400:
        return True, code
    if code not in (200, 201) or not isinstance(data, dict):
        return False, code
    mine, _ = c.api.request("GET", c.api.order_path(data["id"]), token=c.t1)
    theirs, _ = c.api.request("GET", c.api.order_path(data["id"]), token=c.t2)
    return mine == 200 and theirs in DENIED, f"{code}; видно мені {mine}, attacker2 {theirs}"


@row(12, "\"status\": \"confirmed\" у тілі створення", "стан draft (або 400)")
def r12(c):
    before = c.api.left(c.item)
    code, data = c.api.create_order(c.t1, c.item, 1, status="confirmed")
    if code == 400:
        return True, code
    if code not in (200, 201) or not isinstance(data, dict):
        return False, code
    _, got = c.api.request("GET", c.api.order_path(data["id"]), token=c.t1)
    status = got.get("status") if isinstance(got, dict) else None
    after = c.api.left(c.item)
    return status == "draft" and after == before, f"{code}, стан {status}, залишок {before}→{after}"


@row(13, "кількість -5", "400")
def r13(c):
    code, data = c.api.create_order(c.t1, c.item, -5)
    if code == 400:
        return True, code
    note = code
    if code in (200, 201) and isinstance(data, dict):
        before = c.api.left(c.item)
        c.api.action(c.t1, data["id"], "confirm")
        after = c.api.left(c.item)
        if after > before:
            note = f"{code}, ГРУБИЙ ПРОБІЙ: confirm збільшив залишок {before}→{after}"
    return False, note


@row(14, "кількість 0", "400")
def r14(c):
    code, _ = c.api.create_order(c.t1, c.item, 0)
    return code == 400, code


@row(15, "кількість 99999999999999999999", "400")
def r15(c):
    code, _ = c.api.create_order(c.t1, c.item, 99999999999999999999)
    return code == 400, code


@row(16, "заявка на елемент 999999", "400")
def r16(c):
    code, _ = c.api.create_order(c.t1, 999999, 1)
    return code == 400, code


@row(17, "кількість більша за залишок", "400 на створенні або на confirm")
def r17(c):
    before = c.api.left(c.item)
    code, data = c.api.create_order(c.t1, c.item, before + 1)
    if code == 400:
        return True, f"{code} на створенні"
    if code not in (200, 201) or not isinstance(data, dict):
        return False, code
    confirm = c.api.action(c.t1, data["id"], "confirm")
    after = c.api.left(c.item)
    return confirm == 400 and after == before, f"створення {code}, confirm {confirm}, залишок {before}→{after}"


@row(18, "confirm двічі", "2xx, потім 409")
def r18(c):
    order = c.new_order()
    first = c.api.action(c.t1, order, "confirm")
    second = c.api.action(c.t1, order, "confirm")
    return is_ok(first) and second == 409, f"{first}/{second}"


@row(19, "confirm → cancel → cancel", "другий cancel 409, залишок повернувся рівно раз")
def r19(c):
    before = c.api.left(c.item)
    order = c.new_order()
    codes = [c.api.action(c.t1, order, name) for name in ("confirm", "cancel", "cancel")]
    after = c.api.left(c.item)
    ok = is_ok(codes[0]) and is_ok(codes[1]) and codes[2] == 409 and after == before
    return ok, f"{'/'.join(map(str, codes))}, залишок {before}→{after}"


@row(20, "зламаний JSON", "400")
def r20(c):
    code, _ = c.api.request("POST", c.api.order_path(), token=c.t1,
                            raw=('{"%s":' % c.api.c["qty_field"]).encode())
    return code == 400, code


# --- гонки ---------------------------------------------------------------------

@row(21, "Гонка А: 10 одночасних confirm ОДНІЄЇ заявки, 3 раунди",
     "у кожному рівно один 2xx, залишок −1")
def r21(c):
    notes, ok = [], True
    for _ in range(3):
        order = c.new_order()
        before = c.api.left(c.item)
        codes = fire_at_once([lambda: c.api.action(c.t1, order, "confirm")] * 10)
        after = c.api.left(c.item)
        wins = sum(is_ok(x) for x in codes)
        ok &= wins == 1 and after == before - 1
        notes.append(f"{wins}×2xx {before}→{after}")
    return ok, "; ".join(notes)


@row(22, "Гонка Б: різні заявки на елемент race_item, одночасно",
     "успішних рівно стільки, скільки було залишку; залишок 0")
def r22(c):
    item = c.api.c["race_item"]
    stock = c.api.left(item)
    if stock > 10:
        return False, f"залишок race_item {stock} > 10 — дайте елемент із залишком 1"
    orders = []
    for _ in range(stock + 9):
        code, data = c.api.create_order(c.t1, item, 1)
        if code in (200, 201) and isinstance(data, dict):
            orders.append(data["id"])
    if len(orders) <= stock:
        return False, (f"створилось лише {len(orders)} заявок — сервер не приймає заявки понад "
                       "залишок; гонку перевірити нічим, відновіть залишок seed_attack")
    codes = fire_at_once([lambda o=o: c.api.action(c.t1, o, "confirm") for o in orders])
    after = c.api.left(item)
    wins = sum(is_ok(x) for x in codes)
    errors = sum(x >= 500 or x == 0 for x in codes)
    note = f"{len(orders)} заявок, {wins}×2xx, {errors}×5xx, залишок {stock}→{after}"
    return wins == stock and after == 0 and errors == 0, note


# --- додаткові перевірки інваріанта та крайових станів (23–30) ---------------

@row(23, "draft → cancel без попереднього confirm", "2xx, залишок не змінився")
def r23(c):
    before = c.api.left(c.item)
    order = c.new_order()
    code = c.api.action(c.t1, order, "cancel")
    after = c.api.left(c.item)
    return is_ok(code) and after == before, f"{code}, залишок {before}→{after}"


@row(24, "draft → cancel → confirm (кінцевий стан cancelled)", "cancel 2xx, confirm 409")
def r24(c):
    before = c.api.left(c.item)
    order = c.new_order()
    c1 = c.api.action(c.t1, order, "cancel")
    c2 = c.api.action(c.t1, order, "confirm")
    after = c.api.left(c.item)
    return is_ok(c1) and c2 == 409 and after == before, f"{c1}/{c2}, залишок {before}→{after}"


@row(25, "cancel чужої підтвердженої заявки", "403/404, залишок без змін")
def r25(c):
    foreign = c.foreign()
    conf = c.api.action(c.t2, foreign, "confirm")
    if not is_ok(conf):
        return False, f"не вдалося підготувати чужу confirmed-заявку: {conf}"
    locked = c.api.left(c.item)
    code = c.api.action(c.t1, foreign, "cancel")
    after = c.api.left(c.item)
    c.api.action(c.t2, foreign, "cancel")
    return code in DENIED and after == locked, f"{code}, залишок під час спроби {locked}→{after}"


@row(26, "PATCH кількості у confirmed-заявці перед cancel", "інваріант залишку збережено, без 5xx")
def r26(c):
    before = c.api.left(c.item)
    order = c.new_order(qty=1)
    conf = c.api.action(c.t1, order, "confirm")
    if not is_ok(conf):
        return False, f"confirm повернув {conf}"
    patch, _ = c.api.request("PATCH", c.api.order_path(order),
                             {c.api.c["qty_field"]: 5}, token=c.t1)
    canc = c.api.action(c.t1, order, "cancel")
    after = c.api.left(c.item)
    ok = 400 <= patch < 500 and is_ok(canc) and after == before
    return ok, f"PATCH {patch}, cancel {canc}, залишок {before}→{after}"


@row(27, "DELETE підтвердженої заявки (перевірка втрати ресурсу)", "4xx (заборонено) або повернення ресурсу")
def r27(c):
    before = c.api.left(c.item)
    order = c.new_order(qty=1)
    conf = c.api.action(c.t1, order, "confirm")
    if not is_ok(conf):
        return False, f"confirm повернув {conf}"
    delete, _ = c.api.request("DELETE", c.api.order_path(order), token=c.t1)
    if 400 <= delete < 500:
        c.api.action(c.t1, order, "cancel")
        after = c.api.left(c.item)
        return after == before, f"DELETE {delete} (заблоковано), залишок після cancel {before}→{after}"
    after = c.api.left(c.item)
    return is_ok(delete) and after == before, f"DELETE {delete}, залишок {before}→{after}"


@row(28, "PATCH status=\"confirmed\" на чернетці", "стан лишився draft (або 4xx), залишок без змін")
def r28(c):
    before = c.api.left(c.item)
    order = c.new_order(qty=1)
    patch, _ = c.api.request("PATCH", c.api.order_path(order),
                             {"status": "confirmed"}, token=c.t1)
    after = c.api.left(c.item)
    if 400 <= patch < 500:
        return after == before, f"PATCH {patch}, залишок {before}→{after}"
    _, got = c.api.request("GET", c.api.order_path(order), token=c.t1)
    st = got.get("status") if isinstance(got, dict) else None
    return st == "draft" and after == before, f"PATCH {patch}, стан {st}, залишок {before}→{after}"


@row(29, "спроба зміни каталогу зі звичайним токеном (POST/PATCH/DELETE)", "усі 4xx, залишок без змін")
def r29(c):
    before = c.api.left(c.item)
    p1, _ = c.api.request("POST", c.api.item_path(), {c.api.c["left_field"]: 10}, token=c.t1)
    p2, _ = c.api.request("PATCH", c.api.item_path(c.item), {c.api.c["left_field"]: 999}, token=c.t1)
    p3, _ = c.api.request("DELETE", c.api.item_path(c.item), token=c.t1)
    after = c.api.left(c.item)
    ok = all(400 <= x < 500 for x in (p1, p2, p3)) and after == before
    return ok, f"{p1}/{p2}/{p3}, залишок {before}→{after}"


@row(30, "Гонка В: 10 одночасних cancel ОДНІЄЇ підтвердженої заявки",
     "рівно один 2xx, без 5xx, залишок повернувся рівно раз")
def r30(c):
    before = c.api.left(c.item)
    order = c.new_order(qty=1)
    conf = c.api.action(c.t1, order, "confirm")
    if not is_ok(conf):
        return False, f"confirm повернув {conf}"
    codes = fire_at_once([lambda: c.api.action(c.t1, order, "cancel")] * 10)
    after = c.api.left(c.item)
    wins = sum(is_ok(x) for x in codes)
    errors = sum(x >= 500 or x == 0 for x in codes)
    return wins == 1 and errors == 0 and after == before, f"{wins}×2xx, {errors}×5xx, залишок {before}→{after}"


@row(31, "cancel без токена", "401")
def r31(c):
    code, _ = c.api.request("POST", c.api.order_path(c.foreign(), "cancel"))
    return code == 401, code


@row(32, "GET замість POST на confirm і cancel", "405/405")
def r32(c):
    order = c.new_order()
    g1, _ = c.api.request("GET", c.api.order_path(order, "confirm"), token=c.t1)
    g2, _ = c.api.request("GET", c.api.order_path(order, "cancel"), token=c.t1)
    return g1 == 405 and g2 == 405, f"{g1}/{g2}"


@row(33, "PATCH кількості на 0 і -3 у чернетці + confirm", "обидва PATCH 400, залишок не зріс")
def r33(c):
    before = c.api.left(c.item)
    order = c.new_order(qty=1)
    p0, _ = c.api.request("PATCH", c.api.order_path(order), {c.api.c["qty_field"]: 0}, token=c.t1)
    pm, _ = c.api.request("PATCH", c.api.order_path(order), {c.api.c["qty_field"]: -3}, token=c.t1)
    c.api.action(c.t1, order, "confirm")
    c.api.action(c.t1, order, "cancel")
    after = c.api.left(c.item)
    return p0 == 400 and pm == 400 and after == before, f"PATCH {p0}/{pm}, залишок {before}→{after}"


@row(34, "PATCH підміни товару у confirmed-заявці перед cancel", "інваріант обох товарів збережено")
def r34(c):
    items = [i["id"] for i in c.api.items() if isinstance(i, dict) and "id" in i and i["id"] != c.item]
    other = items[0] if items else c.item
    b1, b2 = c.api.left(c.item), c.api.left(other)
    order = c.new_order(qty=1, item=c.item)
    if not is_ok(c.api.action(c.t1, order, "confirm")):
        return False, "не вдалося підтвердити заявку"
    patch, _ = c.api.request("PATCH", c.api.order_path(order), {c.api.c["item_field"]: other}, token=c.t1)
    c.api.action(c.t1, order, "cancel")
    a1, a2 = c.api.left(c.item), c.api.left(other)
    ok = 400 <= patch < 500 and a1 == b1 and a2 == b2
    return ok, f"PATCH {patch}, товар1 {b1}→{a1}, товар2 {b2}→{a2}"


@row(35, "PATCH та повторні дії над уже скасованою (cancelled) заявкою", "4xx на PATCH і confirm, залишок без змін")
def r35(c):
    before = c.api.left(c.item)
    order = c.new_order(qty=1)
    c.api.action(c.t1, order, "cancel")
    patch, _ = c.api.request("PATCH", c.api.order_path(order),
                             {"status": "draft", c.api.c["qty_field"]: 2}, token=c.t1)
    conf = c.api.action(c.t1, order, "confirm")
    after = c.api.left(c.item)
    _, got = c.api.request("GET", c.api.order_path(order), token=c.t1)
    st = got.get("status") if isinstance(got, dict) else None
    ok = st == "cancelled" and conf == 409 and after == before and patch < 500
    return ok, f"PATCH {patch}, confirm {conf}, стан {st}, залишок {before}→{after}"


@row(36, "некоректні типи у полі кількості (null, рядок, дріб, список, bool)", "усі 400")
def r36(c):
    bad = [None, "abc", 1.5, [1], True]
    codes = [c.api.create_order(c.t1, c.item, val)[0] for val in bad]
    return all(x == 400 for x in codes), "/".join(map(str, codes))


@row(37, "некоректні типи у полі елемента каталогу (null, рядок, -1, список)", "усі 400")
def r37(c):
    bad = [None, "abc", -1, [c.item]]
    codes = [c.api.create_order(c.t1, val, 1)[0] for val in bad]
    return all(x == 400 for x in codes), "/".join(map(str, codes))


@row(38, "порожній JSON {} та JSON-масив [] у POST заявки", "обидва 400 (не 500)")
def r38(c):
    c1, _ = c.api.request("POST", c.api.order_path(), {}, token=c.t1)
    c2, _ = c.api.request("POST", c.api.order_path(), [1, 2, 3], token=c.t1)
    return c1 == 400 and c2 == 400, f"{c1}/{c2}"


@row(39, "confirm і cancel неіснуючої заявки 999999", "404/404 (не 500)")
def r39(c):
    c1 = c.api.action(c.t1, 999999, "confirm")
    c2 = c.api.action(c.t1, 999999, "cancel")
    return c1 in DENIED and c2 in DENIED, f"{c1}/{c2}"


@row(40, "нечисловий і надвеликий id у URL заявки (/abc/ та /999999999999999999999/)", "обидва 404 (не 500)")
def r40(c):
    c1, _ = c.api.request("GET", c.api.order_path("abc"), token=c.t1)
    c2, _ = c.api.request("GET", c.api.order_path("999999999999999999999"), token=c.t1)
    return c1 == 404 and c2 == 404, f"{c1}/{c2}"


@row(41, "PATCH чужого owner на власній чернетці", "власник не змінився (або 400)")
def r41(c):
    _, fdata = c.api.request("GET", c.api.order_path(c.foreign()), token=c.t2)
    other_owner = fdata.get("owner") if isinstance(fdata, dict) and isinstance(fdata.get("owner"), int) else 2
    order = c.new_order()
    pcode, _ = c.api.request("PATCH", c.api.order_path(order), {"owner": other_owner}, token=c.t1)
    if pcode == 400:
        return True, pcode
    mine, _ = c.api.request("GET", c.api.order_path(order), token=c.t1)
    theirs, _ = c.api.request("GET", c.api.order_path(order), token=c.t2)
    return mine == 200 and theirs in DENIED, f"PATCH {pcode}, мені {mine}, чужому {theirs}"


@row(42, "Гонка Г: одночасні 5×confirm + 5×cancel ОДНІЄЇ чернетки, 3 раунди",
     "без 5xx, фінальний залишок точно відповідає фінальному статусу")
def r42(c):
    notes, ok = [], True
    for _ in range(3):
        before = c.api.left(c.item)
        order = c.new_order(qty=1)
        calls = ([lambda o=order: c.api.action(c.t1, o, "confirm")] * 5 +
                 [lambda o=order: c.api.action(c.t1, o, "cancel")] * 5)
        codes = fire_at_once(calls)
        errors = sum(x >= 500 or x == 0 for x in codes)
        _, got = c.api.request("GET", c.api.order_path(order), token=c.t1)
        st = got.get("status") if isinstance(got, dict) else None
        after = c.api.left(c.item)
        expected_left = before - 1 if st == "confirmed" else before
        round_ok = errors == 0 and st in ("confirmed", "cancelled") and after == expected_left
        ok &= round_ok
        notes.append(f"{st}:{before}→{after}(5xx={errors})")
        if st == "confirmed":
            c.api.action(c.t1, order, "cancel")
    return ok, "; ".join(notes)


@row(43, "PUT (повне оновлення) у confirmed-заявці перед cancel", "PUT 4xx, інваріант залишку збережено")
def r43(c):
    before = c.api.left(c.item)
    order = c.new_order(qty=1)
    if not is_ok(c.api.action(c.t1, order, "confirm")):
        return False, "confirm не пройшов"
    put_code, _ = c.api.request("PUT", c.api.order_path(order),
                                c.api.order_body(c.item, 5), token=c.t1)
    canc = c.api.action(c.t1, order, "cancel")
    after = c.api.left(c.item)
    return 400 <= put_code < 500 and is_ok(canc) and after == before, f"PUT {put_code}, cancel {canc}, {before}→{after}"


@row(44, "PUT зі status=\"confirmed\" на чернетці (обхід confirm)", "стан draft (або 4xx), залишок без змін")
def r44(c):
    before = c.api.left(c.item)
    order = c.new_order(qty=1)
    put_code, _ = c.api.request("PUT", c.api.order_path(order),
                                c.api.order_body(c.item, 1, status="confirmed"), token=c.t1)
    after = c.api.left(c.item)
    if 400 <= put_code < 500:
        return after == before, f"PUT {put_code}, залишок {before}→{after}"
    _, got = c.api.request("GET", c.api.order_path(order), token=c.t1)
    st = got.get("status") if isinstance(got, dict) else None
    return st == "draft" and after == before, f"PUT {put_code}, стан {st}, {before}→{after}"


@row(45, "DELETE чернетки (перевірка, що залишок НЕ збільшується)", "залишок не змінився")
def r45(c):
    before = c.api.left(c.item)
    order = c.new_order(qty=3)
    del_code, _ = c.api.request("DELETE", c.api.order_path(order), token=c.t1)
    after = c.api.left(c.item)
    return del_code < 500 and after == before, f"DELETE {del_code}, залишок {before}→{after}"


@row(46, "DELETE уже скасованої (cancelled) заявки", "залишок НЕ повернувся вдруге")
def r46(c):
    before = c.api.left(c.item)
    order = c.new_order(qty=3)
    c.api.action(c.t1, order, "confirm")
    c.api.action(c.t1, order, "cancel")
    del_code, _ = c.api.request("DELETE", c.api.order_path(order), token=c.t1)
    after = c.api.left(c.item)
    return del_code < 500 and after == before, f"DELETE {del_code}, залишок {before}→{after}"


@row(47, "PATCH збільшення кількості в чернетці понад залишок + confirm", "400 на PATCH або confirm, залишок без змін")
def r47(c):
    before = c.api.left(c.item)
    order = c.new_order(qty=1)
    pcode, _ = c.api.request("PATCH", c.api.order_path(order),
                             {c.api.c["qty_field"]: before + 5}, token=c.t1)
    if pcode == 400:
        after = c.api.left(c.item)
        return after == before, f"PATCH {pcode}, залишок {before}→{after}"
    conf = c.api.action(c.t1, order, "confirm")
    after = c.api.left(c.item)
    return conf == 400 and after == before, f"PATCH {pcode}, confirm {conf}, залишок {before}→{after}"


@row(48, "PATCH надвеликої кількості 99999999999999999999 на чернетці", "400 (не 500)")
def r48(c):
    order = c.new_order(qty=1)
    pcode, _ = c.api.request("PATCH", c.api.order_path(order),
                             {c.api.c["qty_field"]: 99999999999999999999}, token=c.t1)
    return pcode == 400, pcode


@row(49, "невалідні заголовки Authorization (битий JWT, порожній Bearer)", "усі 401 (не 500)")
def r49(c):
    c1, _ = c.api.request("GET", c.api.order_path(), headers={"Authorization": "Bearer invalid.jwt.token"})
    c2, _ = c.api.request("GET", c.api.order_path(), headers={"Authorization": "Bearer "})
    c3, _ = c.api.request("GET", c.api.order_path(), headers={"Authorization": "Token 12345"})
    return all(x == 401 for x in (c1, c2, c3)), f"{c1}/{c2}/{c3}"


@row(50, "JSON-примітиви (null, число 123, рядок) замість об'єкта у POST і PATCH", "усі 400 (не 500)")
def r50(c):
    order = c.new_order(qty=1)
    codes = [
        c.api.request("POST", c.api.order_path(), token=c.t1, raw=b"null")[0],
        c.api.request("POST", c.api.order_path(), token=c.t1, raw=b"123")[0],
        c.api.request("PATCH", c.api.order_path(order), token=c.t1, raw=b'"hello"')[0],
        c.api.request("PATCH", c.api.order_path(order), token=c.t1, raw=b"null")[0],
    ]
    return all(x == 400 for x in codes), "/".join(map(str, codes))


@row(51, "підміна полів у тілі POST .../confirm/ ({\"quantity\": 999})", "списується реальна кількість заявки (1), а не з тіла")
def r51(c):
    before = c.api.left(c.item)
    order = c.new_order(qty=1)
    code, _ = c.api.request("POST", c.api.order_path(order, "confirm"),
                            {c.api.c["qty_field"]: 999, "status": "draft"}, token=c.t1)
    mid = c.api.left(c.item)
    if is_ok(code):
        c.api.action(c.t1, order, "cancel")
    after = c.api.left(c.item)
    ok = is_ok(code) and mid == before - 1 and after == before
    return ok, f"confirm {code}, залишок {before}→{mid}→{after}"


@row(52, "GET неіснуючого елемента каталогу (/999999/ та /abc/)", "обидва 404 (не 500)")
def r52(c):
    c1, _ = c.api.request("GET", c.api.item_path(999999))
    c2, _ = c.api.request("GET", c.api.item_path("abc"))
    return c1 == 404 and c2 == 404, f"{c1}/{c2}"


@row(53, "запит до неіснуючої заявки 999999 БЕЗ токена (GET і confirm)", "обидва 401 (спочатку перевірка токена)")
def r53(c):
    c1, _ = c.api.request("GET", c.api.order_path(999999))
    c2, _ = c.api.request("POST", c.api.order_path(999999, "confirm"))
    return c1 == 401 and c2 == 401, f"{c1}/{c2}"


@row(54, "Гонка Д: одночасні PATCH(qty=5) + confirm ОДНІЄЇ чернетки, потім cancel (3 раунди)",
     "після cancel залишок точно дорівнює початковому, без 5xx")
def r54(c):
    notes, ok = [], True
    for _ in range(3):
        before = c.api.left(c.item)
        order = c.new_order(qty=1)
        codes = fire_at_once([
            lambda o=order: c.api.request("PATCH", c.api.order_path(o), {c.api.c["qty_field"]: 5}, token=c.t1)[0],
            lambda o=order: c.api.action(c.t1, o, "confirm"),
        ])
        errors = sum(x >= 500 or x == 0 for x in codes)
        c.api.action(c.t1, order, "cancel")
        after = c.api.left(c.item)
        ok &= errors == 0 and after == before
        notes.append(f"{codes[0]}/{codes[1]}:{before}→{after}")
    return ok, "; ".join(notes)


@row(55, "Гонка Е: два різні користувачі одночасно (5×attacker1 + 5×attacker2 по qty=2)",
     "списання точно 2×wins, без 5xx, після cancel залишок відновлюється")
def r55(c):
    before = c.api.left(c.item)
    o1 = [c.new_order(token=c.t1, qty=2) for _ in range(5)]
    o2 = [c.new_order(token=c.t2, qty=2) for _ in range(5)]
    calls = ([lambda o=o: c.api.action(c.t1, o, "confirm") for o in o1] +
             [lambda o=o: c.api.action(c.t2, o, "confirm") for o in o2])
    codes = fire_at_once(calls)
    mid = c.api.left(c.item)
    wins = sum(is_ok(x) for x in codes)
    errors = sum(x >= 500 or x == 0 for x in codes)
    for o in o1:
        c.api.action(c.t1, o, "cancel")
    for o in o2:
        c.api.action(c.t2, o, "cancel")
    after = c.api.left(c.item)
    ok = errors == 0 and mid == before - 2 * wins and after == before
    return ok, f"{wins}×2xx, {errors}×5xx, залишок {before}→{mid}→{after}"


@row(56, "бухгалтерський ланцюжок змішаних переходів (confirm + draft-cancel + повторні дії)",
     "точний баланс залишку на кожному кроці")
def r56(c):
    s0 = c.api.left(c.item)
    a = c.new_order(qty=2)
    b = c.new_order(qty=3)
    k = c.new_order(qty=1)
    c.api.action(c.t1, a, "confirm")
    s1 = c.api.left(c.item)
    c.api.action(c.t1, b, "cancel")
    s2 = c.api.left(c.item)
    c.api.action(c.t1, k, "confirm")
    s3 = c.api.left(c.item)
    c.api.action(c.t1, a, "cancel")
    s4 = c.api.left(c.item)
    again = c.api.action(c.t1, a, "confirm")
    c.api.action(c.t1, k, "cancel")
    s5 = c.api.left(c.item)
    ok = (s1 == s0 - 2 and s2 == s0 - 2 and s3 == s0 - 3 and
          s4 == s0 - 1 and again == 409 and s5 == s0)
    return ok, f"{s0}→{s1}→{s2}→{s3}→{s4}→{s5}, re-confirm={again}"


@row(57, "PUT чужої заявки", "403/404")
def r57(c):
    foreign = c.foreign()
    code, _ = c.api.request("PUT", c.api.order_path(foreign), c.api.order_body(c.item, 2), token=c.t1)
    return code in DENIED, code


@row(58, "HEAD і OPTIONS списку заявок без токена", "обидва 401")
def r58(c):
    h, _ = c.api.request("HEAD", c.api.order_path())
    o, _ = c.api.request("OPTIONS", c.api.order_path())
    return h == 401 and o == 401, f"HEAD {h}, OPTIONS {o}"


@row(59, "спеціальні рядки у кількості (\"\", \"   \", \"NaN\", \"Infinity\", \"1e5\")", "усі 400 (не 500)")
def r59(c):
    vals = ["", "   ", "NaN", "Infinity", "1e5"]
    codes = [c.api.create_order(c.t1, c.item, v)[0] for v in vals]
    return all(x == 400 for x in codes), "/".join(map(str, codes))


@row(60, "рядкові межові числа кількості (\"0\", \"-5\")", "обидва 400")
def r60(c):
    c0, _ = c.api.create_order(c.t1, c.item, "0")
    cm, _ = c.api.create_order(c.t1, c.item, "-5")
    return c0 == 400 and cm == 400, f"{c0}/{cm}"


@row(61, "нульовий і від'ємний id в URL (/0/ та /-1/) для каталогу й заявок", "усі 404 (не 500)")
def r61(c):
    codes = [
        c.api.request("GET", c.api.item_path(0))[0],
        c.api.request("GET", c.api.item_path(-1))[0],
        c.api.request("GET", c.api.order_path(0), token=c.t1)[0],
        c.api.request("GET", c.api.order_path(-1), token=c.t1)[0],
    ]
    return all(x == 404 for x in codes), "/".join(map(str, codes))


@row(62, "непідтримуваний Content-Type (text/plain) у POST заявки", "400 або 415 (не 500)")
def r62(c):
    code, _ = c.api.request("POST", c.api.order_path(), token=c.t1,
                            raw=b"hello=world", headers={"Content-Type": "text/plain"})
    return code in (400, 415), code


@row(63, "ізоляція списку заявок у всіх станах (чужі draft, confirmed, cancelled)", "чужих 0 у списку")
def r63(c):
    f1 = c.foreign()
    f2 = c.foreign()
    c.api.action(c.t2, f2, "confirm")
    f3 = c.foreign()
    c.api.action(c.t2, f3, "cancel")
    code, data = c.api.request("GET", c.api.order_path(), token=c.t1)
    c.api.action(c.t2, f2, "cancel")
    ids = {o.get("id") for o in c.api.as_list(data) if isinstance(o, dict)}
    leaked = ids & {f1, f2, f3}
    return code == 200 and not leaked, f"{code}, витекло: {len(leaked)}"


@row(64, "валідація структури відповіді заявки (status у 3 станах, id ціле)", "коректна схема")
def r64(c):
    oid = c.new_order(qty=1)
    code, data = c.api.request("GET", c.api.order_path(oid), token=c.t1)
    ok = (code == 200 and isinstance(data, dict) and isinstance(data.get("id"), int)
          and data.get("status") in ("draft", "confirmed", "cancelled"))
    return ok, f"{code}, status={data.get('status') if isinstance(data, dict) else data}"


@row(65, "confirm рівно на ВЕСЬ залишок (qty == available) + відмова наступній + cancel",
     "перший 2xx (залишок 0), другий 400, після cancel залишок відновлено")
def r65(c):
    before = c.api.left(c.item)
    if before < 1:
        return False, "залишок 0 — запустіть seed_attack"
    full = c.new_order(qty=before)
    extra = c.new_order(qty=1)
    c1 = c.api.action(c.t1, full, "confirm")
    zero_left = c.api.left(c.item)
    c2 = c.api.action(c.t1, extra, "confirm")
    canc = c.api.action(c.t1, full, "cancel")
    after = c.api.left(c.item)
    ok = is_ok(c1) and zero_left == 0 and c2 == 400 and is_ok(canc) and after == before
    return ok, f"full={c1}(left={zero_left}), extra={c2}, cancel={canc}(left={after})"


@row(66, "draft → cancel → cancel (подвійне скасування чернетки)", "перший 2xx, другий 409, залишок без змін")
def r66(c):
    before = c.api.left(c.item)
    order = c.new_order(qty=1)
    c1 = c.api.action(c.t1, order, "cancel")
    c2 = c.api.action(c.t1, order, "cancel")
    after = c.api.left(c.item)
    return is_ok(c1) and c2 == 409 and after == before, f"{c1}/{c2}, залишок {before}→{after}"


@row(67, "Гонка Ж: одночасні DELETE + confirm ОДНІЄЇ чернетки (3 раунди)",
     "без 5xx і без втрати ресурсу зі складу")
def r67(c):
    notes, ok = [], True
    for _ in range(3):
        before = c.api.left(c.item)
        order = c.new_order(qty=1)
        codes = fire_at_once([
            lambda o=order: c.api.request("DELETE", c.api.order_path(o), token=c.t1)[0],
            lambda o=order: c.api.action(c.t1, o, "confirm"),
        ])
        errors = sum(x >= 500 or x == 0 for x in codes)
        get_code, got = c.api.request("GET", c.api.order_path(order), token=c.t1)
        if get_code == 200 and isinstance(got, dict) and got.get("status") == "confirmed":
            c.api.action(c.t1, order, "cancel")
        after = c.api.left(c.item)
        ok &= errors == 0 and after == before
        notes.append(f"DEL={codes[0]}/CONF={codes[1]}:{before}→{after}")
    return ok, "; ".join(notes)


@row(68, "Гонка З: одночасні DELETE + cancel ОДНІЄЇ confirmed-заявки (3 раунди)",
     "без 5xx, ресурс повернено рівно один раз")
def r68(c):
    notes, ok = [], True
    for _ in range(3):
        before = c.api.left(c.item)
        order = c.new_order(qty=1)
        if not is_ok(c.api.action(c.t1, order, "confirm")):
            return False, "confirm не пройшов"
        codes = fire_at_once([
            lambda o=order: c.api.request("DELETE", c.api.order_path(o), token=c.t1)[0],
            lambda o=order: c.api.action(c.t1, o, "cancel"),
        ])
        errors = sum(x >= 500 or x == 0 for x in codes)
        after = c.api.left(c.item)
        ok &= errors == 0 and after == before
        notes.append(f"DEL={codes[0]}/CANC={codes[1]}:{before}→{after}")
    return ok, "; ".join(notes)


@row(69, "Гонка И: одночасний confirm заявок різного розміру (qty 1,2,3,5,10) від двох юзерів",
     "точне списання суми успішних заявок, без 5xx, повне відновлення після cancel")
def r69(c):
    before = c.api.left(c.item)
    specs = [(c.t1, 1), (c.t2, 2), (c.t1, 3), (c.t2, 5), (c.t1, 10),
             (c.t2, 1), (c.t1, 2), (c.t2, 3)]
    created = [(tok, qty, c.new_order(token=tok, qty=qty)) for tok, qty in specs]
    codes = fire_at_once([lambda tok=tok, oid=oid: c.api.action(tok, oid, "confirm")
                          for tok, _, oid in created])
    mid = c.api.left(c.item)
    errors = sum(x >= 500 or x == 0 for x in codes)
    taken = sum(qty for (_, qty, _), code in zip(created, codes) if is_ok(code))
    for (tok, _, oid), code in zip(created, codes):
        if is_ok(code):
            c.api.action(tok, oid, "cancel")
    after = c.api.left(c.item)
    ok = errors == 0 and mid == before - taken and after == before
    return ok, f"списано={taken}, 5xx={errors}, {before}→{mid}→{after}"


@row(70, "одночасні 5×PATCH(різний qty) + 5×confirm ОДНІЄЇ чернетки, потім cancel",
     "без 5xx, після cancel залишок точно дорівнює початковому")
def r70(c):
    before = c.api.left(c.item)
    order = c.new_order(qty=1)
    calls = ([lambda o=order, q=q: c.api.request("PATCH", c.api.order_path(o),
                                                 {c.api.c["qty_field"]: q}, token=c.t1)[0]
              for q in (2, 3, 4, 5, 6)] +
             [lambda o=order: c.api.action(c.t1, o, "confirm")] * 5)
    codes = fire_at_once(calls)
    errors = sum(x >= 500 or x == 0 for x in codes)
    c.api.action(c.t1, order, "cancel")
    after = c.api.left(c.item)
    return errors == 0 and after == before, f"5xx={errors}, залишок {before}→{after}"


@row(71, "створення і confirm заявки, коли залишок ВЖЕ дорівнює 0", "400 на створенні або на confirm, залишок лишився 0")
def r71(c):
    before = c.api.left(c.item)
    blocker = c.new_order(qty=before)
    if not is_ok(c.api.action(c.t1, blocker, "confirm")):
        return False, "не вдалося тимчасово обнулити залишок"
    code, data = c.api.create_order(c.t1, c.item, 1)
    if code == 400:
        zero_ok = c.api.left(c.item) == 0
        c.api.action(c.t1, blocker, "cancel")
        return zero_ok and c.api.left(c.item) == before, "400 на створенні при залишку 0"
    conf = c.api.action(c.t1, data["id"], "confirm") if isinstance(data, dict) and "id" in data else code
    mid = c.api.left(c.item)
    c.api.action(c.t1, blocker, "cancel")
    after = c.api.left(c.item)
    return conf == 400 and mid == 0 and after == before, f"confirm={conf}, залишок під час тесту={mid}, після={after}"


@row(72, "зміна товару (item_field) у чернетці через PATCH перед confirm і cancel",
     "списується і повертається НОВИЙ товар, старий без змін")
def r72(c):
    items = [i["id"] for i in c.api.items()
             if isinstance(i, dict) and isinstance(i.get(c.api.c["left_field"]), int)
             and i["id"] != c.item and i[c.api.c["left_field"]] >= 5]
    if not items:
        return True, "лише один товар із достатнім залишком — пропуск"
    other = items[0]
    b1, b2 = c.api.left(c.item), c.api.left(other)
    order = c.new_order(qty=2, item=c.item)
    pcode, _ = c.api.request("PATCH", c.api.order_path(order), {c.api.c["item_field"]: other}, token=c.t1)
    if pcode == 400:
        return c.api.left(c.item) == b1 and c.api.left(other) == b2, "PATCH зміни товару заборонено (400)"
    conf = c.api.action(c.t1, order, "confirm")
    m1, m2 = c.api.left(c.item), c.api.left(other)
    canc = c.api.action(c.t1, order, "cancel")
    a1, a2 = c.api.left(c.item), c.api.left(other)
    ok = is_ok(conf) and m1 == b1 and m2 == b2 - 2 and is_ok(canc) and a1 == b1 and a2 == b2
    return ok, f"товар1 {b1}→{m1}→{a1}, товар2 {b2}→{m2}→{a2}"


@row(73, "PATCH неіснуючого (999999) і від'ємного (-5) item_field на чернетці", "обидва 400 (не 500 IntegrityError)")
def r73(c):
    order = c.new_order(qty=1)
    p1, _ = c.api.request("PATCH", c.api.order_path(order), {c.api.c["item_field"]: 999999}, token=c.t1)
    p2, _ = c.api.request("PATCH", c.api.order_path(order), {c.api.c["item_field"]: -5}, token=c.t1)
    return p1 == 400 and p2 == 400, f"{p1}/{p2}"


@row(74, "передача id існуючої заявки та невідомих полів у POST створення",
     "не перезаписує чужу заявку і не падає з 500")
def r74(c):
    foreign = c.foreign()
    code, data = c.api.create_order(c.t1, c.item, 1, id=foreign, unknown_extra_field="abc")
    if code == 400:
        return True, "400 (зайві поля відхилено)"
    ok = code in (200, 201) and isinstance(data, dict) and data.get("id") != foreign
    fcheck, _ = c.api.request("GET", c.api.order_path(foreign), token=c.t2)
    return ok and fcheck == 200, f"POST {code}, new_id={data.get('id') if isinstance(data, dict) else None}, foreign={fcheck}"


@row(75, "передача чужого id у PATCH власної чернетки", "чужа заявка не змінюється, без 500")
def r75(c):
    foreign = c.foreign()
    mine = c.new_order(qty=1)
    pcode, _ = c.api.request("PATCH", c.api.order_path(mine),
                             {"id": foreign, c.api.c["qty_field"]: 2}, token=c.t1)
    _, fdata = c.api.request("GET", c.api.order_path(foreign), token=c.t2)
    fqty = fdata.get(c.api.c["qty_field"]) if isinstance(fdata, dict) else None
    return pcode < 500 and fqty == 1, f"PATCH {pcode}, чужа кількість={fqty}"


@row(76, "фільтрація списку заявок через query-параметри (?owner=, ?user=)", "чужі заявки не протікають")
def r76(c):
    foreign = c.foreign()
    _, fdata = c.api.request("GET", c.api.order_path(foreign), token=c.t2)
    fowner = fdata.get("owner") if isinstance(fdata, dict) else 2
    qpath = f"{c.api.order_path()}?owner={fowner}&user={fowner}"
    code, data = c.api.request("GET", qpath, token=c.t1)
    ids = {o.get("id") for o in c.api.as_list(data) if isinstance(o, dict)}
    return code == 200 and foreign not in ids, f"{code}, чужа в списку={'так' if foreign in ids else 'ні'}"


@row(77, "спроба запису в каталог БЕЗ токена (POST / PATCH / DELETE)", "401 або 405 на всі три")
def r77(c):
    before = c.api.left(c.item)
    c1, _ = c.api.request("POST", c.api.item_path(), {c.api.c["left_field"]: 10})
    c2, _ = c.api.request("PATCH", c.api.item_path(c.item), {c.api.c["left_field"]: 999})
    c3, _ = c.api.request("DELETE", c.api.item_path(c.item))
    after = c.api.left(c.item)
    return all(x in (401, 403, 405) for x in (c1, c2, c3)) and after == before, f"{c1}/{c2}/{c3}"


@row(78, "PUT, PATCH і DELETE на самих ендпоінтах /confirm/ та /cancel/", "усі 405")
def r78(c):
    order = c.new_order(qty=1)
    codes = [
        c.api.request(m, c.api.order_path(order, act), token=c.t1)[0]
        for act in ("confirm", "cancel") for m in ("PUT", "PATCH", "DELETE")
    ]
    return all(x == 405 for x in codes), "/".join(map(str, codes))


@row(79, "перевірка реального збереження status у БД через GET після кожного переходу",
     "draft → confirmed → cancelled зберігаються в БД")
def r79(c):
    order = c.new_order(qty=1)
    _, d0 = c.api.request("GET", c.api.order_path(order), token=c.t1)
    c.api.action(c.t1, order, "confirm")
    _, d1 = c.api.request("GET", c.api.order_path(order), token=c.t1)
    c.api.action(c.t1, order, "cancel")
    _, d2 = c.api.request("GET", c.api.order_path(order), token=c.t1)
    s0, s1, s2 = (d.get("status") if isinstance(d, dict) else None for d in (d0, d1, d2))
    return (s0, s1, s2) == ("draft", "confirmed", "cancelled"), f"{s0} → {s1} → {s2}"


@row(80, "межа 64-бітного цілого SQLite (2^63 та -2^63-1) у item_field", "обидва 400 (не 500 OverflowError)")
def r80(c):
    c1, _ = c.api.create_order(c.t1, 9223372036854775808, 1)
    c2, _ = c.api.create_order(c.t1, -9223372036854775809, 1)
    return c1 == 400 and c2 == 400, f"{c1}/{c2}"


@row(81, "булеві значення true/false у PATCH кількості та товару", "усі 400")
def r81(c):
    order = c.new_order(qty=1)
    codes = [
        c.api.request("PATCH", c.api.order_path(order), {c.api.c["qty_field"]: True}, token=c.t1)[0],
        c.api.request("PATCH", c.api.order_path(order), {c.api.c["qty_field"]: False}, token=c.t1)[0],
        c.api.request("PATCH", c.api.order_path(order), {c.api.c["item_field"]: True}, token=c.t1)[0],
    ]
    return all(x == 400 for x in codes), "/".join(map(str, codes))


@row(82, "POST створення заявки без поля кількості (перевірка на 500 KeyError)", "400 або коректний дефолт без 500")
def r82(c):
    body = {c.api.c["item_field"]: c.item, **c.api.c["order_extra"]}
    code, data = c.api.request("POST", c.api.order_path(), body, token=c.t1)
    if code == 400:
        return True, "400 (поле обов'язкове)"
    if code in (200, 201) and isinstance(data, dict) and "id" in data:
        before = c.api.left(c.item)
        c.api.action(c.t1, data["id"], "confirm")
        c.api.action(c.t1, data["id"], "cancel")
        return c.api.left(c.item) == before, f"{code} з дефолтною кількістю, баланс зійшовся"
    return False, code


@row(83, "одночасні 10×POST створення + 10×GET списку (перевірка database is locked)", "усі 2xx, 0×5xx")
def r83(c):
    calls = ([lambda: c.api.create_order(c.t1, c.item, 1)[0]] * 5 +
             [lambda: c.api.create_order(c.t2, c.item, 1)[0]] * 5 +
             [lambda: c.api.request("GET", c.api.order_path(), token=c.t1)[0]] * 5 +
             [lambda: c.api.request("GET", c.api.item_path())[0]] * 5)
    codes = fire_at_once(calls)
    errors = sum(x >= 500 or x == 0 for x in codes)
    return all(is_ok(x) for x in codes) and errors == 0, f"ok={sum(is_ok(x) for x in codes)}/20, 5xx={errors}"


@row(84, "Гонка К (самоочисна): зведення залишку до 1 + 10 одночасних confirm від 2 юзерів",
     "рівно 1×2xx, залишок 0 під час піку, 0×5xx, повне відновлення")
def r84(c):
    before = c.api.left(c.item)
    if before < 2:
        return False, "залишок < 2 — запустіть seed_attack"
    blocker = c.new_order(qty=before - 1)
    if not is_ok(c.api.action(c.t1, blocker, "confirm")):
        return False, "не вдалося зарезервувати blocker"
    contenders = [(c.t1, c.new_order(token=c.t1, qty=1)) for _ in range(5)] + \
                 [(c.t2, c.new_order(token=c.t2, qty=1)) for _ in range(5)]
    codes = fire_at_once([lambda tok=tok, oid=oid: c.api.action(tok, oid, "confirm")
                          for tok, oid in contenders])
    peak_left = c.api.left(c.item)
    wins = sum(is_ok(x) for x in codes)
    errors = sum(x >= 500 or x == 0 for x in codes)
    for (tok, oid), code in zip(contenders, codes):
        if is_ok(code):
            c.api.action(tok, oid, "cancel")
    c.api.action(c.t1, blocker, "cancel")
    after = c.api.left(c.item)
    ok = wins == 1 and peak_left == 0 and errors == 0 and after == before
    return ok, f"{wins}×2xx, пік={peak_left}, 5xx={errors}, відновлено={after}/{before}"


@row(85, "Гонка Л (некратний залишок): 3 одиниці на полиці проти 8 одночасних confirm по qty=2",
     "рівно 1×2xx, на полиці лишається рівно 1 (не 0 і не -1!), 0×5xx")
def r85(c):
    before = c.api.left(c.item)
    if before < 4:
        return False, "залишок < 4 — запустіть seed_attack"
    blocker = c.new_order(qty=before - 3)
    if not is_ok(c.api.action(c.t1, blocker, "confirm")):
        return False, "не вдалося виставити залишок 3"
    orders = [c.new_order(qty=2) for _ in range(8)]
    codes = fire_at_once([lambda oid=oid: c.api.action(c.t1, oid, "confirm") for oid in orders])
    rem = c.api.left(c.item)
    wins = sum(is_ok(x) for x in codes)
    errors = sum(x >= 500 or x == 0 for x in codes)
    for oid, code in zip(orders, codes):
        if is_ok(code):
            c.api.action(c.t1, oid, "cancel")
    c.api.action(c.t1, blocker, "cancel")
    after = c.api.left(c.item)
    ok = wins == 1 and rem == 1 and errors == 0 and after == before
    return ok, f"{wins}×2xx, залишок при 3: {rem}, 5xx={errors}, відновлено={after}/{before}"


@row(86, "Гонка М: 5 чужих confirm + 5 власних confirm ОДНІЄЇ чернетки одночасно",
     "чужі всі 403/404, власний рівно 1×2xx, без 5xx")
def r86(c):
    before = c.api.left(c.item)
    target_order = c.foreign()
    calls = ([lambda: c.api.action(c.t1, target_order, "confirm")] * 5 +
             [lambda: c.api.action(c.t2, target_order, "confirm")] * 5)
    codes = fire_at_once(calls)
    foreign_codes, own_codes = codes[:5], codes[5:]
    mid = c.api.left(c.item)
    c.api.action(c.t2, target_order, "cancel")
    after = c.api.left(c.item)
    ok = (all(x in DENIED for x in foreign_codes) and sum(is_ok(x) for x in own_codes) == 1
          and sum(x >= 500 or x == 0 for x in codes) == 0 and mid == before - 1 and after == before)
    return ok, f"чужі={set(foreign_codes)}, свої 2xx={sum(is_ok(x) for x in own_codes)}, {before}→{mid}→{after}"


@row(87, "Гонка Н: 5 чужих cancel + 5 власних cancel ОДНІЄЇ confirmed-заявки одночасно",
     "чужі всі 403/404, власний рівно 1×2xx, ресурс повернено рівно раз")
def r87(c):
    before = c.api.left(c.item)
    target_order = c.foreign()
    if not is_ok(c.api.action(c.t2, target_order, "confirm")):
        return False, "confirm не пройшов"
    calls = ([lambda: c.api.action(c.t1, target_order, "cancel")] * 5 +
             [lambda: c.api.action(c.t2, target_order, "cancel")] * 5)
    codes = fire_at_once(calls)
    foreign_codes, own_codes = codes[:5], codes[5:]
    after = c.api.left(c.item)
    ok = (all(x in DENIED for x in foreign_codes) and sum(is_ok(x) for x in own_codes) == 1
          and sum(x >= 500 or x == 0 for x in codes) == 0 and after == before)
    return ok, f"чужі={set(foreign_codes)}, свої 2xx={sum(is_ok(x) for x in own_codes)}, {before}→{after}"


@row(88, "повна звірка інваріанта: списано зі складу == сума(qty активних confirmed-заявок)",
     "ідеальна рівність до і після очищення")
def r88(c):
    before = c.api.left(c.item)
    a1 = c.new_order(token=c.t1, qty=2)
    a2 = c.new_order(token=c.t1, qty=3)
    b1 = c.new_order(token=c.t2, qty=4)
    d1 = c.new_order(token=c.t2, qty=5)
    c.api.action(c.t1, a1, "confirm")
    c.api.action(c.t1, a2, "confirm")
    c.api.action(c.t2, b1, "confirm")
    c.api.action(c.t2, d1, "cancel")
    c.api.action(c.t1, a2, "cancel")
    mid = c.api.left(c.item)
    # Активні confirmed зараз лише a1 (qty=2) та b1 (qty=4) => разом 6.
    c.api.action(c.t1, a1, "cancel")
    c.api.action(c.t2, b1, "cancel")
    after = c.api.left(c.item)
    ok = mid == before - 6 and after == before
    return ok, f"очікувалось списано 6: {before}→{mid} (різниця {before - mid}), після очищення {after}"


def _parse_only(spec):
    out = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            out.extend(range(int(start), int(end) + 1))
        elif part:
            out.append(int(part))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--contract", default="contract.json")
    parser.add_argument("--only", help="номери або діапазони рядків, напр. 18,19,21 або 23-42")
    args = parser.parse_args()

    api = Api(load_contract(args.contract))
    numbers = [n for n in sorted(ROWS) if n <= 22] if not args.only else _parse_only(args.only)
    ctx = Ctx(api)

    passed = {}
    for n in numbers:
        title, expected, fn = ROWS[n]
        try:
            ok, got = fn(ctx)
        except RuntimeError as err:
            ok, got = False, str(err)
        passed[n] = ok
        print(f"{'✅' if ok else '❌'} {n:>2}. {title}\n       очікувано: {expected} · отримано: {got}")

    open_rows = [n for n in passed if n <= 20]
    extra_rows = [n for n in passed if n >= 23]
    print("\n" + "─" * 60)
    if open_rows:
        print(f"Відкрита карта: {sum(passed[n] for n in open_rows)} / {len(open_rows)}")
    for n, name in ((21, "Гонка А"), (22, "Гонка Б")):
        if n in passed:
            print(f"{name}: {'витримано' if passed[n] else 'ПРОБИТО'}")
    if extra_rows:
        print(f"Додаткові перевірки інваріанта (23–88): {sum(passed[n] for n in extra_rows)} / {len(extra_rows)}")
    print("Гонки ймовірнісні: зелений результат — не доказ, червоний — доказ.")
    sys.exit(0 if all(passed.values()) else 1)


if __name__ == "__main__":
    main()

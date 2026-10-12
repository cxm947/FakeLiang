"""Control-side mapping proxy and data-flow probes."""
from __future__ import annotations

import json

#: 控制端映射代理端口。**必须避开交付 handler 的端口带（1080–1150）**：两者都在控制端监听，
#: 落进同一条带里会让"交付拿到的端口"与"中转代理的端口"互相挤（2026-10-09 真机 walk-205）。
TUNNEL_PROXY_PORT = 1185
#: 跳板上的转发入口端口从 1445 起（Windows 跳板不能占用 445 这类系统端口）。
TUNNEL_BASE_PORT = 1445


def conf_path(port=TUNNEL_PROXY_PORT) -> str:
    return "/tmp/agv_proxy_%s.conf" % port


def map_path() -> str:
    return "/tmp/agv_tunnel_map.json"


def conf_body(port=TUNNEL_PROXY_PORT) -> str:
    """控制端那份 proxychains 配置。只指本机 socks，不写死盘符、不依赖 /etc。"""
    return ("strict_chain\n"
            "proxy_dns\n"
            "tcp_read_time_out 15000\n"
            "tcp_connect_time_out 8000\n"
            "[ProxyList]\n"
            "socks5 127.0.0.1 %s\n" % port)


def proxy_prefix(port=TUNNEL_PROXY_PORT):
    """命令前缀：`proxychains4 -q -f <conf>`（-q 必须：不加它每条连接都刷 |S-chain| 进回执）。"""
    return ["proxychains4", "-q", "-f", conf_path(port)]


def proxy_argv(port, argv):
    return [*proxy_prefix(port), *[str(part) for part in argv]]


#: 控制端的小 SOCKS5（只做 CONNECT、无认证）。**每次 CONNECT 重读 map 文件**：映射可以随时加，
#: 不用重启进程。查不到映射就如实回"目标不可达"，绝不偷偷直连（那会变成"看起来通了"）。
SOCKS5_MAPPER = (
    "import json, socket, struct, sys, threading\n"
    "BIND = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'\n"
    "PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1085\n"
    "MAPFILE = sys.argv[3] if len(sys.argv) > 3 else '/tmp/agv_tunnel_map.json'\n"
    "def load():\n"
    "    try:\n"
    "        return json.load(open(MAPFILE))\n"
    "    except Exception:\n"
    "        return {}\n"
    "def relay(a, b):\n"
    "    while True:\n"
    "        try:\n"
    "            data = a.recv(65536)\n"
    "        except OSError:\n"
    "            break\n"
    "        if not data:\n"
    "            break\n"
    "        try:\n"
    "            b.sendall(data)\n"
    "        except OSError:\n"
    "            break\n"
    "    for sock in (a, b):\n"
    "        try:\n"
    "            sock.shutdown(socket.SHUT_RDWR)\n"
    "        except OSError:\n"
    "            pass\n"
    "def handle(conn):\n"
    "    try:\n"
    "        head = conn.recv(2)\n"
    "        if len(head) < 2 or head[0] != 5:\n"
    "            return\n"
    "        conn.recv(head[1])\n"
    "        conn.sendall(b'\\x05\\x00')\n"
    "        req = conn.recv(4)\n"
    "        if len(req) < 4 or req[1] != 1:\n"
    "            return\n"
    "        if req[3] == 1:\n"
    "            host = socket.inet_ntoa(conn.recv(4))\n"
    "        elif req[3] == 3:\n"
    "            host = conn.recv(conn.recv(1)[0]).decode()\n"
    "        else:\n"
    "            host = socket.inet_ntop(socket.AF_INET6, conn.recv(16))\n"
    "        port = struct.unpack('>H', conn.recv(2))[0]\n"
    "        entry = load().get('%s:%d' % (host, port))\n"
    "        if not entry:\n"
    "            conn.sendall(b'\\x05\\x04\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00')\n"
    "            return\n"
    "        try:\n"
    "            up = socket.create_connection((entry[0], int(entry[1])), 10)\n"
    "        except OSError:\n"
    "            conn.sendall(b'\\x05\\x05\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00')\n"
    "            return\n"
    "        conn.sendall(b'\\x05\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00')\n"
    "        threading.Thread(target=relay, args=(conn, up), daemon=True).start()\n"
    "        relay(up, conn)\n"
    "    except Exception:\n"
    "        pass\n"
    "    finally:\n"
    "        try:\n"
    "            conn.close()\n"
    "        except Exception:\n"
    "            pass\n"
    "srv = socket.socket()\n"
    "srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
    "srv.bind((BIND, PORT))\n"
    "srv.listen(64)\n"
    "print('AGV_TUNNEL_READY %s:%d' % (BIND, PORT), flush=True)\n"
    "while True:\n"
    "    conn, _ = srv.accept()\n"
    "    threading.Thread(target=handle, args=(conn,), daemon=True).start()\n"
)


def ensure_local_proxy(executor, *, port=TUNNEL_PROXY_PORT, timeout=60.0) -> str:
    """在控制端放好并起好映射代理（幂等：已在听就不重启）。返回 reach。"""
    script = "/tmp/agv_socks_map.py"
    alive = executor(["/bin/sh", "-c",
                      "ss -ltn | grep -q ':%s ' && echo up || echo down" % port], timeout)
    if "up" in str(getattr(alive, "stdout", "") or ""):
        return "socks5://127.0.0.1:%s" % port
    executor(["python3", "-c", "import io;io.open(%r,'w').write(%r)" % (script, SOCKS5_MAPPER)],
             timeout)
    executor(["python3", "-c", "import io;io.open(%r,'w').write('{}')" % map_path()], timeout)
    started = executor(["/bin/sh", "-c",
                        "(setsid nohup python3 %s 127.0.0.1 %s %s >/tmp/agv_socks_map.log 2>&1 &); "
                        "sleep 2; cat /tmp/agv_socks_map.log" % (script, port, map_path())], timeout)
    executor(["python3", "-c",
              "import io;io.open(%r,'w').write(%r)" % (conf_path(port), conf_body(port))], timeout)
    return "socks5://127.0.0.1:%s" % port


def _write_map(executor, mapping, *, timeout=30.0):
    executor(["python3", "-c",
              "import io;io.open(%r,'w').write(%r)" % (map_path(), json.dumps(mapping))], timeout)


#: 数据级探针：**收到字节才算通**。445 上发一个合法的 SMB2 NEGOTIATE（SMB 服务必回）；
#: 其他端口先等服务先说话，不说就喂一个换行再等。connect-only（`nc -z`）会被中间态骗过。
PROBE = (
    "import socket, struct, sys\n"
    "host, port = sys.argv[1], int(sys.argv[2])\n"
    "def smb2():\n"
    "    header = (b'\\xfeSMB' + struct.pack('<HHIHHIIQ', 64, 0, 0, 0, 0, 0, 0, 0)\n"
    "              + struct.pack('<IIQI', 0, 0, 0, 0) + b'\\x00' * 16)\n"
    "    body = struct.pack('<HHHHIH', 36, 2, 0, 0, 0, 0) + b'\\x00' * 16 + struct.pack('<Q', 0)\n"
    "    body += struct.pack('<HH', 0x0210, 0x0202)\n"
    "    payload = header + body\n"
    "    return b'\\x00' + struct.pack('>I', len(payload))[1:] + payload\n"
    "try:\n"
    "    sock = socket.create_connection((host, port), 10.0)\n"
    "    sock.settimeout(8.0)\n"
    "    if port == 445:\n"
    "        sock.sendall(smb2())\n"
    "    try:\n"
    "        data = sock.recv(256)\n"
    "    except socket.timeout:\n"
    "        data = b''\n"
    "    if not data:\n"
    "        try:\n"
    "            sock.sendall(b'\\r\\n')\n"
    "            data = sock.recv(256)\n"
    "        except Exception:\n"
    "            data = b''\n"
    "    sock.close()\n"
    "    print('AGV_FLOW_OK %d' % len(data) if data else 'AGV_FLOW_FAIL no-bytes')\n"
    "except Exception as error:\n"
    "    print('AGV_FLOW_FAIL %s: %s' % (type(error).__name__, error))\n"
)


def data_probe(executor, host, port, *, proxy_port=TUNNEL_PROXY_PORT, timeout=30.0) -> bool:
    """经代理发真包、要真回包 —— 这是"隧道通了"的唯一证据。"""
    program = "/tmp/agv_flow_probe.py"
    executor(["python3", "-c", "import io;io.open(%r,'w').write(%r)" % (program, PROBE)], timeout)
    line = ("timeout %d proxychains4 -q -f %s python3 %s %s %s"
            % (int(timeout), conf_path(proxy_port), program, host, port))
    outcome = executor(["/bin/sh", "-c", line], float(timeout) + 20.0)
    return "AGV_FLOW_OK" in str(getattr(outcome, "stdout", "") or "")

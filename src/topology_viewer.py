#!/usr/bin/env python3
"""
topology_viewer.py - Ve topo mang SDN qua Ryu REST API.
Chay: python3 src/topology_viewer.py
"""

import json
import webbrowser
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import requests


RYU_URL = "http://127.0.0.1:8080"
OUTPUT_FILE = "topology_map.html"

VIS_NETWORK_CDN = (
    "https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"
)
VIS_NETWORK_CSS = (
    "https://unpkg.com/vis-network@9.1.9/styles/vis-network.min.css"
)

def svg_icon(svg):
    return "data:image/svg+xml;charset=utf-8," + quote(svg)


ICON_CONTROLLER = svg_icon(
    """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
<rect x="30" y="12" width="68" height="104" rx="8" fill="#0f8fbd" stroke="#ffffff" stroke-width="6"/>
<rect x="18" y="30" width="24" height="78" rx="5" fill="#0b79a3" stroke="#ffffff" stroke-width="5"/>
<path d="M50 42h34M50 62h34M50 82h34" stroke="#ffffff" stroke-width="6" stroke-linecap="round"/>
<circle cx="29" cy="47" r="4" fill="#ffffff"/><circle cx="29" cy="69" r="4" fill="#ffffff"/><circle cx="29" cy="91" r="4" fill="#ffffff"/>
</svg>"""
)
ICON_SWITCH = svg_icon(
    """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 160 96">
<rect x="12" y="24" width="136" height="50" rx="8" fill="#18a7c9" stroke="#ffffff" stroke-width="6"/>
<path d="M30 41h22M30 57h22M66 41h22M66 57h22M102 41h22M102 57h22" stroke="#ffffff" stroke-width="5" stroke-linecap="round"/>
<path d="M33 78l-13 10m13-10l13 10M80 78v13M127 78l-13 10m13-10l13 10" stroke="#0f6f8f" stroke-width="5" stroke-linecap="round"/>
</svg>"""
)
ICON_HOST = svg_icon(
    """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 144 112">
<rect x="30" y="16" width="84" height="58" rx="6" fill="#27a8d8" stroke="#ffffff" stroke-width="6"/>
<rect x="42" y="27" width="60" height="36" rx="3" fill="#dff7ff"/>
<path d="M20 84h104l10 14H10z" fill="#116f97" stroke="#ffffff" stroke-width="5" stroke-linejoin="round"/>
<path d="M58 90h28" stroke="#dff7ff" stroke-width="4" stroke-linecap="round"/>
</svg>"""
)


def get_topology():
    """Lay danh sach switches va links tu Ryu topology API."""
    try:
        res_sw = requests.get(f"{RYU_URL}/v1.0/topology/switches", timeout=5)
        res_sw.raise_for_status()

        res_link = requests.get(f"{RYU_URL}/v1.0/topology/links", timeout=5)
        res_link.raise_for_status()

        return {
            "switches": res_sw.json(),
            "links": res_link.json(),
        }
    except requests.exceptions.RequestException as exc:
        return {"error": f"Loi ket noi Ryu topology API: {exc}"}
    except ValueError as exc:
        return {"error": f"Ryu tra ve JSON khong hop le: {exc}"}


def get_switches():
    """Lay danh sach DPID switches tu Ryu stats API."""
    try:
        res = requests.get(f"{RYU_URL}/stats/switches", timeout=5)
        res.raise_for_status()
        return res.json()
    except (requests.exceptions.RequestException, ValueError):
        return []


def get_flows(dpid):
    """Lay flow table cua mot switch."""
    try:
        res = requests.get(f"{RYU_URL}/stats/flow/{dpid}", timeout=5)
        res.raise_for_status()
        return res.json().get(str(dpid), [])
    except (requests.exceptions.RequestException, ValueError):
        return []


def get_ports(dpid):
    """Lay thong tin port cua mot switch."""
    try:
        res = requests.get(f"{RYU_URL}/stats/port/{dpid}", timeout=5)
        res.raise_for_status()
        return res.json().get(str(dpid), [])
    except (requests.exceptions.RequestException, ValueError):
        return []


def parse_dpid(raw_dpid):
    """Chuyen DPID hex/string tu Ryu thanh int de goi stats API."""
    if raw_dpid is None:
        return None
    try:
        if isinstance(raw_dpid, str):
            return int(raw_dpid, 16)
        return int(raw_dpid)
    except (TypeError, ValueError):
        return None


def switch_id(dpid):
    return f"switch:{dpid}"


def host_id(ip_address):
    return f"host:{ip_address}"


def add_edge_once(edges, edge_keys, from_id, to_id, **edge_data):
    edge_key = (from_id, to_id)
    if edge_key in edge_keys:
        return

    edge = {"from": from_id, "to": to_id}
    edge.update(edge_data)
    edges.append(edge)
    edge_keys.add(edge_key)


def parse_switch_dpids(switches):
    dpids = []
    seen = set()
    for sw in switches:
        dpid = parse_dpid(sw.get("dpid") if isinstance(sw, dict) else sw)
        if dpid is None or dpid in seen:
            continue

        dpids.append(dpid)
        seen.add(dpid)

    return dpids


def host_sort_key(host_node_id):
    try:
        ip_address = host_node_id.split("host:", 1)[1]
        return int(ip_address.split(".")[-1])
    except (IndexError, ValueError):
        return 0


def apply_star_layout(nodes, switch_ids, host_ids_by_switch):
    """Gan toa do co dinh de topo hien thi gon theo dang controller-switch-host."""
    node_by_id = {node["id"]: node for node in nodes}
    if not switch_ids:
        return

    switch_spacing = 360
    switch_start_x = -((len(switch_ids) - 1) * switch_spacing) / 2

    controller = node_by_id.get("controller")
    if controller:
        controller.update({"x": 0, "y": -280, "fixed": {"x": True, "y": True}})

    for switch_index, sw_id in enumerate(switch_ids):
        switch_x = switch_start_x + switch_index * switch_spacing
        switch_node = node_by_id.get(sw_id)
        if not switch_node:
            continue

        switch_node.update({"x": switch_x, "y": -80, "fixed": {"x": True, "y": True}})

        host_ids = sorted(host_ids_by_switch.get(sw_id, []), key=host_sort_key)
        hosts_per_row = 8 if len(switch_ids) == 1 else 4
        host_spacing_x = 150 if len(switch_ids) == 1 else 125
        host_spacing_y = 150

        for host_index, h_id in enumerate(host_ids):
            row = host_index // hosts_per_row
            col = host_index % hosts_per_row
            hosts_in_row = min(hosts_per_row, len(host_ids) - row * hosts_per_row)
            host_x = switch_x + (col - (hosts_in_row - 1) / 2) * host_spacing_x
            host_y = 150 + row * host_spacing_y

            host_node = node_by_id.get(h_id)
            if host_node:
                host_node.update(
                    {"x": host_x, "y": host_y, "fixed": {"x": True, "y": True}}
                )


def count_valid_ports(dpid):
    valid_ports = 0
    for port in get_ports(dpid):
        try:
            if int(port.get("port_no", 0)) > 0:
                valid_ports += 1
        except (TypeError, ValueError):
            continue
    return valid_ports


def extract_hosts_from_flows(dpid):
    """Suy ra host IP/MAC tu match fields trong flow table."""
    hosts = {}
    for flow in get_flows(dpid):
        match = flow.get("match", {})
        macs = [
            match[field]
            for field in ("eth_src", "eth_dst", "dl_src", "dl_dst")
            if field in match
        ]

        for mac in macs:
            if not isinstance(mac, str):
                continue

            mac = mac.lower()
            if not mac.startswith("00:00:00:00:00:"):
                continue

            try:
                suffix = int(mac.split(":")[-1])
            except (TypeError, ValueError):
                continue

            ip_address = f"10.0.0.{suffix}"
            hosts[ip_address] = mac

    return hosts


def build_graph_data():
    topo = get_topology()
    if topo.get("error"):
        return {
            "nodes": [],
            "edges": [],
            "stats": {"switches": 0, "links": 0, "hosts": 0},
            "error": topo["error"],
        }

    switch_dpids = parse_switch_dpids(topo.get("switches", []))
    nodes = [
        {
            "id": "controller",
            "label": "Ryu Controller",
            "shape": "image",
            "image": ICON_CONTROLLER,
            "size": 42,
            "level": 0,
            "font": {"size": 18, "face": "Inter, Arial", "color": "#0f172a"},
            "title": "Ryu Controller<br>REST API: 127.0.0.1:8080",
        }
    ]
    edges = []
    edge_keys = set()
    node_ids = {"controller"}
    host_records = {}
    host_ids_by_switch = {}
    switch_ids = [switch_id(dpid) for dpid in switch_dpids]

    parsed_switches = []
    for dpid in switch_dpids:
        port_count = count_valid_ports(dpid)
        parsed_switches.append({"dpid": dpid, "ports": port_count})

        sw_id = switch_id(dpid)
        nodes.append(
            {
                "id": sw_id,
                "label": f"s{dpid}",
                "shape": "image",
                "image": ICON_SWITCH,
                "size": 46,
                "level": 1,
                "font": {"size": 17, "face": "Inter, Arial", "color": "#0f172a"},
                "title": f"Switch s{dpid}<br>DPID: {dpid}<br>Ports: {port_count}",
            }
        )
        node_ids.add(sw_id)

        add_edge_once(
            edges,
            edge_keys,
            "controller",
            sw_id,
            dashes=True,
            width=2,
            color={"color": "#0ea5e9", "opacity": 0.75},
            title="Control channel: Ryu Controller -> Switch",
        )

        for ip_address, mac in extract_hosts_from_flows(dpid).items():
            h_id = host_id(ip_address)
            host_records[ip_address] = mac

            if h_id not in node_ids:
                nodes.append(
                    {
                        "id": h_id,
                        "label": ip_address,
                        "shape": "image",
                        "image": ICON_HOST,
                        "size": 38,
                        "level": 2,
                        "font": {
                            "size": 15,
                            "face": "Inter, Arial",
                            "color": "#1e293b",
                        },
                        "title": f"Host<br>IP: {ip_address}<br>MAC: {mac}",
                    }
                )
                node_ids.add(h_id)

            host_ids_by_switch.setdefault(sw_id, set()).add(h_id)
            add_edge_once(
                edges,
                edge_keys,
                sw_id,
                h_id,
                dashes=False,
                width=2,
                color={"color": "#16a34a", "opacity": 0.82},
                title=f"s{dpid} <-> {ip_address}",
            )

    apply_star_layout(nodes, switch_ids, host_ids_by_switch)

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "switches": len(parsed_switches),
            "links": len(edges),
            "hosts": len(host_records),
        },
        "error": "",
    }


def build_html(graph_data):
    nodes_json = json.dumps(graph_data["nodes"], ensure_ascii=False, indent=2)
    edges_json = json.dumps(graph_data["edges"], ensure_ascii=False, indent=2)
    stats_json = json.dumps(graph_data["stats"], ensure_ascii=False)
    error_json = json.dumps(graph_data["error"], ensure_ascii=False)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SDN Topology Map</title>
  <link rel="stylesheet" href="{VIS_NETWORK_CSS}">
  <script src="{VIS_NETWORK_CDN}"></script>
  <style>
    :root {{
      color-scheme: light;
      --bg: #eef5fb;
      --panel: #ffffff;
      --ink: #0f172a;
      --muted: #64748b;
      --line: #d8e3ef;
      --accent: #0ea5e9;
      --danger: #b91c1c;
      --danger-bg: #fff1f2;
    }}

    * {{
      box-sizing: border-box;
    }}

    body {{
      margin: 0;
      height: 100vh;
      overflow: hidden;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
        "Segoe UI", Arial, sans-serif;
      color: var(--ink);
      background:
        linear-gradient(135deg, rgba(14, 165, 233, 0.11), transparent 38%),
        linear-gradient(315deg, rgba(34, 197, 94, 0.09), transparent 32%),
        var(--bg);
    }}

    .app {{
      display: grid;
      grid-template-rows: auto 1fr;
      height: 100vh;
    }}

    header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 16px 22px;
      background: rgba(255, 255, 255, 0.9);
      border-bottom: 1px solid var(--line);
      backdrop-filter: blur(10px);
    }}

    h1 {{
      margin: 0;
      font-size: 22px;
      font-weight: 750;
      letter-spacing: 0;
    }}

    .subtitle {{
      margin-top: 4px;
      color: var(--muted);
      font-size: 13px;
    }}

    .stats {{
      display: flex;
      flex-wrap: wrap;
      justify-content: flex-end;
      gap: 8px;
    }}

    .stat {{
      min-width: 96px;
      padding: 8px 10px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      text-align: center;
    }}

    .stat strong {{
      display: block;
      font-size: 18px;
    }}

    .stat span {{
      color: var(--muted);
      font-size: 12px;
    }}

    main {{
      position: relative;
      min-height: 0;
      padding: 14px;
    }}

    #network {{
      width: 100%;
      height: 100%;
      min-height: 0;
      overflow: hidden;
      border: 1px solid var(--line);
      border-radius: 8px;
      background:
        linear-gradient(rgba(148, 163, 184, 0.10) 1px, transparent 1px),
        linear-gradient(90deg, rgba(148, 163, 184, 0.10) 1px, transparent 1px),
        #fbfdff;
      background-size: 40px 40px;
      box-shadow: 0 14px 34px rgba(15, 23, 42, 0.08);
    }}

    .message {{
      position: absolute;
      left: 50%;
      top: 50%;
      width: min(560px, calc(100% - 48px));
      transform: translate(-50%, -50%);
      padding: 22px;
      border: 1px solid #fecdd3;
      border-radius: 8px;
      background: var(--danger-bg);
      color: var(--danger);
      box-shadow: 0 16px 36px rgba(127, 29, 29, 0.16);
    }}

    .message h2 {{
      margin: 0 0 8px;
      font-size: 18px;
    }}

    .message p {{
      margin: 8px 0;
      line-height: 1.5;
    }}

    code {{
      padding: 2px 5px;
      border-radius: 5px;
      background: rgba(15, 23, 42, 0.08);
      color: #7f1d1d;
      font-size: 0.95em;
    }}

    @media (max-width: 720px) {{
      header {{
        align-items: flex-start;
        flex-direction: column;
        padding: 14px;
      }}

      .stats {{
        justify-content: flex-start;
        width: 100%;
      }}

      .stat {{
        flex: 1 1 90px;
      }}

      main {{
        padding: 10px;
      }}

      #network {{
        height: 100%;
      }}
    }}
  </style>
</head>
<body>
  <div class="app">
    <header>
      <div>
        <h1>SDN Network Topology</h1>
        <div class="subtitle">Ryu REST API: {RYU_URL} | Cập nhật: {generated_at}</div>
      </div>
      <div class="stats" aria-label="Topology statistics">
        <div class="stat"><strong id="switch-count">0</strong><span>Switches</span></div>
        <div class="stat"><strong id="link-count">0</strong><span>Links</span></div>
        <div class="stat"><strong id="host-count">0</strong><span>Hosts</span></div>
      </div>
    </header>
    <main>
      <div id="network"></div>
      <div id="message" class="message" hidden></div>
    </main>
  </div>

  <script>
    const nodesData = {nodes_json};
    const edgesData = {edges_json};
    const stats = {stats_json};
    const errorMessage = {error_json};

    document.getElementById("switch-count").textContent = stats.switches;
    document.getElementById("link-count").textContent = stats.links;
    document.getElementById("host-count").textContent = stats.hosts;

    if (errorMessage) {{
      const message = document.getElementById("message");
      message.hidden = false;
      message.innerHTML = `
        <h2>Khong ket noi duoc Ryu Controller</h2>
        <p>${{errorMessage}}</p>
        <p>Hay kiem tra Ryu da chay voi REST app chua:</p>
        <p><code>ryu-manager src/arp_monitor.py ryu.app.ofctl_rest</code></p>
      `;
    }}

    const container = document.getElementById("network");
    const data = {{
      nodes: new vis.DataSet(nodesData),
      edges: new vis.DataSet(edgesData)
    }};
    const options = {{
      autoResize: true,
      layout: {{
        improvedLayout: false
      }},
      nodes: {{
        borderWidth: 0,
        chosen: true,
        shapeProperties: {{
          useBorderWithImage: false
        }},
        shadow: {{
          enabled: true,
          color: "rgba(15, 23, 42, 0.18)",
          size: 12,
          x: 0,
          y: 5
        }}
      }},
      edges: {{
        smooth: false,
        selectionWidth: 2,
        arrows: {{
          to: {{
            enabled: false
          }}
        }}
      }},
      physics: {{
        enabled: false
      }},
      interaction: {{
        hover: true,
        tooltipDelay: 80,
        dragNodes: false,
        dragView: true,
        zoomView: true,
        navigationButtons: false,
        keyboard: true
      }}
    }};

    const network = new vis.Network(container, data, options);
    requestAnimationFrame(() => {{
      network.fit({{ animation: {{ duration: 600, easingFunction: "easeInOutQuad" }} }});
    }});
  </script>
</body>
</html>
"""


def write_html(graph_data, output_file=OUTPUT_FILE):
    output_path = Path(output_file).resolve()
    output_path.write_text(build_html(graph_data), encoding="utf-8")
    return output_path


def open_html(output_path):
    webbrowser.open(output_path.as_uri())


def main():
    graph_data = build_graph_data()
    output_path = write_html(graph_data)
    print(f"Da tao ban do topology: {output_path}")
    open_html(output_path)


if __name__ == "__main__":
    main()

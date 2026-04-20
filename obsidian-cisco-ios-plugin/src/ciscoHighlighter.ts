export interface Token {
  start: number;
  end: number;
  cssClass: string;
}

const TOP_KEYWORDS = new Set([
  "interface", "router", "bgp", "ospf", "ospfv3", "isis", "eigrp", "rip",
  "ip", "ipv6", "access-list", "crypto", "vlan", "vrf", "mpls", "aaa",
  "logging", "ntp", "snmp", "snmp-server", "telemetry", "segment-routing",
  "evpn", "l2vpn", "configure", "hostname", "no", "exit", "end", "write",
  "copy", "reload", "ping", "traceroute", "show", "debug", "do",
  "username", "enable", "disable", "service", "line", "class-map",
  "policy-map", "route-map", "spanning-tree", "tacacs", "tacacs-server",
  "radius", "radius-server", "ptp", "dhcp", "netconf", "version",
]);

const SUB_KEYWORDS = new Set([
  "description", "shutdown", "passive-interface", "bandwidth", "delay",
  "encapsulation", "switchport", "neighbor", "network", "redistribute",
  "route-target", "route-policy", "mtu", "duplex", "speed", "keepalive",
  "area", "metric", "distance", "address-family", "default-information",
  "summary-address", "timers", "authentication", "l2transport", "rewrite",
  "ingress", "egress", "tag", "push", "pop", "translate", "propagate",
  "cost", "priority", "weight", "local-preference", "community", "origin",
  "set", "match", "call", "continue", "drop", "pass", "prepend",
]);

const INTERFACE_NAMES =
  /^(GigabitEthernet|TenGigabitEthernet|HundredGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|FastEthernet|Bundle-Ether|BVI|GigE|Loopback|Tunnel|Vlan|Serial|MgmtEth|Management|Port-channel|Ethernet|ATM|Dialer|Multilink|Cellular)([\d/.:]+)/i;

const IPV4_RE = /\b(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?\b/;
const IPV6_RE = /\b([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(\/\d{1,3})?\b/;
const NUMBER_RE = /\b\d+(\.\d+)?\b/;
const WORD_RE = /[a-zA-Z0-9][-a-zA-Z0-9]*/;

export function tokenizeCiscoLine(line: string): Token[] {
  const tokens: Token[] = [];
  const trimmed = line.trimStart();

  if (trimmed === "" ) return tokens;

  // Full-line comment: starts with ! or !!
  if (trimmed.startsWith("!")) {
    tokens.push({ start: 0, end: line.length, cssClass: "chl-ios-comment" });
    return tokens;
  }

  let pos = 0;

  while (pos < line.length) {
    // Skip whitespace
    if (line[pos] === " " || line[pos] === "\t") {
      pos++;
      continue;
    }

    const slice = line.slice(pos);

    // Try interface name first (e.g. GigabitEthernet0/0/0)
    const ifaceMatch = slice.match(INTERFACE_NAMES);
    if (ifaceMatch && ifaceMatch.index === 0) {
      tokens.push({ start: pos, end: pos + ifaceMatch[0].length, cssClass: "chl-ios-type" });
      pos += ifaceMatch[0].length;
      continue;
    }

    // Try IPv6 before IPv4 (IPv6 can look like partial IPv4 matches)
    const ipv6Match = slice.match(IPV6_RE);
    if (ipv6Match && ipv6Match.index === 0) {
      tokens.push({ start: pos, end: pos + ipv6Match[0].length, cssClass: "chl-ios-number" });
      pos += ipv6Match[0].length;
      continue;
    }

    // Try IPv4
    const ipv4Match = slice.match(IPV4_RE);
    if (ipv4Match && ipv4Match.index === 0) {
      tokens.push({ start: pos, end: pos + ipv4Match[0].length, cssClass: "chl-ios-number" });
      pos += ipv4Match[0].length;
      continue;
    }

    // Try a word token (keyword, sub-keyword, permit, deny, or plain word)
    const wordMatch = slice.match(WORD_RE);
    if (wordMatch && wordMatch.index === 0) {
      const word = wordMatch[0];
      const wordEnd = pos + word.length;

      if (word === "permit") {
        tokens.push({ start: pos, end: wordEnd, cssClass: "chl-ios-permit" });
        pos = wordEnd;
        continue;
      }

      if (word === "deny") {
        tokens.push({ start: pos, end: wordEnd, cssClass: "chl-ios-deny" });
        pos = wordEnd;
        continue;
      }

      if (word === "description") {
        tokens.push({ start: pos, end: wordEnd, cssClass: "chl-ios-builtin" });
        pos = wordEnd;
        // Rest of the line is a string
        if (pos < line.length) {
          tokens.push({ start: pos, end: line.length, cssClass: "chl-ios-string" });
          pos = line.length;
        }
        continue;
      }

      if (TOP_KEYWORDS.has(word.toLowerCase())) {
        tokens.push({ start: pos, end: wordEnd, cssClass: "chl-ios-keyword" });
        pos = wordEnd;
        continue;
      }

      if (SUB_KEYWORDS.has(word.toLowerCase())) {
        tokens.push({ start: pos, end: wordEnd, cssClass: "chl-ios-builtin" });
        pos = wordEnd;
        continue;
      }

      // Plain word — no token, just advance
      pos = wordEnd;
      continue;
    }

    // Try standalone number
    const numMatch = slice.match(NUMBER_RE);
    if (numMatch && numMatch.index === 0) {
      tokens.push({ start: pos, end: pos + numMatch[0].length, cssClass: "chl-ios-number" });
      pos += numMatch[0].length;
      continue;
    }

    // Advance past any unrecognised character
    pos++;
  }

  return tokens;
}

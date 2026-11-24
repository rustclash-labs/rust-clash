import test from "node:test";
import assert from "node:assert/strict";
import {
  requiresVlessTcpTransport,
  resolveTransportOnVlessFlowChange,
  resolveVlessTransportPayload,
} from "./vlessTransport.mjs";

test("requiresVlessTcpTransport is true for REALITY or any non-empty flow", () => {
  assert.equal(requiresVlessTcpTransport(true, ""), true);
  assert.equal(requiresVlessTcpTransport(false, "xtls-rprx-vision"), true);
  assert.equal(requiresVlessTcpTransport(false, "xtls-rprx-vision-udp443"), true);
  assert.equal(requiresVlessTcpTransport(false, "  xtls-rprx-vision  "), true);
  assert.equal(requiresVlessTcpTransport(true, "xtls-rprx-vision"), true);
  assert.equal(requiresVlessTcpTransport(false, ""), false);
  assert.equal(requiresVlessTcpTransport(false, "   "), false);
  assert.equal(requiresVlessTcpTransport(false, null), false);
  assert.equal(requiresVlessTcpTransport(false, undefined), false);
});

test("resolveVlessTransportPayload resets transport to tcp/undefined when flowTrimmed is non-empty", () => {
  let wsBuilderCalled = false;
  const result = resolveVlessTransportPayload({
    vlessReality: false,
    flowTrimmed: "xtls-rprx-vision",
    buildWsTransport: () => {
      wsBuilderCalled = true;
      return {
        network: "ws",
        wsOpts: { path: "/ws", headers: { Host: "cdn.example.com" } },
      };
    },
  });

  assert.equal(wsBuilderCalled, false);
  assert.deepEqual(result, { network: "tcp", wsOpts: undefined });
});

test("resolveVlessTransportPayload resets transport to tcp/undefined when vlessReality is true", () => {
  let wsBuilderCalled = false;
  const result = resolveVlessTransportPayload({
    vlessReality: true,
    flowTrimmed: "",
    buildWsTransport: () => {
      wsBuilderCalled = true;
      return {
        network: "ws",
        wsOpts: { path: "/secret" },
      };
    },
  });

  assert.equal(wsBuilderCalled, false);
  assert.deepEqual(result, { network: "tcp", wsOpts: undefined });
});

test("resolveVlessTransportPayload preserves WebSocket network and wsOpts for standard non-REALITY VLESS", () => {
  const wsPayload = {
    network: "ws",
    wsOpts: {
      path: "/vless-ws",
      headers: { Host: "edge.example.com" },
      "max-early-data": 2048,
      "early-data-header-name": "Sec-WebSocket-Protocol",
    },
  };
  let wsBuilderCalled = false;

  const result = resolveVlessTransportPayload({
    vlessReality: false,
    flowTrimmed: "",
    buildWsTransport: () => {
      wsBuilderCalled = true;
      return wsPayload;
    },
  });

  assert.equal(wsBuilderCalled, true);
  assert.deepEqual(result, wsPayload);
});

test("resolveTransportOnVlessFlowChange resets ws to tcp when selecting flow and stays tcp when flow is cleared", () => {
  const afterSelectVision = resolveTransportOnVlessFlowChange(
    "xtls-rprx-vision",
    "ws",
  );
  assert.equal(afterSelectVision, "tcp");

  const afterSelectUdp443 = resolveTransportOnVlessFlowChange(
    "xtls-rprx-vision-udp443",
    "ws",
  );
  assert.equal(afterSelectUdp443, "tcp");

  // Once reset to tcp, clearing flow back to "" keeps transport as tcp.
  assert.equal(resolveTransportOnVlessFlowChange("", afterSelectVision), "tcp");
  // Choosing empty flow when already ws preserves ws.
  assert.equal(resolveTransportOnVlessFlowChange("", "ws"), "ws");
  assert.equal(resolveTransportOnVlessFlowChange("   ", "ws"), "ws");
});

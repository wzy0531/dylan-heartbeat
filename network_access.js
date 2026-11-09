function normalizedIp(value) {
  return String(value || "").replace(/^::ffff:/, "");
}

function isLoopbackIp(value) {
  const ip = normalizedIp(value);
  return ip === "127.0.0.1" || ip === "::1" || ip === "localhost";
}

function isPrivateIp(value) {
  const ip = normalizedIp(value);
  return isLoopbackIp(ip) || /^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)/.test(ip);
}

function decideRequestAccess({
  path,
  ip,
  isRailway,
  allowPublicApi,
  configuredKey,
  authorization,
  headerKey,
  queryKey
}) {
  const requestPath = String(path || "").split("?")[0];
  // /test-bark 只是穿过网络层，路由本身仍必须通过与管理页相同的 Basic Auth。
  if (requestPath.startsWith("/admin") || requestPath === "/healthz" || requestPath === "/test-bark") return { allow: true };

  // 批注 2026-08-10：云平台反代的 10/172/192.168 地址不代表最终访客可信；
  // 内部写接口只接受同容器 localhost，不能被公网代理转发后伪造心跳或唤醒事件。
  if (requestPath.startsWith("/internal/")) {
    return isLoopbackIp(ip) ? { allow: true } : { allow: false, status: 403, error: "Forbidden" };
  }

  // 批注 2026-11-09：/mcp 与 /timeline/* 供客户端读取唤醒记录，按与 /v1 相同的网关密钥鉴权后放行。
  const isGatewayApiPath = requestPath.startsWith("/v1/") || requestPath === "/mcp" || requestPath.startsWith("/timeline/") || requestPath.startsWith("/aru-");
  if (allowPublicApi && isGatewayApiPath) {
    if (!configuredKey) return { allow: false, status: 401, error: "公网接口已开启，但 GATEWAY_API_KEY 未配置", authRejected: true };
    const bearer = String(authorization || "").match(/^Bearer\s+(.+)$/i)?.[1]?.trim() || "";
    const alternate = String(headerKey || "").trim();
    const fromQuery = String(queryKey || "").trim();
    if (bearer === configuredKey || alternate === configuredKey || fromQuery === configuredKey) return { allow: true };
    return {
      allow: false,
      status: 401,
      error: "Gateway API Key 无效或缺失",
      authRejected: true,
      authSource: bearer ? "bearer" : alternate ? "x-api-key" : "missing"
    };
  }

  if (isLoopbackIp(ip) || (!isRailway && isPrivateIp(ip))) return { allow: true };
  return { allow: false, status: 403, error: "Forbidden" };
}

module.exports = { decideRequestAccess, isLoopbackIp, isPrivateIp };
//（注：内容由AI生成）

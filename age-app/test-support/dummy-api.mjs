// Provide only the discovery and resources the volunteer needs to see one namespace.
export function dummyAPI(method, path, namespace = "vault-test") {
  if (method === "GET" && (path === "/api/v1/pods" || /^\/api\/v1\/namespaces\/[^/]+\/pods$/.test(path))) {
    return { apiVersion: "v1", kind: "PodList", metadata: { resourceVersion: "1" }, items: [] };
  }
  switch (method + " " + path) {
  case "GET /version":
    return { major: "1", minor: "32", gitVersion: "v1.32.0" };
  case "GET /api":
    return { apiVersion: "v1", kind: "APIVersions", versions: ["v1"], serverAddressByClientCIDRs: [] };
  case "GET /apis":
    return { apiVersion: "v1", kind: "APIGroupList", groups: [] };
  case "GET /api/v1":
    return { apiVersion: "v1", kind: "APIResourceList", groupVersion: "v1",
      resources: [{ name: "namespaces", singularName: "namespace", kind: "Namespace", namespaced: false, verbs: ["get", "list"] },
        { name: "nodes", singularName: "node", kind: "Node", namespaced: false, verbs: ["get", "list"] },
        { name: "pods", singularName: "pod", kind: "Pod", namespaced: true, verbs: ["list"] }] };
  case "GET /api/v1/namespaces":
    return { apiVersion: "v1", kind: "NamespaceList", metadata: { resourceVersion: "1" },
      items: [{ apiVersion: "v1", kind: "Namespace", metadata: { name: namespace, uid: namespace, resourceVersion: "1" },
        status: { phase: "Active" } }] };
  case "GET /api/v1/nodes":
    return { apiVersion: "v1", kind: "NodeList", metadata: { resourceVersion: "1" }, items: [] };
  case "POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
    return { apiVersion: "authorization.k8s.io/v1", kind: "SelfSubjectAccessReview", status: { allowed: true } };
  case "POST /apis/authorization.k8s.io/v1/selfsubjectrulesreviews":
    return { apiVersion: "authorization.k8s.io/v1", kind: "SelfSubjectRulesReview",
      status: { resourceRules: [{ verbs: ["*"], apiGroups: ["*"], resources: ["*"] }], nonResourceRules: [], incomplete: false } };
  default:
    return undefined;
  }
}

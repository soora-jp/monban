# Kubernetes

monban runs in its own Pod. NetworkPolicy makes it the only way out for your
applications. Your CNI must enforce NetworkPolicy.

## Deploy the example

[deploy/kubernetes.yaml](../deploy/kubernetes.yaml) creates a namespace
`monban-example` containing:

- a monban Deployment and Service on port 8888
- a default-deny NetworkPolicy
- a policy that lets Pods labeled `app: application` reach only monban
- a policy that lets monban accept traffic from those Pods, and connect anywhere
  (monban's own rules filter destinations)
- a policy that lets Prometheus in namespace `monitoring` scrape port 9090

Edit `MONBAN_ALLOW` in the manifest, then apply it:

```sh
kubectl apply -f deploy/kubernetes.yaml
```

## Configure applications

Applications get no DNS access, so they cannot leak data through DNS queries.
Use the Service's ClusterIP instead of its name:

```sh
kubectl -n monban-example get service monban -o jsonpath='{.spec.clusterIP}'
```

```yaml
env:
  - name: HTTP_PROXY
    value: http://<cluster-ip>:8888
  - name: HTTPS_PROXY
    value: http://<cluster-ip>:8888
```

The client must send FQDNs to the proxy instead of resolving them itself.
Most HTTP clients do this when a proxy is set.

## Check the boundary

NetworkPolicy is not a complete boundary on its own:

- Traffic to and from the Pod's own node is often exempt.
- Behavior differs between CNIs, especially for IPv6 and host networking.
- Policies are additive. Any other policy that allows egress bypasses monban.

On your cluster, verify that application Pods cannot reach external IPs, DNS,
or node-local services directly. Also restrict who can change Pod labels and
NetworkPolicies.

## Settings in the example

| Setting | Value | Why |
|---|---|---|
| `limits.memory` | 128Mi | Fits the default limits; see [sizing](operations.md#sizing) |
| `GOMEMLIMIT` | 64MiB | Leaves room for kernel TCP queues |
| `--shutdown-delay` / `--shutdown-timeout` | 5s / 10s | Endpoint removal, then draining |
| `terminationGracePeriodSeconds` | 30 | Must exceed delay + timeout |
| Probes | `/readyz`, `/livez` on port 9090 | Do not depend on DNS or upstreams |

The example runs one replica. Restarts and rollouts briefly interrupt traffic,
so applications should retry.
